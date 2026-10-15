"""Explicit administrator/public-key inventories in the native page lifecycle.

Only configured collector authentication is used. Values returned by CI-variable
GETs are handled separately and never enter the native store or its checkpoint.
"""

from __future__ import annotations

import base64
import hashlib
import re
from urllib.parse import parse_qs, urlsplit

# Integration: moved from cremore.coverage.providers.facts, whose package import ran the adapter
# registry (every provider) and the coverage store; this module loads neither.
from cremore.coverage.facts import FactWriter, unpack_facts
from cremore.coverage.metadata_models import (
    EntityIdentity,
    EntityObservation,
    MetadataProvenance,
    OperationReport,
    in_metadata_scope,
)

from .http import CollectionError
from .model import identity as native_identity
from .model import native_id, now, stable_id
from .normalization import SOURCE_COMMIT, _permissions, _state
from .normalization import identity as normalized_identity

SOURCES = frozenset({
    "instance_pat", "instance_deploy_tokens", "instance_ssh_keys", "instance_deploy_keys",
    "enterprise_ssh_keys", "project_deploy_keys", "ci_variables",
})
ADMIN_SOURCES = frozenset(name for name in SOURCES if name.startswith("instance_"))
PUBLIC_KEY_SOURCES = frozenset({"instance_ssh_keys", "instance_deploy_keys", "enterprise_ssh_keys", "project_deploy_keys"})
PATHS = {
    "instance_pat": r"/personal_access_tokens",
    "instance_deploy_tokens": r"/deploy_tokens",
    "instance_ssh_keys": r"/users",
    "instance_deploy_keys": r"/deploy_keys",
    "user_ssh_keys": r"/users/[1-9][0-9]*/keys",
    "enterprise_ssh_keys": r"/groups/[1-9][0-9]*/manage/ssh_keys",
    "project_deploy_keys": r"/projects/[1-9][0-9]*/deploy_keys",
    "ci_variables": r"/(?:groups|projects)/[1-9][0-9]*/variables",
}
PREFIX = "gitlab.ext."
# GET /users boolean params declared `default: false` (lib/api/users.rb, :with_custom_attributes, EE
# :optional_index_params_ee); the keyset next link echoes them all (params.merge(cursor:)).
USER_DEFAULT_FILTERS = frozenset({
    "active", "humans", "external", "blocked", "without_projects", "without_project_bots",
    "admins", "exclude_active", "exclude_external", "exclude_humans", "exclude_internal",
    "with_custom_attributes", "skip_ldap", "auditors",
})


def validate_spec(spec):
    selected = set(spec.options.sources)
    if selected - SOURCES:
        raise ValueError("INVALID_GITLAB_SOURCE")
    instance = [scope for scope in spec.scopes if scope.kind == "organization"]
    if instance and (not selected & ADMIN_SOURCES or len(instance) != 1
                     or instance[0].id != spec.origin):
        raise ValueError("GITLAB_INSTANCE_SCOPE_REQUIRED")
    if selected & ADMIN_SOURCES and (
        spec.edition not in {"self_managed", "dedicated"} or not instance
    ):
        raise ValueError("GITLAB_ADMIN_INSTANCE_SCOPE_REQUIRED")
    if "enterprise_ssh_keys" in selected and (
        spec.edition != "cloud" or spec.origin != "https://gitlab.com"
        or not any(scope.kind == "group" for scope in spec.scopes)
    ):
        raise ValueError("GITLAB_MANAGED_SSH_REQUIRES_CLOUD_GROUP")
    if selected & PUBLIC_KEY_SOURCES and "public_keys" not in spec.capabilities:
        raise ValueError("GITLAB_PUBLIC_KEYS_CAPABILITY_REQUIRED")
    if "project_deploy_keys" in selected and not any(s.kind == "project" for s in spec.scopes):
        raise ValueError("GITLAB_DEPLOY_KEYS_PROJECT_REQUIRED")
    if "ci_variables" in selected and (
        "vault_metadata" not in spec.capabilities
        or not any(s.kind in {"group", "project"} for s in spec.scopes)
    ):
        raise ValueError("GITLAB_VARIABLE_SCOPE_REQUIRED")
    if spec.options.include_values and (
        "ci_variables" not in selected or "vault_value" not in spec.capabilities
    ):
        raise ValueError("GITLAB_VARIABLE_VALUE_CAPABILITY_REQUIRED")


def source_valid(spec, source):
    """A source is authorized by explicit scope, never by a submitted asset edge."""
    handler, path = source.get("handler"), source.get("path")
    if handler not in PATHS or not isinstance(path, str) or not re.fullmatch(PATHS[handler], path):
        return False
    context = source.get("context", {})
    scope = context.get("scope", {})
    approved = {(s.kind, s.id) for s in spec.scopes}
    if (scope.get("kind"), str(scope.get("id"))) not in approved:
        return False
    selection = "instance_ssh_keys" if handler == "user_ssh_keys" else handler
    if selection not in spec.options.sources:
        return False
    if selection in ADMIN_SOURCES:
        if scope != {"kind": "organization", "id": spec.origin}:
            return False
    elif path.split("/")[1:3] != [scope["kind"] + "s", str(scope["id"])]:
        return False
    expected = {"pagination": "keyset", "order_by": "id", "sort": "asc"} if handler == "instance_ssh_keys" else {}
    return source.get("params") == expected


def _scope(spec, kind, identifier):
    return next((s for s in spec.scopes if (s.kind, s.id) == (kind, str(identifier))), None)


def _common(spec, scope, operation, resource, *, purpose="issuer_inventory"):
    return {
        "scope": scope, "purpose": purpose,
        "provenance": MetadataProvenance(operation=PREFIX + operation,
                                         resource_id=resource, observed_at=now(),
                                         source_commit=SOURCE_COMMIT,
                                         contract_version="gitlab-extra-inventory-v1"),
    }


def _identity(spec, kind, identifier):
    return EntityIdentity(provider="gitlab", origin=spec.origin, tenant=spec.tenant,
                          tenant_confirmed=spec.tenant_confirmed, kind=kind, object_id=identifier)


def _public_fingerprint(value):
    # SSH comments may contain private text. Keep only a fingerprint of the
    # decoded public blob, with its algorithm validated against the wire data.
    if not isinstance(value, str) or len(value) > 32768:
        return None
    fields = value.split()
    if len(fields) < 2 or not re.fullmatch(r"(?:ssh-|ecdsa-|sk-)[A-Za-z0-9@._+-]{1,100}", fields[0]):
        return None
    try:
        blob = base64.b64decode(fields[1], validate=True)
        length = int.from_bytes(blob[:4], "big")
        if length < 1 or blob[4:4 + length] != fields[0].encode() or len(blob) <= 4 + length:
            return None
    except (ValueError, UnicodeError):
        return None
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def observation(spec, scope, source, item):
    identifier = native_id(item.get("id"))
    writer = FactWriter()
    metadata = {key: item[key] for key in (
        "id", "name", "title", "user_id", "created_at", "expires_at", "last_used_at",
        "active", "revoked", "expired", "username", "scopes", "granular_scopes",
        "usage_type", "can_push",
    ) if key in item}
    # title is deliberately projected under the shared display name field.
    if "title" in metadata:
        metadata["display_name"] = metadata.pop("title")
    public = source in {"user_ssh_keys", "enterprise_ssh_keys", "project_deploy_keys", "instance_deploy_keys"}
    if public:
        fingerprint = _public_fingerprint(item.get("key"))
        reported = item.get("fingerprint_sha256")
        if not fingerprint and isinstance(reported, str) and re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", reported):
            fingerprint = reported
        if fingerprint:
            metadata["sha256_fingerprint"] = fingerprint
        projects = []
        for field, access in (("projects_with_readonly_access", "read"), ("projects_with_write_access", "write")):
            for project in item.get(field, []) if isinstance(item.get(field), list) else []:
                if isinstance(project, dict) and type(project.get("id")) is int and project["id"] > 0:
                    projects.append({"id": project["id"], "access": access})
        if projects:
            metadata["projects"] = projects[:250]
            if len(projects) > 250:
                writer.omit("projects", "METADATA_FACT_LIMIT")
        kind, family = "public_key", "deploy_key" if "deploy" in source else "ssh_key"
    else:
        kind = "credential"
        family = "personal_access_token" if source == "instance_pat" else "deploy_token"
    if source == "user_ssh_keys":
        metadata["user_id"] = int(item["user_id"])
    resource = f"{family}:{identifier}"
    native = native_identity(spec.origin, family, identifier, {})
    if source == "instance_pat":
        # Same documented PAT ID space as the native self/group/service-account
        # adapters, with no inference from a secret token's prefix or suffix.
        entity = normalized_identity(spec, native)
    else:
        entity = _identity(spec, kind, resource)
    state = _state(metadata)
    permissions = _permissions(metadata, writer)
    return EntityObservation(
        **_common(spec, scope, source, resource), identity=entity,
        facts=writer.facts({"family": family, "identity": native, "metadata": metadata}), omissions=writer.omissions,
        provider_state=state[0], normalized_state=state[1], state_basis=state[2],
        permissions=permissions,
    )


def validate_record(spec, item, *, machine=False):
    if not in_metadata_scope(spec, item) or item.provenance.source_commit != SOURCE_COMMIT:
        return False
    operation = item.provenance.operation.removeprefix(PREFIX)
    if operation in {"ci_variables", "ci_variable_values"}:
        from .variables import validate_record as validate_variable
        return validate_variable(spec, item)
    if operation not in SOURCES | {"user_ssh_keys"}:
        return False
    source = "instance_ssh_keys" if operation == "user_ssh_keys" else operation
    if source not in spec.options.sources or item.purpose != "issuer_inventory":
        return False
    if source in ADMIN_SOURCES and (item.scope.kind, item.scope.id) != ("organization", spec.origin):
        return False
    if operation == "enterprise_ssh_keys" and item.scope.kind != "group":
        return False
    if operation == "project_deploy_keys" and item.scope.kind != "project":
        return False
    if item.record_type == "operation_report":
        return item.value_contract is None and item.value_access == "NOT_REQUESTED"
    if item.record_type != "entity_observation" or item.value_match is not None:
        return False
    resource = item.provenance.resource_id
    family = "personal_access_token" if operation == "instance_pat" else (
        "deploy_token" if operation == "instance_deploy_tokens" else
        "deploy_key" if "deploy" in operation else "ssh_key")
    if not re.fullmatch(re.escape(family) + r":[1-9][0-9]*", resource):
        return False
    values = unpack_facts([fact.model_dump() for fact in item.facts])
    metadata = values.get("metadata")
    if not isinstance(metadata, dict) or values.get("family") != family:
        return False
    if values.get("identity") != native_identity(spec.origin, family, int(resource.split(":")[1]), {}):
        return False
    if str(metadata.get("id")) != resource.split(":")[1]:
        return False
    expected = observation(spec, item.scope, operation, {**metadata, "id": int(metadata["id"])})
    return (item.identity, item.provider_state, item.normalized_state, item.state_basis, item.permissions) == (
        expected.identity, expected.provider_state, expected.normalized_state, expected.state_basis, expected.permissions)


class Extensions:
    """Add bounded tasks to the existing native queue; no second scheduler."""

    def __init__(self, spec, value_context=None):
        self.spec, self.value_context = spec, value_context
        if spec.options.include_values:
            from .variables import validate_context
            validate_context(value_context)

    def verify_principal(self, user):
        if set(self.spec.options.sources) & ADMIN_SOURCES and user.get("is_admin") is not True:
            raise CollectionError("GITLAB_ADMIN_REQUIRED", "인스턴스 목록에는 관리자 인증이 필요합니다.")

    def initialize(self, collector):
        spec = self.spec
        instance = _scope(spec, "organization", spec.origin)
        for source in sorted(set(spec.options.sources) & ADMIN_SOURCES):
            params = {"pagination": "keyset", "order_by": "id", "sort": "asc"} if source == "instance_ssh_keys" else {}
            path = {"instance_pat": "/personal_access_tokens", "instance_deploy_tokens": "/deploy_tokens",
                    "instance_ssh_keys": "/users", "instance_deploy_keys": "/deploy_keys"}[source]
            collector.store.add_task(source, path, {"scope": instance.model_dump()}, params)
        # Explicit group/project scopes only. A newly discovered descendant
        # does not independently authorize reading its CI-variable values.
        for scope in spec.scopes:
            if "ci_variables" in spec.options.sources and scope.kind in {"group", "project"}:
                collector.store.add_task("ci_variables", f"/{scope.kind}s/{scope.id}/variables",
                                         {"scope": scope.model_dump()})
            if "project_deploy_keys" in spec.options.sources and scope.kind == "project":
                collector.store.add_task("project_deploy_keys", f"/projects/{scope.id}/deploy_keys",
                                         {"scope": scope.model_dump()})

    def group(self, collector, identifier, metadata):
        scope = _scope(self.spec, "group", identifier)
        if not scope or "enterprise_ssh_keys" not in self.spec.options.sources:
            return
        if "parent_id" in metadata and metadata["parent_id"] is None:
            collector.store.add_task("enterprise_ssh_keys", f"/groups/{identifier}/manage/ssh_keys",
                                     {"scope": scope.model_dump()})
        else:
            report = OperationReport(**_common(self.spec, scope, "enterprise_ssh_keys", str(identifier)),
                                     status="UNSUPPORTED", reasons=["GITLAB_TOP_LEVEL_GROUP_REQUIRED"])
            collector.store.pending.append(("extension", report.model_dump()))
            collector.store.note("GITLAB_TOP_LEVEL_GROUP_REQUIRED", scope.model_dump())

    def check_task(self, task):
        source = task["spec"]
        if not source_valid(self.spec, source):
            raise CollectionError("GITLAB_EXTENSION_SCOPE_MISMATCH", "승인 범위와 수집 경로가 다릅니다.")
        if task.get("next_url"):
            parsed = urlsplit(task["next_url"])
            if (parsed.scheme + "://" + parsed.netloc != self.spec.origin
                    or parsed.path != "/api/v4" + source["path"] or parsed.fragment
                    or parsed.username or parsed.password):
                raise CollectionError("PAGINATION_SCOPE_CHANGED", "다음 페이지가 승인 범위를 벗어났습니다.")
            query = parse_qs(parsed.query, keep_blank_values=True)
            allowed = {"page", "per_page", "pagination", "order_by", "sort", "id_after"}
            defaults = USER_DEFAULT_FILTERS if source["handler"] == "instance_ssh_keys" else frozenset()
            if defaults:
                allowed |= {"cursor"} | defaults
            if (set(query) - allowed or any(len(values) != 1 or not values[0] for values in query.values())
                    or any(query.get(key) != [value] for key, value in source["params"].items())
                    or any(query[key] != ["false"] for key in defaults & query.keys())):
                raise CollectionError("PAGINATION_SCOPE_CHANGED", "다음 페이지가 조회 범위를 변경했습니다.")

    def handle(self, collector, task, body):
        source = task["spec"]["handler"]
        if not isinstance(body, list) or any(not isinstance(row, dict) for row in body):
            raise CollectionError("INVALID_RESPONSE_SHAPE", "목록은 객체 배열이어야 합니다.")
        requested = task["spec"]["context"]["scope"]
        scope = _scope(self.spec, requested["kind"], requested["id"])
        if source == "ci_variables":
            from .variables import collect
            return collect(self.spec, scope, collector.store, task, body, self.value_context)
        seen = set()
        known_users = sum(t["spec"]["handler"] == "user_ssh_keys" for t in collector.store.state["tasks"].values())
        for row in body:
            identifier = native_id(row.get("id"))
            if identifier in seen:
                raise CollectionError("DUPLICATE_PROVIDER_ID", "한 페이지에서 식별자가 중복되었습니다.")
            seen.add(identifier)
            if source == "instance_ssh_keys":
                if known_users >= self.spec.max_records:
                    raise CollectionError("GITLAB_TARGET_LIMIT", "사용자 조회 한도에 도달했습니다.")
                collector.store.add_task("user_ssh_keys", f"/users/{identifier}/keys",
                                         {"scope": scope.model_dump()})
                known_users += 1
                continue
            if source == "user_ssh_keys":
                owner = int(task["spec"]["path"].split("/")[2])
                if row.get("user_id", owner) != owner:
                    raise CollectionError("RESPONSE_ID_MISMATCH", "SSH 키 소유자가 요청과 다릅니다.")
                row = {**row, "user_id": owner}
            if source == "instance_pat":
                native_id(row.get("user_id"))
            result = observation(self.spec, scope, source, row)
            collector.store.pending.append(("extension", result.model_dump()))
        return len(body)

    def final_reports(self, store):
        if "ci_variables" in self.spec.options.sources:
            from .variables import reports
            yield from reports(self.spec, store, self.value_context)


def compare_metadata(before, after, *, scope_id=None):
    """Compare stored metadata only; absent values do not prove revocation."""
    def index(rows):
        found = {}
        for row in rows:
            operation = row.get("provenance", {}).get("operation", "")
            if (row.get("record_type") != "entity_observation" or not operation.startswith(PREFIX)
                    or row.get("value_match") or scope_id and row.get("scope", {}).get("id") != scope_id):
                continue
            key = stable_id([row["identity"], row["scope"], operation])
            found[key] = row
        return found

    complete = set()
    for row in after:
        if row.get("provenance", {}).get("operation") != "gitlab.native.source":
            continue
        payload = unpack_facts(row.get("facts", []))
        source = payload.get("spec", {})
        if payload.get("status") == "complete" and source.get("handler") in PATHS:
            complete.add((source["handler"], source["path"]))

    old, new = index(before), index(after)
    changes = []
    for key in sorted(old.keys() | new.keys()):
        if key not in old:
            changes.append({"inventory_id": key, "object_id": new[key]["identity"]["object_id"],
                            "change": "newly_observed", "not_necessarily_newly_issued": True})
            continue
        prior = old[key]
        if key in new:
            previous, current = unpack_facts(prior.get("facts", [])), unpack_facts(new[key].get("facts", []))
            previous, current = previous.get("metadata", previous), current.get("metadata", current)
            fields = sorted(name for name in previous.keys() | current.keys()
                            if (name in previous, previous.get(name)) != (name in current, current.get(name)))
            if fields:
                changes.append({"inventory_id": key, "object_id": prior["identity"]["object_id"],
                                "change": "metadata_changed", "fields": fields})
            continue
        operation = prior["provenance"]["operation"].removeprefix(PREFIX)
        scope = prior["scope"]
        base = f"/{scope['kind']}s/{scope['id']}"
        if operation == "user_ssh_keys":
            values = unpack_facts(prior.get("facts", []))
            owner = values.get("metadata", values).get("user_id")
            path = f"/users/{owner}/keys"
        else:
            path = {"instance_pat": "/personal_access_tokens", "instance_deploy_tokens": "/deploy_tokens",
                    "instance_deploy_keys": "/deploy_keys", "enterprise_ssh_keys": base + "/manage/ssh_keys",
                    "project_deploy_keys": base + "/deploy_keys", "ci_variables": base + "/variables"}.get(operation)
        changes.append({"inventory_id": key, "object_id": prior["identity"]["object_id"],
                        "change": "not_observed" if (operation, path) in complete else "observation_unknown",
                        "revocation_inferred": False})
    return changes
