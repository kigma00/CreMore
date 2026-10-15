"""GitLab native collection in the shared lease, batch and checkpoint lifecycle."""

from __future__ import annotations

import math
import re
import time
from copy import deepcopy
from dataclasses import asdict, fields
from urllib.parse import parse_qs, urlsplit

from cremore.coverage.metadata_models import (
    RECORD_ADAPTER,
    MetadataConnectionSpec,
    MetadataPage,
    MetadataProvenance,
    OperationReport,
    checkpoint_json,
    in_metadata_scope,
)

from . import UPGRADE_SOURCE_COMMIT
from .audit import TokenAuditIndex, audit_reference
from .collector import Collector
from .config import Config
from .extensions import PATHS as EXTRA_PATHS
from .extensions import PREFIX as EXTRA_PREFIX
from .extensions import Extensions, source_valid
from .extensions import validate_record as validate_extra_record
from .extensions import validate_spec as validate_extra_spec
from .handlers import task_scheduling_policy
from .http import Client, CollectionError
from .model import identity as native_identity
from .model import native_id, now, secret_field, stable_id
from .normalization import (
    NATIVE_PREFIX,
    SOURCE_COMMIT,
    identity,
    record,
    relation_payloads,
    replay,
    unpack_facts,
)
from .provenance import code_provenance
from .storage import Store, read_previous_inventory

_SOURCE_PATHS = {
    "group": r"/groups/[1-9][0-9]*",
    "project": r"/projects/[1-9][0-9]*",
    "user": r"/users/[1-9][0-9]*",
    "agent_detail": r"/projects/[1-9][0-9]*/cluster_agents/[1-9][0-9]*",
    "subgroups": r"/groups/[1-9][0-9]*/subgroups",
    "projects": r"/groups/[1-9][0-9]*/projects",
    "service_accounts": r"/(?:groups|projects)/[1-9][0-9]*/service_accounts",
    "agents": r"/projects/[1-9][0-9]*/cluster_agents",
    "resource_list": r"/groups/[1-9][0-9]*/manage/resource_access_tokens",
    "graphql_triggers": r"/api/graphql",
    "audit_plan": r"/(?:groups|projects)/[1-9][0-9]*/audit_events",
    "audit_events": r"/(?:groups|projects)/[1-9][0-9]*/audit_events",
    "token_list": r"(?:/personal_access_tokens|/groups/[1-9][0-9]*/manage/personal_access_tokens|/(?:groups|projects)/[1-9][0-9]*/(?:access_tokens|deploy_tokens|service_accounts/[1-9][0-9]*/personal_access_tokens)|/projects/[1-9][0-9]*/(?:triggers|error_tracking/client_keys|cluster_agents/[1-9][0-9]*/tokens))",
    "token_detail": r"(?:/personal_access_tokens/[1-9][0-9]*|/(?:groups|projects)/[1-9][0-9]*/(?:access_tokens|deploy_tokens)/[1-9][0-9]*|/projects/[1-9][0-9]*/(?:triggers/[1-9][0-9]*|cluster_agents/[1-9][0-9]*/tokens/[1-9][0-9]*))",
}
_FAMILIES = {
    "personal_access_token",
    "group_service_account_pat",
    "project_service_account_pat",
    "group_access_token",
    "project_access_token",
    "group_deploy_token",
    "project_deploy_token",
    "pipeline_trigger_token",
    "error_tracking_client_key",
    "kubernetes_agent_token",
}
_GLOBAL_STOPS = {
    "AUTHENTICATION_FAILED",
    "REQUEST_BUDGET_EXCEEDED",
    "RATE_LIMIT_CIRCUIT_OPEN",
    "RETRY_LATER",
}
_DEFERRED = {"RATE_LIMIT_CIRCUIT_OPEN", "RETRY_LATER", "RATE_LIMITED"}
_EXPECTED_FAILURES = (CollectionError, ValueError, KeyError, TypeError)


def validate_spec(spec, *, collecting=True):
    if spec.provider != "gitlab" or spec.edition not in {"cloud", "self_managed", "dedicated"}:
        raise ValueError("INVALID_GITLAB_EDITION")
    if spec.auth_type not in {"bearer", "token"} or "inventory" not in spec.capabilities:
        raise ValueError("GITLAB_INVENTORY_AUTH_REQUIRED")
    if collecting and set(spec.secret_refs) != {"token"}:
        raise ValueError("GITLAB_TOKEN_REFERENCE_REQUIRED")
    if not collecting and set(spec.secret_refs) - {"token"}:
        raise ValueError("GITLAB_TOKEN_REFERENCE_REQUIRED")
    if set(spec.capabilities) - {"inventory", "audit", "relations", "public_keys", "vault_metadata", "vault_value"}:
        raise ValueError("GITLAB_CAPABILITY_NOT_SUPPORTED")
    validate_extra_spec(spec)
    for scope in spec.scopes:
        if scope.kind not in {"group", "project", "user", "organization"}:
            raise ValueError("GITLAB_EXPLICIT_SCOPE_REQUIRED")
        if scope.kind == "user":
            if scope.id != "self" and scope.id != spec.principal_pin:
                raise ValueError("GITLAB_SELF_SCOPE_REQUIRED")
        elif scope.kind != "organization":
            native_id(scope.id)
    if spec.options.page_size > 100:
        raise ValueError("INVALID_GITLAB_COLLECTION_OPTION")
    if spec.options.include_enterprise_pat and (
        spec.origin != "https://gitlab.com" or spec.edition != "cloud"
    ):
        raise ValueError("GITLAB_MANAGED_PAT_REQUIRES_CLOUD")
    if spec.principal_pin is not None:
        native_id(spec.principal_pin)
    if sum(scope.kind in {"group", "project"} for scope in spec.scopes) > spec.options.max_targets:
        raise ValueError("GITLAB_TARGET_LIMIT")


def _config(spec, *, collecting=True):
    """``collecting`` is false for an export or comparison, which reads records.

    A stored contract snapshot deliberately carries no secret reference, so the
    authentication half of the contract cannot be re-checked there -- and does
    not need to be: nothing is requested from the provider.
    """
    validate_spec(spec, collecting=collecting)
    options = spec.options.model_dump()
    names = {field.name for field in fields(Config)}
    settings = {key: value for key, value in options.items() if key in names}
    if spec.origin != "https://gitlab.com" or spec.edition != "cloud":
        settings["include_resource_access_tokens"] = False
    settings.update(
        base_url=spec.origin,
        group_ids=[native_id(scope.id) for scope in spec.scopes if scope.kind == "group"],
        project_ids=[native_id(scope.id) for scope in spec.scopes if scope.kind == "project"],
        max_pages_per_task=spec.max_pages,
        max_requests_per_run=spec.max_requests,
    )
    return Config.from_dict(settings)


def _source_valid(value, connection=None):
    spec = value.get("spec", {})
    handler = spec.get("handler")
    if handler in EXTRA_PATHS:
        return connection is not None and value.get("id") == stable_id(spec) and source_valid(connection, spec)
    path = spec.get("path")
    valid = (
        handler in _SOURCE_PATHS
        and isinstance(path, str)
        and re.fullmatch(_SOURCE_PATHS[handler], path) is not None
        and value.get("id") == stable_id(spec)
        and isinstance(spec.get("context"), dict)
        and isinstance(spec.get("params"), dict)
    )
    if not valid:
        return False
    scope = spec["context"].get("scope")
    endpoint_scope = _path_scope(path)
    if (
        scope
        and endpoint_scope
        and (scope.get("kind"), native_id(scope.get("id")))
        != (endpoint_scope["kind"], endpoint_scope["id"])
    ):
        return False
    if path == "/personal_access_tokens":
        return bool(
            scope
            and scope.get("kind") == "user"
            and native_id(spec["params"].get("user_id")) == native_id(scope["id"])
        )
    if handler == "projects":
        return spec["params"] == {"with_shared": "false", "include_subgroups": "false"}
    return True


def _path_scope(path):
    match = re.match(r"/(groups|projects|users)/([1-9][0-9]*)(?:/|$)", path)
    return {"kind": match[1][:-1], "id": int(match[2])} if match else None


def _token_observation_valid(origin, native, observation):
    handler, endpoint = observation["handler"], observation["endpoint"]
    if handler not in {"token_list", "token_detail", "resource_list", "graphql_triggers"}:
        return False
    context, metadata = observation["context"], observation["metadata"]
    family, scope = context["family"], context["scope"]
    if family not in _FAMILIES or scope["kind"] not in {"user", "group", "project"}:
        return False
    identifier = native_id(scope["id"])
    if native_identity(origin, family, native["native_id"], scope) != native:
        return False
    request = observation["request_url"]
    if handler == "graphql_triggers":
        if request != "/api/graphql":
            return False
    else:
        parsed, expected_origin = urlsplit(request), urlsplit(origin)
        if (
            (parsed.scheme, parsed.netloc) != (expected_origin.scheme, expected_origin.netloc)
            or parsed.path != "/api/v4" + endpoint
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            return False
        query = parse_qs(parsed.query, keep_blank_values=True)
        if any(secret_field(key, value) for key, values in query.items() for value in values):
            return False
        if endpoint == "/personal_access_tokens" and query.get("user_id") != [str(identifier)]:
            return False
    if (
        native_id(metadata["id"], "Ci::Trigger" if handler == "graphql_triggers" else None)
        != native["native_id"]
    ):
        return False
    if handler == "resource_list":
        return (
            re.fullmatch(_SOURCE_PATHS[handler], endpoint) is not None
            and family == scope["kind"] + "_access_token"
            and metadata.get("resource_type") == scope["kind"]
            and native_id(metadata["resource_id"]) == identifier
        )
    if handler == "graphql_triggers":
        return (
            endpoint == "/api/graphql"
            and family == "pipeline_trigger_token"
            and scope["kind"] == "project"
        )
    base = f"/{scope['kind']}s/{identifier}"
    if family == "personal_access_token":
        expected = (
            "/personal_access_tokens"
            if scope["kind"] == "user" or handler == "token_detail"
            else base + "/manage/personal_access_tokens"
        )
        if scope["kind"] not in {"user", "group"}:
            return False
    elif family in {"group_service_account_pat", "project_service_account_pat"}:
        expected = (
            base
            + f"/service_accounts/{native_id(scope['service_account_id'])}/personal_access_tokens"
        )
        if family != scope["kind"] + "_service_account_pat":
            return False
    elif family in {
        "group_access_token",
        "project_access_token",
        "group_deploy_token",
        "project_deploy_token",
    }:
        suffix = "access_tokens" if family.endswith("_access_token") else "deploy_tokens"
        expected = base + "/" + suffix
        if not family.startswith(scope["kind"] + "_"):
            return False
    else:
        if scope["kind"] != "project":
            return False
        expected = (
            base
            + {
                "pipeline_trigger_token": "/triggers",
                "error_tracking_client_key": "/error_tracking/client_keys",
                "kubernetes_agent_token": f"/cluster_agents/{native_id(scope['agent_id'])}/tokens"
                if "agent_id" in scope
                else "",
            }[family]
        )
    if handler == "token_detail":
        expected += "/" + str(native["native_id"])
    return endpoint == expected


def _asset_valid(payload):
    kind, identifier, source = payload["kind"], native_id(payload["id"]), payload["source"]
    if native_id(payload["metadata"]["id"]) != identifier:
        return False
    if kind == "user":
        return (
            source in {"/user", f"/users/{identifier}"}
            or re.fullmatch(_SOURCE_PATHS["service_accounts"], source) is not None
        )
    if kind in {"group", "project"}:
        listing = "subgroups" if kind == "group" else "projects"
        return (
            source == f"/{kind}s/{identifier}"
            or re.fullmatch(_SOURCE_PATHS[listing], source) is not None
        )
    if kind == "agent":
        return (
            re.fullmatch(_SOURCE_PATHS["agents"], source) is not None
            or re.fullmatch(r"/projects/[1-9][0-9]*/cluster_agents/" + str(identifier), source)
            is not None
        )
    return False


def validate_record(spec, item):
    """Reject other origins, arbitrary operations and inconsistent native IDs."""
    if item.provenance.operation.startswith(EXTRA_PREFIX):
        try:
            return validate_extra_record(spec, item)
        except (ValueError, KeyError, TypeError):
            return False
    if (
        not in_metadata_scope(spec, item)
        or item.provenance.source_commit != SOURCE_COMMIT
        or item.purpose != "issuer_inventory"
        or getattr(item, "value_match", None) is not None
    ):
        return False
    operation = item.provenance.operation
    if operation in {"gitlab.run", "gitlab.bootstrap"}:
        return item.record_type == "operation_report"
    if not operation.startswith(NATIVE_PREFIX):
        return False
    kind = operation[len(NATIVE_PREFIX) :]
    try:
        payload = unpack_facts([fact.model_dump() for fact in item.facts])
        if kind == "capability":
            return (
                item.record_type == "operation_report"
                and item.status == "UNSUPPORTED"
                and item.reasons == ["GITLAB_CLOUD_MANAGED_API_ONLY"]
                and payload == {"name": "include_resource_access_tokens", "status": "UNSUPPORTED"}
                and (spec.origin != "https://gitlab.com" or spec.edition != "cloud")
            )
        if kind == "source":
            return item.record_type == "operation_report" and _source_valid(payload, spec)
        if kind == "asset":
            return (
                item.record_type == "entity_observation"
                and _asset_valid(payload)
                and item.identity == identity(spec, payload, asset=True)
            )
        if kind in {"observation", "inventory"}:
            native = payload["identity"]
            native_id(native["native_id"])
            if native["instance"] != spec.origin or item.record_type != "entity_observation":
                return False
            if payload["inventory_id"] != stable_id(native) or item.identity != identity(
                spec, native
            ):
                return False
            families = [payload["family"]] if kind == "observation" else payload["credential_types"]
            if not families or set(families) - _FAMILIES:
                return False
            observations = (
                [payload["observation"]] if kind == "observation" else payload["observations"]
            )
            if not observations:
                return False
            for observation in observations:
                if not _token_observation_valid(spec.origin, native, observation):
                    return False
            expected = record(spec, item.scope, kind, payload)
            return (
                item.provider_state,
                item.normalized_state,
                item.state_basis,
                item.permissions,
            ) == (
                expected.provider_state,
                expected.normalized_state,
                expected.state_basis,
                expected.permissions,
            )
        if kind == "relation":
            native = payload["identity"]
            native_id(payload["user_id"])
            if (
                item.record_type != "relation"
                or native["instance"] != spec.origin
                or payload["inventory_id"] != stable_id(native)
                or payload["state"] not in {"observed", "observed_in_audit"}
                or payload["relationship"] not in {"owns", "created_by"}
                or not payload["observed_scopes"]
            ):
                return False
            expected = record(spec, item.scope, kind, payload)
            return (
                item.subject,
                item.target,
                item.relation,
                item.match_basis,
                item.confidence,
            ) == (
                expected.subject,
                expected.target,
                expected.relation,
                expected.match_basis,
                expected.confidence,
            )
        if kind in {"audit", "filtered_audit"}:
            if "audit" not in spec.capabilities:
                return False
            scope = payload["scope"]
            native_id(scope["id"])
            native_id(payload["event_id"])
            if scope["kind"] not in {"group", "project"}:
                return False
            if kind == "audit":
                if (
                    item.record_type not in {"provider_event", "operation_report"}
                    or payload["audit_event_id"]
                    != stable_id({"scope": scope, "event_id": payload["event_id"]})
                    or native_id(payload["metadata"]["id"]) != native_id(payload["event_id"])
                    or payload["interpretation"] != audit_reference(payload["metadata"], scope)
                ):
                    return False
                if payload.get("identity"):
                    native = payload["identity"]
                    candidate = stable_id(native)
                    index = TokenAuditIndex(
                        [
                            {
                                "inventory_id": candidate,
                                "identity": native,
                                "audit_scopes": {
                                    (value["kind"], native_id(value["id"]))
                                    for value in payload["observed_scopes"]
                                },
                            }
                        ]
                    )
                    if (
                        payload.get("inventory_id") != candidate
                        or payload.get("candidate_inventory_ids") != [candidate]
                        or index.match(payload["interpretation"], scope)[0] != [candidate]
                    ):
                        return False
                expected = record(spec, item.scope, kind, payload)
                return item.record_type == "operation_report" or (
                    item.subject,
                    item.target,
                    item.event_id,
                    item.event_type,
                    item.occurred_at,
                    item.match_basis,
                    item.confidence,
                ) == (
                    expected.subject,
                    expected.target,
                    expected.event_id,
                    expected.event_type,
                    expected.occurred_at,
                    expected.match_basis,
                    expected.confidence,
                )
            return (
                item.record_type == "operation_report"
                and payload.get("reason") == "not_token_related"
            )
    except (KeyError, TypeError, ValueError):
        return False
    return False


def validate_machine_record(spec, item):
    """External batches cannot authorize descendants by inventing a discovery edge."""
    if not validate_record(spec, item):
        return False
    operation = item.provenance.operation
    if operation.startswith(EXTRA_PREFIX):
        return validate_extra_record(spec, item, machine=True)
    if operation in {"gitlab.run", "gitlab.bootstrap"}:
        return True
    kind = operation[len(NATIVE_PREFIX) :]
    payload = unpack_facts([fact.model_dump() for fact in item.facts])
    approved = {
        (scope.kind, spec.principal_pin if scope.id == "self" else scope.id)
        for scope in spec.scopes
    }

    def allows(scope):
        return bool(scope) and (scope.get("kind"), str(scope.get("id"))) in approved

    try:
        if kind == "capability":
            return True
        if kind in {"audit", "filtered_audit"}:
            return allows(payload["scope"]) and all(
                allows(scope) for scope in payload.get("observed_scopes", [])
            )
        if kind in {"observation", "inventory"}:
            observations = (
                [payload["observation"]] if kind == "observation" else payload["observations"]
            )
            for row in observations:
                if not allows(row["context"]["scope"]):
                    return False
                if row["endpoint"].startswith("/personal_access_tokens"):
                    if not allows({"kind": "user", "id": row["metadata"].get("user_id")}):
                        return False
                elif row["endpoint"] != "/api/graphql" and not allows(_path_scope(row["endpoint"])):
                    return False
            return True
        if kind == "relation":
            native = payload["identity"]
            # PAT IDs share an instance-wide namespace. Other token IDs carry
            # their own resource scope, independent of the reported sightings.
            native_allowed = (native.get("namespace") == "personal_access_token"
                              and native.get("scope") == {}) or allows(native.get("scope"))
            return native_allowed and all(allows(scope) for scope in payload["observed_scopes"])
        if kind == "source":
            source = payload["spec"]
            if source["handler"] in EXTRA_PATHS:
                return source_valid(spec, source)
            scope = _path_scope(source["path"]) or source["context"].get("scope")
            return allows(scope) and (
                not source["context"].get("scope") or allows(source["context"]["scope"])
            )
        if kind == "asset":
            source = payload["source"]
            if payload["kind"] in {"group", "project"}:
                return allows(payload) and allows(_path_scope(source))
            if source == "/user":
                return allows({"kind": "user", "id": payload["id"]})
            return allows(_path_scope(source))
    except (KeyError, TypeError, ValueError):
        return False
    return False


def _root_for(spec, roots, kind, value):
    if kind == "source":
        context = value["spec"]["context"]
        path = value["spec"]["path"]
    elif kind == "observation":
        context = value["observation"]["context"]
        path = value["observation"]["endpoint"]
    elif kind in {"audit", "filtered_audit"}:
        context = {"scope": value["scope"]}
        path = ""
    elif kind == "asset":
        context = {"scope": {"kind": value["kind"], "id": value["id"]}}
        path = value["source"]
    else:
        contexts = value.get("observed_scopes", [])
        context = {"scope": contexts[0]} if contexts else {}
        path = ""
    source_scope = context.get("scope", {})
    key = f"{source_scope.get('kind')}:{source_scope.get('id')}"
    match = re.match(r"/(groups|projects)/([1-9][0-9]*)", path)
    parent = f"{'group' if match[1] == 'groups' else 'project'}:{match[2]}" if match else ""
    root_index = roots.get(key, roots.get(parent, 0))
    if kind == "asset" and value["kind"] in {"group", "project"}:
        # Descendants inherit only the root used to discover their actual source page.
        roots.setdefault(f"{value['kind']}:{value['id']}", root_index)
    if kind == "observation" and value["observation"]["handler"] == "resource_list":
        roots.setdefault(key, root_index)
    return spec.scopes[root_index]


class _BoundedCollector(Collector):
    """Apply the shared target budget before native discovery schedules descendants."""

    def handle(self, task, body, url):
        handler = task["spec"]["handler"]
        if handler not in {"subgroups", "projects", "resource_list"}:
            return super().handle(task, body, url)
        if not isinstance(body, list) or any(not isinstance(item, dict) for item in body):
            return super().handle(task, body, url)
        targets = {key for key in self.roots if key.startswith(("group:", "project:"))}
        selected = []
        for item in body:
            native_id(item.get("id"))
            kind = item.get("resource_type") if handler == "resource_list" else (
                "group" if handler == "subgroups" else "project")
            if kind not in {"group", "project"}:
                raise CollectionError("UNKNOWN_RESOURCE_TYPE", "통합 Token 응답에 알려지지 않은 resource_type이 있습니다.")
            identifier = native_id(item.get("resource_id") if handler == "resource_list" else item["id"])
            key = f"{kind}:{identifier}"
            if key not in targets and len(targets) >= self.max_targets:
                self.truncated = True
                continue
            targets.add(key)
            selected.append(item)
        return super().handle(task, selected, url)


def _prepare(spec, store, roots, *, phase, emitted, cursor=None):
    updated = dict(roots)
    records = []
    size = 0
    if emitted + len(store.pending) > spec.max_records:
        raise CollectionError("RECORD_LIMIT", "수집 레코드 한도에 도달했습니다.")
    for kind, payload in store.pending:
        if kind == "extension":
            item = RECORD_ADAPTER.validate_python(payload)
        else:
            scope = _root_for(spec, updated, kind, payload)
            item = record(spec, scope, kind, payload)
        if not validate_record(spec, item):
            raise CollectionError(
                "GITLAB_NORMALIZATION_FAILED", "정규화된 레코드가 공급자 계약을 만족하지 않습니다."
            )
        length = len(item.model_dump_json().encode())
        if length > 500000:
            raise CollectionError(
                "METADATA_RECORD_LIMIT", "정규화 레코드 크기 한도에 도달했습니다."
            )
        records.append(item)
        size += length
        if kind == "inventory" and "relations" in spec.capabilities:
            for relation in relation_payloads(payload):
                item = record(spec, scope, "relation", relation)
                if not validate_record(spec, item):
                    raise CollectionError(
                        "GITLAB_NORMALIZATION_FAILED",
                        "관계 레코드가 공급자 계약을 만족하지 않습니다.",
                    )
                records.append(item)
                size += len(item.model_dump_json().encode())
        if size > 1900000 or len(records) > 5000:
            raise CollectionError("METADATA_PAGE_LIMIT", "정규화 페이지 크기 한도에 도달했습니다.")
    if sum(key.startswith(("group:", "project:")) for key in updated) > spec.options.max_targets:
        raise CollectionError("GITLAB_TARGET_LIMIT", "승인된 자산 발견 한도에 도달했습니다.")
    if emitted + len(records) > spec.max_records:
        raise CollectionError("RECORD_LIMIT", "수집 레코드 한도에 도달했습니다.")
    result = {
        **store.checkpoint(),
        "roots": updated,
        "phase": phase,
        "emitted": emitted + len(records),
        "final_cursor": cursor,
        "principal_verified": True,
    }
    try:
        checkpoint_json(result)
    except ValueError as exc:
        raise CollectionError("CHECKPOINT_LIMIT", "재개 체크포인트 한도에 도달했습니다.") from exc
    return records, result


def _failure_report(spec, operation, code):
    return OperationReport(
        scope=spec.scopes[0],
        provenance=MetadataProvenance(
            operation=operation, observed_at=now(), source_commit=SOURCE_COMMIT
        ),
        status="FAILED",
        reasons=[code],
    )


def _retry_delay(error):
    delay = (getattr(error, "details", None) or {}).get("retry_after_seconds", 60)
    if not isinstance(delay, (int, float)) or not math.isfinite(delay):
        return 60
    return max(1, delay)


def collect_pages(spec, *, secrets, checkpoint, check, read_records=None, client=None, value_context=None):
    """Yield one native page and its restart cursor; worker owns atomic commit."""
    if not isinstance(spec, MetadataConnectionSpec):
        spec = MetadataConnectionSpec.model_validate(spec)
    config = _config(spec)
    extensions = Extensions(spec, value_context) if spec.options.sources else None
    saved = deepcopy(checkpoint or {})
    if saved.get("retry_not_before", 0) > time.time():
        check()
        pin = saved.get("settings", {}).get("principal_id")
        verified = saved.get("principal_verified", False)
        if pin is not None:
            pin = native_id(pin)
        if (
            pin is not None
            and spec.principal_pin is not None
            and pin != native_id(spec.principal_pin)
        ):
            raise ValueError("PRINCIPAL_CHANGED")
        yield MetadataPage(
            checkpoint=saved,
            principal_id=str(pin) if pin is not None and verified else None,
            principal_verified=verified,
            status="WAITING",
            reasons=["RETRY_LATER"],
            retry_after_seconds=max(
                1, min(3600, math.ceil(saved["retry_not_before"] - time.time()))
            ),
        )
        return
    saved.pop("retry_not_before", None)
    store = Store(config.fingerprint(), saved)
    # A budget-truncated source is terminal for this run, unlike a retryable API failure.
    for task_id, task in saved.get("tasks", {}).items():
        if (task.get("error") or {}).get("code") == "GITLAB_TARGET_LIMIT":
            store.state["tasks"][task_id] = deepcopy(task)
    if spec.options.include_values:
        from .variables import validate_context
        value_contract = validate_context(value_context).model_dump()
        prior = store.get_setting("gitlab_value_contract")
        if prior is not None and prior != value_contract:
            raise ValueError("GITLAB_VALUE_RESUME_CONTRACT_CHANGED")
        store.set_setting("gitlab_value_contract", value_contract)
    if read_records is not None:
        replay(store, read_records())
    elif saved.get("emitted"):
        raise ValueError("GITLAB_RECORD_REPLAY_REQUIRED")
    roots = {
        f"{scope.kind}:{scope.id}": index
        for index, scope in enumerate(spec.scopes)
        if scope.kind in {"group", "project", "organization"}
    }
    roots.update(saved.get("roots", {}))
    if any(type(index) is not int or not 0 <= index < len(spec.scopes) for index in roots.values()):
        raise ValueError("INVALID_GITLAB_CHECKPOINT")
    token = secrets.get("token", "")
    if not isinstance(token, str) or not token or "\r" in token or "\n" in token:
        raise ValueError("GITLAB_TOKEN_REFERENCE_REQUIRED")

    def sleep(seconds):
        remaining = seconds
        while remaining > 0:
            check()
            pause = min(remaining, 1.0)
            time.sleep(pause)
            remaining -= pause

    if client is None:
        client = Client(config, token, sleep=sleep, check=check)
    if getattr(client, "origin", None) != spec.origin:
        raise ValueError("GITLAB_CLIENT_ORIGIN_MISMATCH")
    if spec.principal_pin is not None:
        pin = native_id(spec.principal_pin)
        previous = store.get_setting("principal_id")
        if previous is not None and previous != pin:
            raise ValueError("PRINCIPAL_CHANGED")
        store.set_setting("principal_id", pin)
    collector = _BoundedCollector(config, client, store, extensions=extensions)
    emitted = int(saved.get("emitted", 0))
    reasons = set()
    committed = saved
    stop = False
    attempt_started = now()
    try:
        check()
        collector.initialize()
    except _EXPECTED_FAILURES as exc:
        code = exc.code if isinstance(exc, CollectionError) else "RESPONSE_SCHEMA_ERROR"
        if code in _DEFERRED:
            delay = _retry_delay(exc)
            saved = {**saved, **store.checkpoint(), "retry_not_before": time.time() + delay}
            verified = saved.get("principal_verified", False)
            previous = saved.get("settings", {}).get("principal_id")
            yield MetadataPage(
                checkpoint=saved,
                status="WAITING",
                reasons=[code],
                principal_id=str(previous) if previous is not None and verified else None,
                principal_verified=verified,
                retry_after_seconds=min(3600, math.ceil(delay)),
            )
            return
        failure = (
            [_failure_report(spec, "gitlab.bootstrap", code)] if emitted < spec.max_records else []
        )
        saved["emitted"] = emitted + len(failure)
        yield MetadataPage(records=failure, checkpoint=saved, status="FAILED", reasons=[code])
        return
    principal = str(collector.principal_id)
    if saved.get("phase") == "done":
        # Authentication still pins the approved principal, but completed sources never rerun.
        yield MetadataPage(
            checkpoint=saved,
            principal_id=principal,
            principal_verified=True,
            status=saved.get("finish_status", "COMPLETE"),
            reasons=saved.get("finish_reasons", []),
        )
        return
    if spec.options.include_resource_access_tokens and not config.include_resource_access_tokens:
        reasons.add("GITLAB_CLOUD_MANAGED_API_ONLY")
        store.note("GITLAB_CLOUD_MANAGED_API_ONLY", {"feature": "include_resource_access_tokens"})
        store.pending.append(
            ("capability", {"name": "include_resource_access_tokens", "status": "UNSUPPORTED"})
        )
    try:
        records, committed = _prepare(
            spec,
            store,
            roots,
            phase=saved.get("phase", "collect"),
            emitted=emitted,
            cursor=saved.get("final_cursor"),
        )
    except CollectionError as exc:
        yield MetadataPage(
            checkpoint=saved,
            principal_id=principal,
            principal_verified=True,
            status="PARTIAL" if emitted else "FAILED",
            reasons=[exc.code],
        )
        return
    roots = committed["roots"]
    emitted = committed["emitted"]
    store.pending.clear()
    yield MetadataPage(
        records=records, checkpoint=committed, principal_id=principal, principal_verified=True
    )

    if saved.get("phase") not in {"finalize", "done"}:
        while task := store.next_task(
            client.deferred_rate_classes() if hasattr(client, "deferred_rate_classes") else frozenset()
        ):
            check()
            wait_for = None
            try:
                if (
                    sum(source["pages"] for source in store.state["tasks"].values())
                    >= spec.max_pages
                ):
                    raise CollectionError(
                        "PAGE_LIMIT_REACHED", "전체 수집 페이지 한도에 도달했습니다."
                    )
                if client.requests >= spec.max_requests:
                    raise CollectionError(
                        "REQUEST_BUDGET_EXCEEDED", "이번 수집 시도의 요청 한도에 도달했습니다."
                    )
                collector.roots, collector.max_targets = roots, spec.options.max_targets
                collector.truncated = False
                collector.process(task)
                if collector.truncated:
                    with store.db:
                        store.note("GITLAB_TARGET_LIMIT", {"source_id": task["id"]})
                        store.error(task, "GITLAB_TARGET_LIMIT", "승인된 자산 발견 한도에 도달해 일부 대상을 생략했습니다.")
            except _EXPECTED_FAILURES as exc:
                code = exc.code if isinstance(exc, CollectionError) else "RESPONSE_SCHEMA_ERROR"
                with store.db:
                    store.error(
                        task,
                        code,
                        "공급자 응답을 완료하지 못했습니다.",
                        getattr(exc, "status", None),
                        "gitlab.collector",
                        getattr(exc, "details", None),
                    )
                reasons.add(code)
                stop = code in _GLOBAL_STOPS or code == "PAGE_LIMIT_REACHED"
                if code in _DEFERRED:
                    wait_for = _retry_delay(exc)
            try:
                records, candidate = _prepare(spec, store, roots, phase="collect", emitted=emitted)
            except CollectionError as exc:
                reasons.add(exc.code)
                yield MetadataPage(
                    checkpoint=committed,
                    principal_id=principal,
                    principal_verified=True,
                    status="PARTIAL" if emitted else "FAILED",
                    reasons=sorted(reasons),
                )
                return
            committed = candidate
            roots = committed["roots"]
            emitted = committed["emitted"]
            store.pending.clear()
            if wait_for is not None:
                committed["retry_not_before"] = time.time() + wait_for
                yield MetadataPage(
                    records=records,
                    checkpoint=committed,
                    principal_id=principal,
                    principal_verified=True,
                    status="WAITING",
                    reasons=sorted(reasons),
                    retry_after_seconds=min(3600, math.ceil(wait_for)),
                )
                return
            yield MetadataPage(
                records=records,
                checkpoint=committed,
                principal_id=principal,
                principal_verified=True,
            )
            if stop:
                store.note("COLLECTION_STOPPED", {"reason": code})
                break

    if extensions:
        for report in extensions.final_reports(store):
            store.pending = [("extension", report.model_dump())]
            try:
                records, committed = _prepare(spec, store, roots, phase="collect", emitted=emitted)
            except CollectionError as exc:
                yield MetadataPage(checkpoint=committed, status="PARTIAL", reasons=[exc.code],
                                   principal_id=principal, principal_verified=True)
                return
            emitted = committed["emitted"]
            store.pending.clear()
            if report.status != "COMPLETE":
                reasons.update(report.reasons)
            yield MetadataPage(records=records, checkpoint=committed,
                               principal_id=principal, principal_verified=True)
        reasons.update(note["code"] for note in store.get_setting("coverage_notes")
                       if note["code"] == "GITLAB_TOP_LEVEL_GROUP_REQUIRED")

    # Reconcile only once after source collection; reference events never create missing tokens.
    final = [("inventory", row) for row in store.inventory()]
    for row in store.audit_events():
        if row["inventory_id"] is not None:
            observed = store.state["records"][row["inventory_id"]]
            row["identity"] = observed["identity"]
            row["observed_scopes"] = [
                observation["context"]["scope"] for observation in observed["observations"].values()
            ]
        final.append(("audit", row))
    # Even sources stopped before their first request remain visible in exports.
    final += [
        ("source", row) for row in store.state["tasks"].values() if row["status"] != "complete"
    ]

    def final_key(pair):
        kind, payload = pair
        return (
            kind
            + ":"
            + str(
                payload[
                    {"inventory": "inventory_id", "audit": "audit_event_id", "source": "id"}[kind]
                ]
            )
        )

    final.sort(key=final_key)
    cursor = saved.get("final_cursor") if saved.get("phase") == "finalize" else None
    for kind, payload in final:
        check()
        key = final_key((kind, payload))
        if cursor is not None and key <= cursor:
            continue
        store.pending = [(kind, payload)]
        try:
            records, candidate = _prepare(
                spec, store, roots, phase="finalize", emitted=emitted, cursor=key
            )
        except CollectionError as exc:
            reasons.add(exc.code)
            yield MetadataPage(
                checkpoint=committed,
                principal_id=principal,
                principal_verified=True,
                status="PARTIAL",
                reasons=sorted(reasons),
            )
            return
        committed, emitted = candidate, candidate["emitted"]
        store.pending.clear()
        yield MetadataPage(
            records=records, checkpoint=committed, principal_id=principal, principal_verified=True
        )

    states = {task["status"] for task in store.coverage()}
    reasons.update(task["error"]["code"] for task in store.coverage() if task["error"])
    if "pending" in states:
        reasons.add("GITLAB_SOURCES_PENDING")
    status = "PARTIAL" if reasons or states - {"complete"} else "COMPLETE"
    # A partial run keeps failed/pending cursors retryable; only a finished run is marked done.
    committed = {
        **committed,
        "phase": "done" if status == "COMPLETE" else "collect",
        "finish_status": status,
        "finish_reasons": sorted(reasons),
        "final_cursor": None,
    }
    provenance = code_provenance()
    history = (store.get_setting("execution_history") or [])[-99:]
    history.append(
        {
            "started_at": attempt_started,
            "finished_at": now(),
            "status": status,
            "requests": client.requests,
            "retries": getattr(client, "retries", 0),
            "code_digest": provenance["source_digest"],
        }
    )
    run_payload = {
        "code_commit": SOURCE_COMMIT,
        "upgrade_source_commit": UPGRADE_SOURCE_COMMIT,
        "task_scheduling_policy": task_scheduling_policy(),
        "transport_settings": config.transport_settings(),
        "code_digest": provenance["source_digest"],
        "metadata_selection_policy": "cremore_inventory_v1",
        "metadata_merge_policy": "handler_priority_deep_merge_v1",
        "started_at": store.get_setting("started_at"),
        "count": len(store.state["records"]),
        "code_provenance": {
            "collector_version": provenance["collector_version"],
            "code_commit": provenance["git"].get("head"),
            "status": provenance["git"]["status"],
            "code_digest": provenance["source_digest"],
            "sources": [
                {"name": name, "digest": value}
                for name, value in provenance["source_files_sha256"].items()
            ],
        },
        "execution_history": history,
        "warnings": store.get_setting("coverage_notes") or [],
    }
    from .normalization import FactWriter

    writer = FactWriter()
    report = OperationReport(
        scope=spec.scopes[0],
        status=status,
        reasons=sorted(reasons),
        report_type="gitlab_inventory",
        native_schema_version="1.4",
        provenance=MetadataProvenance(
            operation="gitlab.run", observed_at=now(), source_commit=SOURCE_COMMIT
        ),
        facts=writer.facts(run_payload),
    )
    if emitted >= spec.max_records:
        status = "PARTIAL"
        reasons.add("RECORD_LIMIT")
        committed.update(phase="collect", finish_status=status, finish_reasons=sorted(reasons))
    else:
        committed["emitted"] = emitted + 1
    yield MetadataPage(
        records=[report] if emitted < spec.max_records else [],
        checkpoint=committed,
        principal_id=principal,
        principal_verified=True,
        status=status,
        reasons=sorted(reasons),
    )


def _projection(records, spec=None, config=None):
    if spec is not None:
        spec = (
            spec
            if isinstance(spec, MetadataConnectionSpec)
            else MetadataConnectionSpec.model_validate(spec)
        )
        config = _config(spec, collecting=False)
    store = Store(config.fingerprint() if config is not None else "projection")
    if config is not None:
        store.set_setting("config", asdict(config))
    normalized = [item.model_dump() if hasattr(item, "model_dump") else item for item in records]
    replay(store, normalized)
    return store, normalized


def export_records(records, *, spec=None, config=None):
    """Render common committed records in the native artifact shape without a sidecar DB."""
    from .presentation import order_for_json

    store, normalized = _projection(records, spec, config)
    result = store.export()
    result["inventory"] = [order_for_json(row, "inventory") for row in result["inventory"]]
    result["normalization_omissions"] = [
        {
            "operation": item["provenance"]["operation"],
            "resource_id": item["provenance"]["resource_id"],
            "omissions": item["omissions"],
        }
        for item in normalized
        if item.get("omissions")
    ]
    # Preserve the existing native inventory shape. New metadata-only sources
    # are an additive artifact; private comparison fingerprints never export.
    extra = [deepcopy(item) for item in normalized
             if item.get("provenance", {}).get("operation", "").startswith(EXTRA_PREFIX)]
    for item in extra:
        item.pop("value_match", None)
        item.pop("value_contract", None)
    if extra:
        result["supplemental_metadata"] = extra
    return result


def compare_records(records, previous, *, spec=None, config=None):
    """Accept legacy inventory artifacts and committed schema 2 run records."""
    from .extensions import compare_metadata

    store, normalized = _projection(records, spec, config)
    previous = list(read_previous_inventory(previous))
    common = previous and all(isinstance(row, dict) and row.get("record_type") in {
        "entity_observation", "relation", "provider_event", "operation_report"} for row in previous)
    if common:
        previous_store, previous_records = _projection(previous, spec, config)
        previous = list(previous_store.inventory())
    else:
        previous_records = []
    return list(store.compare(previous)) + compare_metadata(previous_records, normalized)


def _compare_runs(before, after, *, spec, scope_id=None):
    """Keep the native current/previous API behind the common run ordering."""
    return compare_records(after, before, spec=spec)
