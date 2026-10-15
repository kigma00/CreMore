"""GitHub collection inside the shared lease, batch and checkpoint lifecycle.

The Enterprise program's task graph is the engine: one page is read outside any
transaction, its follow-up tasks are derived from that page alone, and the
worker commits the records with the task state that resumes after them. The
organization program's per-source reads are the tasks a connection without an
enterprise scope runs. Neither mode reports a source it could not read as empty.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

from cremore.coverage.errors import CoverageError
from cremore.coverage.metadata_models import (
    MetadataConnectionSpec,
    MetadataPage,
    checkpoint_json,
    in_metadata_scope,
)
from cremore_github_provider.github_hosts import normalize_host

from . import CONTRACT_VERSION, SOURCE_COMMIT
from .actions import ACTION_TASKS, SECRET_SOURCES, secret_object_id
from .endpoints import EndpointError, first_path, next_path
from .http import Budget, SourceError, TokenBroker, Transport
from .normalization import (
    CONTEXT_KINDS,
    RESULT_KINDS,
    audit_event,
    identity,
    inventory_observation,
    object_id_for,
    observation,
    record_values,
    relation,
    report,
    token_activity,
)
from .pages import (
    ACTIONS_SOURCES,
    ENTERPRISE_SOURCES,
    ORG_SOURCES,
    _validate_task,
    audit_path,
    handle_enterprise_page,
    handle_page,
    seed_org_tasks,
    task,
)
from .projection import SLUG, installation_info

DEFERRED = {"github_rate_limited", "github_unavailable"}
# The key is not the configured App's, or cannot sign: no read can be trusted.
APP_CREDENTIAL = {"github_app_identity_mismatch", "github_app_private_key_invalid", "github_app_id_invalid"}
STOP = {"github_http_401", "github_invalid_response", "github_response_limit", *APP_CREDENTIAL}
# "These endpoints only support authentication using a personal access token
# (classic)" -- the Enterprise audit log (REST docs, 2026-03-10). An App
# installation token is refused there, so it is never offered to them.
ENTERPRISE_AUDIT_TASKS = frozenset({"audit", "git_audit"})
# Installation checks use the App JWT after current enterprise membership is
# confirmed with the approved enterprise's installation token.
CHECK_TASKS = frozenset({"app", "app_installations", "installation_check"})
APP_JWT_TASKS = frozenset({"app_installations", "installation_check"})
AUDIT_TOKEN = re.compile(r"ghp_[A-Za-z0-9]{36,251}")
ALL_SOURCES = ORG_SOURCES + ENTERPRISE_SOURCES + ACTIONS_SOURCES
_OBJECT_ID = {
    "credential": re.compile(r"^(?:sso|fgpat|token|oauth|inventory):[^\s]{1,2000}$"),
    "public_key": re.compile(r"^(?:sso|deployKey|inventory):[^\s]{1,2000}$"),
    "installation": re.compile(r"^installation:[0-9]{1,20}$"),
    "policy": re.compile(r"^policy:[^\s]{1,2000}$"),
    "request": re.compile(r"^patRequest:[^\s]{1,2000}$"),
    "principal": re.compile(r"^(?:principal|inventory):[^\s]{1,2000}$"),
    "resource": re.compile(r"^(?:repository|environment|organization):[^\s]{1,2000}$"),
    "vault_item": re.compile(r"^actionsSecret:(?:organization|repository|environment):[^\s]{1,2000}$"),
    "context": re.compile(r"^(?:installationRepository|organizations|run|job|actionsSecretRepository):[^\s]{1,2000}$"
                          r"|^app:[1-9][0-9]{0,19}$|^appInstallation:[0-9]{1,20}$|^inventoryAuthorization:[0-9a-f]{64}$"),
    "unknown": re.compile(r"^sso:[^\s]{1,2000}$"),
}


def validate_spec(spec):
    if spec.provider != "github":
        raise ValueError("GITHUB_PROVIDER_REQUIRED")
    if spec.edition not in {"cloud", "enterprise_cloud", "enterprise_server", "dedicated"}:
        raise ValueError("GITHUB_EDITION_NOT_SUPPORTED")
    try:
        host = normalize_host(spec.origin)
    except ValueError:
        raise ValueError("GITHUB_ORIGIN_NOT_SUPPORTED") from None
    if (spec.edition in {"cloud", "enterprise_cloud"}) != (host == ""):
        raise ValueError("GITHUB_EDITION_HOST_MISMATCH")
    if spec.edition == "dedicated" and not host.endswith(".ghe.com"):
        raise ValueError("GITHUB_EDITION_HOST_MISMATCH")
    if spec.edition == "enterprise_server" and (not host or host.endswith(".ghe.com")):
        raise ValueError("GITHUB_EDITION_HOST_MISMATCH")
    if spec.auth_type != "github_app":
        raise ValueError("GITHUB_APP_AUTHENTICATION_REQUIRED")
    required = {"app_id", "private_key"}
    if not required <= set(spec.secret_refs) or set(spec.secret_refs) - (
            required | {"installation_id", "audit_token"}):
        raise ValueError("GITHUB_APP_SECRET_ROLES_REQUIRED")
    if "audit_token" in spec.secret_refs and (spec.options.mode != "enterprise"
                                              or "audit" not in spec.capabilities
                                              or spec.options.audit_scope == "organization"):
        # The classic PAT is read for the Enterprise audit log and nothing else.
        raise ValueError("GITHUB_AUDIT_TOKEN_REQUIRES_ENTERPRISE_AUDIT")
    if "inventory" not in spec.capabilities:
        raise ValueError("GITHUB_INVENTORY_CAPABILITY_REQUIRED")
    if set(spec.capabilities) - {"inventory", "audit", "relations", "policy", "public_keys", "vault_metadata", "issuer_digest"}:
        raise ValueError("GITHUB_CAPABILITY_NOT_SUPPORTED")
    if spec.options.mode not in {"organization", "enterprise"} or spec.options.include_values:
        raise ValueError("GITHUB_INVALID_COLLECTION_MODE")
    if not spec.options.github_inventory and (not spec.options.include_audit_events
            or spec.options.sources or spec.options.include_actions or "vault_metadata" in spec.capabilities):
        raise ValueError("GITHUB_AUDIT_ONLY_REQUIRES_AUDIT_WITHOUT_INVENTORY_SOURCES")
    if spec.options.sources and set(spec.options.sources) - set(ALL_SOURCES):
        raise ValueError("GITHUB_INVALID_SOURCES")
    if spec.options.page_size > 100:
        raise ValueError("GITHUB_PAGE_SIZE_LIMIT")
    if ("issuer_digest" in spec.capabilities or spec.options.include_provider_hashes) and spec.options.mode != "enterprise":
        raise ValueError("GITHUB_PROVIDER_DIGEST_REQUIRES_ENTERPRISE_MODE")
    if set(spec.options.sources) & set(SECRET_SOURCES) and "vault_metadata" not in spec.capabilities:
        raise ValueError("GITHUB_ACTIONS_VAULT_METADATA_CAPABILITY_REQUIRED")
    if spec.options.mode == "organization" and set(spec.options.sources) & set(ENTERPRISE_SOURCES):
        raise ValueError("GITHUB_ENTERPRISE_SOURCE_REQUIRES_ENTERPRISE_MODE")
    if spec.principal_pin is not None:
        raise ValueError("GITHUB_PRINCIPAL_PIN_UNVERIFIABLE")
    if spec.options.include_audit_events and "audit" not in spec.capabilities:
        raise ValueError("GITHUB_AUDIT_CAPABILITY_REQUIRED")
    enterprise = [scope for scope in spec.scopes if scope.kind == "enterprise"]
    organizations = [scope for scope in spec.scopes if scope.kind == "organization"]
    if len(enterprise) + len(organizations) != len(spec.scopes):
        raise ValueError("GITHUB_INVALID_SCOPE_KIND")
    if spec.options.mode == "enterprise":
        if len(enterprise) != 1 or organizations:
            raise ValueError("GITHUB_SINGLE_ENTERPRISE_SCOPE_REQUIRED")
    elif enterprise or not organizations:
        raise ValueError("GITHUB_ORGANIZATION_SCOPES_REQUIRED")
    for scope in spec.scopes:
        if not SLUG.fullmatch(scope.id):
            raise ValueError("GITHUB_INVALID_SCOPE_SLUG")
    if len(organizations) > spec.options.max_targets:
        raise ValueError("GITHUB_TARGET_LIMIT")
    if spec.options.include_audit_events and spec.options.mode != "enterprise" and not any(
            scope.kind == "organization" for scope in spec.scopes):
        raise ValueError("GITHUB_AUDIT_SCOPE_REQUIRED")
    if spec.options.audit_scope != "both" and not spec.options.include_audit_events:
        raise ValueError("GITHUB_AUDIT_SCOPE_REQUIRES_AUDIT_EVENTS")
    if spec.options.audit_scope == "enterprise" and spec.options.mode != "enterprise":
        raise ValueError("GITHUB_ENTERPRISE_AUDIT_REQUIRES_ENTERPRISE_MODE")
    if spec.options.enterprise_only and (spec.options.mode != "enterprise" or spec.options.sources
                                         or spec.options.include_actions
                                         or spec.options.audit_scope == "organization"):
        # Without organizations there is nothing for a source, an Actions read
        # or an organization audit to read.
        raise ValueError("GITHUB_ENTERPRISE_ONLY_EXCLUDES_ORGANIZATION_READS")
    if spec.options.actions_run_days is not None and not (
            spec.options.include_actions or "repo_actions_runs" in spec.options.sources):
        raise ValueError("GITHUB_ACTIONS_RUN_DAYS_REQUIRES_ACTIONS")


def _root(spec):
    return spec.scopes[0]


def validate_record(spec, item):
    try:
        validate_spec(spec)
    except ValueError:
        return False
    if item.scope not in spec.scopes:
        return False
    if (item.provenance.contract_version != CONTRACT_VERSION
            or item.provenance.source_commit != SOURCE_COMMIT):
        return False
    for value in [getattr(item, name, None) for name in ("identity", "subject", "target")]:
        if value is None:
            continue
        if (value.provider, value.origin, value.tenant, value.tenant_confirmed) != (
                "github", spec.origin, spec.tenant, spec.tenant_confirmed):
            return False
        pattern = _OBJECT_ID.get(value.kind)
        if pattern is None or not pattern.fullmatch(value.object_id):
            return False
    if item.record_type == "provider_event" and item.purpose != "usage":
        return False
    return in_metadata_scope(spec, item)


def validate_machine_record(spec, item):
    """Outside submissions must name a scope this connection already approved."""
    if not validate_record(spec, item):
        return False
    expected = (item.scope.kind, item.scope.id.casefold())
    # The enclosing approved scope cannot relabel a native object or endpoint.
    # Only the worker can discover descendant organizations of an enterprise.
    # Every entity key must itself contain its approved scope. A caller-supplied
    # endpoint cannot bind a global inventory/installation/principal/App ID;
    # those keys intentionally remain available to the trusted worker only.
    identities = [value for attr in ("identity", "subject", "target")
                  if (value := getattr(item, attr, None)) is not None]
    for value in identities:
        native = tuple(_identity_scopes(value))
        if not native or any((kind, name.casefold()) != expected for kind, name in native):
            return False
    # Reports without an entity still need a scoped source endpoint. Metadata
    # labels and the operation's suffix alone do not establish native scope.
    if not identities and not tuple(_path_scopes(item.provenance.resource_id)):
        return False
    return all((kind, name.casefold()) == expected for kind, name in _native_scopes(item))


def _path_scopes(path):
    if not isinstance(path, str):
        return
    match = re.match(r"^/(orgs|repos|enterprises)/([^/?#]+)", path)
    if match:
        yield ("enterprise" if match[1] == "enterprises" else "organization", match[2])
    child = re.match(r"^/enterprises/[^/]+/apps/(?:organizations|installable_organizations)/([^/?#]+)", path)
    if child:
        yield "organization", child[1]


def _identity_scopes(value):
    prefix, rest = value.object_id.split(":", 1)
    if prefix == "organizations":
        yield "enterprise", rest
    elif prefix in {"sso", "fgpat", "token", "oauth", "patRequest", "deployKey",
                    "repository", "environment", "run", "job", "actionsSecretRepository"}:
        yield "organization", rest.split(":", 1)[0].split("/", 1)[0]
    elif prefix == "installationRepository":
        yield "organization", rest.split(":", 1)[-1].split("/", 1)[0]
    elif prefix == "actionsSecret":
        yield "organization", rest.split(":", 2)[1].split("/", 1)[0]
    elif prefix == "policy":
        if rest.startswith("/"):
            yield from _path_scopes(rest)
        else:
            yield "organization", rest.split(":", 1)[0].split("/", 1)[0]


def _native_scopes(item):
    yield from _path_scopes(item.provenance.resource_id)
    for attr in ("identity", "subject", "target"):
        value = getattr(item, attr, None)
        if value is not None:
            yield from _identity_scopes(value)
    operation = item.provenance.operation
    if ":" in operation:
        yield "organization", operation.split(":", 1)[1].split("/", 1)[0]
    values = record_values(item)
    for key, kind in (("org", "organization"), ("enterprise", "enterprise")):
        if isinstance(values.get(key), str) and values[key]:
            yield kind, values[key]
    for name in values.get("organization", []) if isinstance(values.get("organization"), list) else []:
        if isinstance(name, str):
            yield "organization", name
    if isinstance(values.get("scope"), str) and values["scope"]:
        yield item.scope.kind, values["scope"]
    yield from _path_scopes(values.get("path"))
    for row in (values, values.get("repository", {})):
        if isinstance(row, dict):
            for key in ("full_name", "repository_full_name", "repo"):
                if isinstance(row.get(key), str) and "/" in row[key]:
                    yield "organization", row[key].split("/", 1)[0]


# -- task state ------------------------------------------------------------


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _task_id(item):
    return _digest([item["kind"], item["auth"], item.get("org"), item["path"]])[:32]


def _compact(item):
    """Only the context a follow-up task must reconstruct is carried forward."""
    context = item.get("context") or {}
    trimmed = {}
    if "repository" in context:
        trimmed["repository"] = {key: context["repository"][key]
                                 for key in ("id", "name", "full_name", "visibility")
                                 if key in context["repository"]}
    if "credential" in context:
        # The whole projected credential travels with its follow-up task: the
        # repositories page reports that credential, and a record reduced to an
        # id would look like a credential whose state is suddenly unknown.
        trimmed["credential"] = deepcopy(context["credential"])
    if "installation_id" in context:
        trimmed["installation_id"] = context["installation_id"]
    if "installation" in context:
        trimmed["installation"] = {key: context["installation"][key]
                                   for key in ("id", "installation_id", "app_slug",
                                               "client_id", "repository_selection",
                                               "created_at", "updated_at", "account")
                                   if key in context["installation"]}
    if "run" in context:
        trimmed["run"] = {key: context["run"][key] for key in ("id", "run_attempt")
                          if key in context["run"]}
    for key in ("environment", "secret_name"):
        if key in context:
            trimmed[key] = context[key]
    return {**{key: item[key] for key in ("kind", "scope", "org", "enterprise", "auth", "path",
                                          "paginated", "collection_key", "priority")},
            "context": trimmed}


def _config_hash(spec, check=None):
    from cremore.coverage.models import digest

    return digest(spec.model_dump()) if check is None else digest([spec.model_dump(), check, "live-membership-v1"])


def _legacy_config_hash(spec, check=None):
    """Only the absent, formerly implicit inventory=true option is compatible.

    Every other field remains covered, including permissions, limits and scope.
    Never use a defaults-insensitive hash to accept arbitrary configuration changes.
    """
    from cremore.coverage.models import digest

    if not spec.options.github_inventory:
        return None
    values = spec.model_dump()
    values["options"].pop("github_inventory")
    return digest(values) if check is None else digest([values, check, "live-membership-v1"])


def _git_window(window):
    """GitHub keeps Git events for seven days; older entries cannot be read."""
    end = datetime.fromisoformat(window[1])
    return [max(datetime.fromisoformat(window[0]), end - timedelta(days=7)).isoformat(), window[1]]


def _run_window(spec, run):
    """The created range for Actions runs: their own window when set, else the audit window."""
    if spec.options.actions_run_days is None:
        return run.window[0][:10] + ".." + run.window[1][:10]
    end = datetime.fromisoformat(run.window[1])
    return (end - timedelta(days=spec.options.actions_run_days)).date().isoformat() + ".." + end.date().isoformat()


def _window(spec, started):
    end = datetime.fromisoformat(started).replace(microsecond=0)
    days = spec.options.audit_lookback_days or 180
    start = end - timedelta(days=days)
    if spec.options.audit_created_after:
        floor = datetime.fromisoformat(spec.options.audit_created_after)
        start = max(start, floor.replace(microsecond=0))
    return [start.isoformat(), end.isoformat()]


class _Run:
    def __init__(self, spec, state, config_hash, now=None, check=None):
        self.spec = spec
        self.check = check
        self.now = now
        self.config_hash = config_hash
        self.scope = _root(spec)
        self.enterprise = self.scope.id if self.scope.kind == "enterprise" else ""
        self.tasks = dict(state.get("tasks") or {})
        self.emitted = int(state.get("emitted", 0))
        self.requests = int(state.get("requests", 0))
        self.reasons = set(state.get("reasons") or [])
        self.status = state.get("status", "COMPLETE")
        moment = now() if callable(now) else datetime.now(UTC)
        self.started = state.get("started_at") or moment.astimezone(UTC).replace(
            microsecond=0).isoformat()
        self.window = state.get("window") or _window(spec, self.started)
        self.generated_at = state.get("generated_at")
        self.refused = dict(state.get("refused") or {})
        self.authorized_orgs = {scope.id.casefold() for scope in spec.scopes if scope.kind == "organization"}
        if self.check is not None and self.enterprise:
            planned = {org.casefold() for org in self.check["orgs"]}
            self.authorized_orgs.update(org for org in state.get("verified_check_orgs", [])
                                        if isinstance(org, str) and org in planned)

    def checkpoint(self):
        return checkpoint_json({
            "version": 1, "provider": "github", "config_hash": self.config_hash,
            "tasks": self.tasks, "emitted": self.emitted, "requests": self.requests,
            "reasons": sorted(self.reasons), "status": self.status, "started_at": self.started,
            "window": self.window, "generated_at": self.generated_at, "refused": self.refused,
            "verified_check_orgs": sorted(self.authorized_orgs) if self.check is not None else [],
        })

    def degrade(self, status, *reasons):
        self.reasons.update(code.upper()[:96] for code in reasons if code)
        if status == "FAILED" or self.status == "FAILED":
            self.status = "FAILED"
        elif status == "PARTIAL":
            self.status = "PARTIAL"

    def add(self, children):
        for child in children:
            item = _compact(child)
            item_id = _task_id(item)
            if item_id in self.tasks:
                continue
            if len(self.tasks) >= min(self.spec.max_pages, 2000):
                self.degrade("PARTIAL", "TASK_BUDGET_EXCEEDED")
                return
            item.update(id=item_id, status="pending", pages=0, count=0,
                        next_path=first_path(item["path"], paginated=item["paginated"],
                                             page_size=self.spec.options.page_size),
                        error=None, warnings=[])
            self.tasks[item_id] = item

    def out_of_time(self):
        """The run's own wall clock since it started, rate-limit waits included."""
        limit = self.spec.options.run_time_limit_minutes
        if limit is None:
            return False
        moment = self.now() if callable(self.now) else datetime.now(UTC)
        return moment - datetime.fromisoformat(self.started) >= timedelta(minutes=limit)

    def pending(self):
        rows = [item for item in self.tasks.values() if item["status"] == "pending"]
        return min(rows, key=lambda row: (row["priority"], row["id"])) if rows else None

    def charge(self, records):
        if self.emitted + len(records) > self.spec.max_records:
            raise Budget("RECORD_BUDGET_EXCEEDED")
        self.emitted += len(records)


def _seed(spec, run):
    # The App behind the key is confirmed first: GET /app, compared with the configured ID.
    app = {**task(run.enterprise, "", "app", "/app", auth="app", paginated=False, priority=0),
           "scope": "", "org": ""}
    if run.check is not None:
        seeds = [app]
        if run.enterprise:
            seeds.append({**task(run.enterprise, "", "organizations",
                                f"/enterprises/{run.enterprise}/apps/installable_organizations",
                                auth="enterprise", priority=1), "scope": "", "org": ""})
        # The App's whole installation list, or this App's installation on each named organization.
        if run.check["listing"]:
            return seeds + [{**task(run.enterprise, "", "app_installations", "/app/installations", auth="app",
                                 priority=5), "scope": "", "org": ""}]
        return seeds + [task(run.enterprise, org, "installation_check", f"/orgs/{org}/installation", auth="app",
                             paginated=False, priority=10) for org in run.check["orgs"]]
    if spec.options.mode == "enterprise":
        enterprise = run.enterprise
        seeds = [app]
        if spec.options.github_inventory:
            seeds.append({**task(enterprise, "", "inventory", f"/enterprises/{enterprise}/credentials/exports",
                                auth="enterprise", paginated=False, priority=10), "scope": "", "org": ""})
        if not spec.options.enterprise_only:
            seeds.append({**task(enterprise, "", "organizations",
                                 f"/enterprises/{enterprise}/apps/installable_organizations",
                                 auth="enterprise", priority=20), "scope": "", "org": ""})
        enterprise_audit = spec.options.include_audit_events and spec.options.audit_scope != "organization"
        if enterprise_audit:
            seeds.append({**task(enterprise, "", "audit",
                                 audit_path(enterprise, run.window, enterprise=True),
                                 auth="enterprise", priority=80), "scope": "", "org": ""})
        if enterprise_audit and spec.options.include_provider_hashes:
            # Git clone/fetch/push made with a token carry its hash too; only the
            # keyed token-activity summaries keep anything from these entries.
            seeds.append({**task(enterprise, "", "git_audit",
                                 audit_path(enterprise, _git_window(run.window), enterprise=True, include="git"),
                                 auth="enterprise", priority=85), "scope": "", "org": ""})
        return seeds
    seeds = [app]
    for scope in spec.scopes:
        if spec.options.github_inventory:
            seeds.extend(seed_org_tasks("", scope.id, sources=tuple(spec.options.sources),
                                        include_actions=spec.options.include_actions,
                                        server=spec.edition == "enterprise_server"))
        if spec.options.include_audit_events:
            seeds.append(task("", scope.id, "org_audit", audit_path(scope.id, run.window),
                              auth="org", priority=90))
    return seeds


# -- record projection -----------------------------------------------------


def _scope_for(spec, current):
    """A record belongs to the connection scope that authorised its read."""
    if spec.options.mode == "enterprise":
        return _root(spec)
    org = (current.get("org") or "").lower()
    for scope in spec.scopes:
        if scope.id.lower() == org:
            return scope
    return _root(spec)


def _records(spec, run, current, output, value_context=None):
    scope = _scope_for(spec, current)
    records = []
    operation = "github." + current["kind"]
    for values in output.get("vault_items", []):
        records.append(observation(spec, scope, kind="vault_item", object_id=secret_object_id(values),
            operation=operation, resource_id=current["path"], row=values, purpose="vault_metadata"))
    for repository in output.get("secret_repositories", []):
        if "relations" in spec.capabilities:
            secret_id = secret_object_id({"org": current["org"], "resource_type": "organization",
                                          "name": current["context"]["secret_name"]})
            records.append(relation(spec, scope, identity(spec, "vault_item", secret_id),
                identity(spec, "resource", "repository:" + repository["full_name"]),
                relation_kind="can_access", match_basis="PROVIDER_EXPLICIT", confidence="EXACT",
                operation=operation, resource_id=current["path"],
                facts={"full_name": repository["full_name"]}, purpose="vault_metadata"))
        else:
            records.append(observation(spec, scope, kind="context",
                object_id=f"actionsSecretRepository:{current['org']}:{current['context']['secret_name']}:{repository['id']}",
                operation=operation, resource_id=current["path"], purpose="vault_metadata",
                row={"name": current["context"]["secret_name"], "org": current["org"],
                     "repository": repository, "resource_type": "organization"}))
    for entry in output.get("inventory_items", []):
        records.append(inventory_observation(spec, scope, entry, operation=operation,
                                             generated_at=output.get("generated_at"), value_context=value_context))
    for entry in output.get("reports", []):
        for collector, result in entry["results"].items():
            for key, (kind, prefix) in RESULT_KINDS.items():
                for row in result.get(key, []) or []:
                    records.extend(_result_records(spec, run, scope, current, collector, kind,
                                                   prefix, row, operation))
            for repository in result.get("repositories", []) or []:
                records.extend(_repository_records(spec, scope, current, repository, operation))
            if result.get("organization_workflow_permissions") is not None:
                records.append(observation(
                    spec, scope, kind="policy",
                    object_id="policy:/orgs/" + (current["org"] or "") + "/actions/workflow",
                    operation=operation, resource_id=current["path"],
                    row=result["organization_workflow_permissions"], purpose="issuer_inventory"))
    for entry in output.get("contexts", []):
        records.extend(_context_records(spec, run, scope, current, entry, operation, value_context))
    records.extend(_installation_records(spec, output.get("installations", []), operation=operation))
    return records


def _result_records(spec, run, scope, current, collector, kind, prefix, row, operation):
    org = current["org"]
    object_id = object_id_for(prefix, org, row)
    records = [observation(spec, scope, kind=kind, object_id=object_id, operation=operation,
                           resource_id=current["path"], row=row)]
    if "relations" not in spec.capabilities:
        return records
    owner = row.get("owner") or row.get("account")
    login = owner.get("login") if isinstance(owner, dict) else row.get("login")
    if isinstance(login, str) and login:
        records.append(relation(
            spec, scope, identity(spec, "principal", "principal:" + login),
            identity(spec, kind, object_id), relation_kind="owns", match_basis="PROVIDER_ID",
            confidence="EXACT", operation=operation, resource_id=current["path"],
            facts={"login": login, "source": collector}))
    repository = row.get("repository")
    if isinstance(repository, dict) and repository.get("full_name"):
        records.append(relation(
            spec, scope, identity(spec, kind, object_id),
            identity(spec, "resource", "repository:" + repository["full_name"]),
            relation_kind="can_access", match_basis="PROVIDER_EXPLICIT", confidence="IDENTIFIER",
            operation=operation, resource_id=current["path"],
            facts={"full_name": repository["full_name"]}))
    return records


def _repository_records(spec, scope, current, entry, operation):
    records = []
    repository = entry.get("repository") if isinstance(entry, dict) else None
    if not isinstance(repository, dict) or not repository.get("full_name"):
        return records
    for field in ("workflow_permissions", "actions_permissions", "fork_pr_workflow_settings"):
        if entry.get(field) is not None:
            records.append(observation(
                spec, scope, kind="policy",
                object_id=f"policy:{repository['full_name']}:{field}", operation=operation,
                resource_id=current["path"], row={**entry[field], "full_name": repository["full_name"]}))
    for run_row in entry.get("workflow_runs", []) or []:
        row = {**run_row, "full_name": repository["full_name"]}
        records.append(observation(
            spec, scope, kind="context",
            object_id=(f"run:{repository['full_name']}:{run_row['id']}"
                       f":{run_row['run_attempt']}"),
            operation=operation, resource_id=current["path"], row=row, purpose="usage"))
    return records


def _context_records(spec, run, scope, current, entry, operation, value_context=None):
    mapped = CONTEXT_KINDS.get(entry["kind"])
    metadata = entry.get("metadata")
    if mapped is None and entry["kind"] not in ("audit_events", "enterprise_organizations", "app_identity"):
        return []
    kind, prefix = mapped or ("context", "context")
    if entry["kind"] == "audit_events":
        events = []
        for row in metadata or []:
            event = audit_event(spec, scope, row, operation=operation, org=entry.get("org", ""),
                                value_context=value_context if spec.options.include_provider_hashes else None)
            if event is not None:
                events.append(event)
        if spec.options.include_provider_hashes:
            events.extend(token_activity(spec, scope, metadata or [], value_context, operation=operation))
        return events
    if entry["kind"] == "app_identity":
        return [observation(spec, scope, kind="context", object_id=f"app:{metadata['id']}",
                            operation=operation, resource_id=current["path"], row=metadata)]
    if entry["kind"] == "enterprise_organizations":
        return [observation(spec, scope, kind="context",
                            object_id="organizations:" + (current["enterprise"] or "enterprise"),
                            operation=operation, resource_id=current["path"],
                            row={"organization": [row["login"] for row in metadata or []]})]
    if not isinstance(metadata, dict):
        return []
    object_id = object_id_for(prefix, current["org"], metadata) if prefix in (
        "repository", "installation", "installationRepository", "patRequest") else (
        f"{prefix}:{current['org']}:{entry['external_id']}")
    return [observation(spec, scope, kind=kind, object_id=object_id[:2048], operation=operation,
                        resource_id=current["path"], row=metadata, purpose="issuer_inventory")]


def _installation_records(spec, discoveries, *, operation="github.installation"):
    """This App's installation on an organization or the Enterprise, as its own lookup saw it.

    The App's evidence about itself, for organization health. It is not a second
    observation of the installation entity the organization and Enterprise listings
    record in their own shape, so that entity keeps one shape.
    """
    records = []
    for scope_kind, owner, info in discoveries:
        row = {key: info[key] for key in ("id", "app_id", "target_type", "account_id",
                                          "repository_selection", "suspended_at", "permissions")
               if info.get(key) is not None}
        enterprise = scope_kind == "enterprise"
        row["enterprise" if enterprise else "org"] = owner
        records.append(observation(spec, _scope_for(spec, {"org": "" if enterprise else owner}),
                                   kind="context", object_id=f"appInstallation:{info['id']}",
                                   operation=operation, row=row,
                                   resource_id=f"/{'enterprises' if enterprise else 'orgs'}/{owner}/installation"))
    return records


def _validated(spec, records):
    for item in records:
        if not validate_record(spec, item):
            raise ValueError("GITHUB_NORMALIZATION_FAILED")
    return records


# -- the engine ------------------------------------------------------------


def _check_plan(plan):
    """A recollection plan is only ever an installation check, from plan_recollection."""
    if plan is None:
        return None
    check = plan.get("installation_check") if isinstance(plan, dict) and set(plan) == {"installation_check"} else None
    if (not isinstance(check, dict) or set(check) != {"orgs", "listing"} or not isinstance(check["listing"], bool)
            or not isinstance(check["orgs"], list) or not all(isinstance(org, str) and SLUG.fullmatch(org)
                                                               for org in check["orgs"])
            or not check["listing"] and len(check["orgs"]) != 1):
        raise ValueError("GITHUB_INVALID_INSTALLATION_CHECK")
    return {"orgs": sorted(set(check["orgs"]), key=str.casefold), "listing": check["listing"]}


def plan_recollection(records, *, scope_id=None, operations=None, include_unverified=False):
    """After a collection only an installation check can run: one organization it knew, or all of them.

    Nothing is re-collected. A named organization is re-looked-up (GET
    /orgs/{org}/installation); without one, the App's installation list is read
    (GET /app/installations) and joined to the organizations the collection knew.
    """
    from .snapshot import organization_roster

    if operations != ["installation_check"] or include_unverified:
        raise CoverageError("GITHUB_ONLY_AN_INSTALLATION_CHECK_FOLLOWS_A_COLLECTION")
    roster = organization_roster(records)
    if roster["installation_check"]:
        # A check knows only what it checked; its base must be a collection.
        raise CoverageError("GITHUB_INSTALLATION_CHECK_NEEDS_A_COLLECTION_BASE")
    known = {row["org"].casefold(): row["org"] for row in roster["items"]}
    if scope_id is None:
        return {"installation_check": {"orgs": sorted(known.values(), key=str.casefold), "listing": True}}
    if not isinstance(scope_id, str) or scope_id.casefold() not in known:
        raise CoverageError("GITHUB_ORGANIZATION_NOT_OBSERVED_BY_THE_COLLECTION")
    return {"installation_check": {"orgs": [known[scope_id.casefold()]], "listing": False}}


def collect_pages(spec, *, secrets, checkpoint, check, read_records=None, transport=None,
                  client=None, broker=None, now=None, value_context=None, recollection_plan=None, export_control=None):
    if not isinstance(spec, MetadataConnectionSpec):
        spec = MetadataConnectionSpec.model_validate(spec)
    validate_spec(spec)
    if spec.options.include_provider_hashes:
        from .digest_evidence import context_key

        context_key(value_context)
    if not {"app_id", "private_key"} <= set(secrets):
        raise ValueError("GITHUB_APP_SECRET_ROLES_REQUIRED")
    state = deepcopy(checkpoint or {})
    installation_check = _check_plan(recollection_plan)
    config_hash = _config_hash(spec, installation_check)
    if state and (state.get("provider") != "github" or state.get("version") != 1
                  or state.get("config_hash") not in {config_hash, _legacy_config_hash(spec, installation_check)}
                  or not state.get("config_hash")):
        raise ValueError("GITHUB_CHECKPOINT_MISMATCH")
    if state and read_records is None:
        raise ValueError("GITHUB_RECORD_REPLAY_REQUIRED")
    run = _Run(spec, state, config_hash, now, installation_check)
    if run.enterprise and any(t.get("kind") == "inventory"
            and t.get("path") == f"/enterprises/{run.enterprise}/credentials" for t in run.tasks.values()):
        # The retired list's pages and a new Export are different snapshots.
        # Keep committed evidence, close the old run as partial and let the next
        # ordinary manual/scheduled collection start a fresh Export. No I/O or
        # quota reservation is performed during this recovery.
        check()
        run.degrade("PARTIAL", "GITHUB_INVENTORY_API_CHANGED_RECOLLECT")
        yield MetadataPage(records=[], checkpoint=run.checkpoint(), status="PARTIAL", reasons=sorted(run.reasons))
        return
    if installation_check is not None:
        orgs = {org.casefold() for org in installation_check["orgs"]}
        if spec.options.mode == "organization" and not orgs <= run.authorized_orgs:
            raise ValueError("GITHUB_INSTALLATION_CHECK_OUT_OF_SCOPE")
    if read_records is not None and spec.options.mode == "enterprise" and installation_check is None:
        for row in read_records():
            if (row.get("record_type") == "entity_observation"
                    and row.get("scope") == run.scope.model_dump()
                    and row.get("provenance", {}).get("operation") == "github.organizations"
                    and row.get("identity", {}).get("object_id") == "organizations:" + run.enterprise):
                run.authorized_orgs.update(name.casefold() for name in record_values(row).get("organization", [])
                                           if isinstance(name, str) and SLUG.fullmatch(name))
    if not run.tasks:
        run.add(_seed(spec, run))

    own_client = client is None and transport is None
    if transport is None:
        import httpx

        client = client or httpx.Client(timeout=spec.options.timeout_seconds,
                                        follow_redirects=False)
        transport = Transport(client, origin=spec.origin, options=spec.options,
                              max_requests=max(0, spec.max_requests - run.requests),
                              enterprise=run.enterprise, check=check)
    if broker is None:
        broker = TokenBroker(transport, app_id=secrets["app_id"],
                             private_key=secrets["private_key"],
                             client_factory=lambda: client, enterprise=run.enterprise,
                             installation_id=secrets.get("installation_id"), now=now)
    broker.restore(run.refused)
    spent = run.requests
    try:
        if run.pending() is not None and run.requests >= spec.max_requests:
            raise Budget("REQUEST_BUDGET_EXCEEDED")
        try:
            yield from _drive(spec, run, transport, broker, value_context,
                              secrets.get("audit_token") if "audit_token" in spec.secret_refs else None,
                              export_control=export_control)
        finally:
            run.requests = spent + transport.requests
            run.refused = broker.refused()
    except Budget as exc:
        run.degrade("PARTIAL", exc.code)
        yield MetadataPage(checkpoint=run.checkpoint(), status=run.status,
                           reasons=sorted(run.reasons))
    finally:
        broker.close()
        if own_client and client is not None:
            client.close()


def _audit_bearer(token, configured=False):
    """The Enterprise audit log's own credential; the App token is never sent there."""
    if not token:
        # A configured PAT the worker could not resolve fails these reads, not the run.
        raise SourceError("github_enterprise_audit_token_unavailable" if configured
                          else "github_enterprise_audit_token_required")
    if not AUDIT_TOKEN.fullmatch(token):
        raise SourceError("github_enterprise_audit_token_invalid")
    return token


def _drive(spec, run, transport, broker, value_context=None, audit_token=None, *, export_control=None):
    spent = run.requests
    while True:
        current = run.pending()
        if current is None:
            break
        if sum(item["pages"] for item in run.tasks.values()) >= spec.max_pages:
            raise Budget("PAGE_BUDGET_EXCEEDED")
        if run.out_of_time():
            # What was read stays; the rest is reported as not reached, never as empty.
            raise Budget("TIME_BUDGET_EXCEEDED")
        # Only a page accepted by the record budget may publish task progress.
        current = deepcopy(current)
        covered = []
        records, terminal = [], None
        try:
            _validate_pending_task(spec, run, current)
            if current["kind"] == "inventory":
                from .export_run import collect as collect_export
                waiting = yield from collect_export(spec, run, current, transport, broker,
                    value_context=value_context, spent=spent, report=_task_report, validate=_validated,
                    control=export_control)
                if waiting:
                    return
                continue
            if current["kind"] == "app":
                payload, headers = broker.app(), {}
            else:
                if current["kind"] in ENTERPRISE_AUDIT_TASKS:
                    bearer = _audit_bearer(audit_token, "audit_token" in spec.secret_refs)
                elif current["kind"] in APP_JWT_TASKS:
                    bearer = broker.app_jwt()
                else:
                    # An enterprise-auth task always uses the enterprise installation,
                    # whichever organization the page is about.
                    bearer = broker.token_for(
                        current["auth"],
                        run.enterprise if current["auth"] == "enterprise" else current.get("org", ""))
                payload, headers = transport.request("GET", current["next_path"], bearer)
            app_id = str(broker.app()["id"]) if current["kind"] in APP_JWT_TASKS else None
            output = _process(spec, run, current, payload, headers, transport, app_id)
        except SourceError as error:
            if error.code in DEFERRED:
                run.requests = spent + transport.requests
                yield MetadataPage(
                    checkpoint=run.checkpoint(), status="WAITING", reasons=[error.code.upper()],
                    retry_after_seconds=max(1, min(3600, math.ceil(error.retry_after or 60))))
                return
            code = error.code
            if current["kind"] in ENTERPRISE_AUDIT_TASKS and code in {"github_http_401", "github_http_403"}:
                # A refused audit PAT fails its own task; the App's reads and the
                # organization audits that stand in for it still run.
                code = "github_enterprise_audit_token_rejected"
            if current["kind"] == "installation_check" and code in {"github_http_403", "github_http_404"}:
                # A refused lookup can hide an installation; it is never read as not installed.
                code = "organization_installation_" + code
            current.update(status="failed", error=code[:96])
            run.degrade("PARTIAL", code)
            terminal = code if code in STOP else None
            output = None
        except EndpointError as error:
            current.update(status="failed", error=str(error)[:96])
            run.degrade("PARTIAL", str(error))
            output = None
        except CoverageError:
            # The platform's check (pause, revision change) is not a page failure.
            raise
        except ValueError as error:
            code = str(error) if re.fullmatch(r"[a-z_]{1,96}", str(error)) else "invalid_page_data"
            current.update(status="failed", error=code)
            run.degrade("PARTIAL", code)
            output = None
        if output is not None:
            records = _validated(spec, _records(spec, run, current, output, value_context))
            if any(omission.reason == "INVALID_PROVIDER_DIGEST" for item in records for omission in item.omissions):
                output.setdefault("warnings", []).append("invalid_provider_digest")
            current["pages"] += 1
            current["count"] += len(records)
            if "received_count" in output:
                current["received_count"] = current.get("received_count", 0) + output["received_count"]
                current["expected_count"] = output["expected_count"]
            current["warnings"] = sorted(set(current.get("warnings", []) + output.get(
                "warnings", [])))
            following = output.get("next_path")
            current["next_path"] = following
            current["status"] = "pending" if following else "complete"
            if output.get("warnings"):
                codes = [warning if re.fullmatch(r"[a-z_]{1,96}", warning)
                         else "github_inventory_metadata_incomplete" for warning in output["warnings"]]
                run.degrade("PARTIAL", *codes)
            if current["kind"] == "audit" and current["status"] == "complete":
                # The enterprise log already contains every organization's
                # entries, so the per-organization reads are not repeated --
                # and each one still says so in its own report.
                for fallback in run.tasks.values():
                    if fallback["kind"] == "org_audit" and fallback["status"] == "pending":
                        fallback = {**fallback, "status": "covered_by_enterprise"}
                        covered.append(fallback)
                        records.append(_task_report(spec, run, fallback))
        # An installation looked up for this page is kept with it, even when the read failed.
        records.extend(_installation_records(spec, broker.discovered()))
        if current["status"] != "pending":
            records.append(_task_report(spec, run, current,
                                        generated_at=(output or {}).get("generated_at")))
        _validated(spec, records)
        run.charge(records)
        run.tasks[current["id"]] = current
        for fallback in covered:
            run.tasks[fallback["id"]] = fallback
        if output is not None:
            if current["kind"] == "organizations":
                for entry in output.get("contexts", []):
                    if entry.get("kind") == "enterprise_organizations":
                        names = {row["login"].casefold() for row in entry["metadata"]}
                        if run.check is not None:
                            names &= {org.casefold() for org in run.check["orgs"]}
                        run.authorized_orgs.update(names)
            run.add(output.get("tasks", []))
            run.generated_at = output.get("generated_at") or run.generated_at
        run.requests = spent + transport.requests
        run.refused = broker.refused()
        yield MetadataPage(records=records, checkpoint=run.checkpoint())
        if terminal:
            # An App that could not be confirmed, or a key that cannot sign, fails the
            # run as it did before the identity check; any other stop keeps what was read.
            run.degrade("FAILED" if current["kind"] == "app" or terminal in APP_CREDENTIAL else "PARTIAL",
                        "COLLECTION_STOPPED")
            break
    yield MetadataPage(checkpoint=run.checkpoint(), status=run.status,
                       reasons=sorted(run.reasons))


def _installations_listed(run, payload, app_id):
    """This App's installations on the organizations the collection knew, and how many others it has."""
    if not isinstance(payload, list) or not all(isinstance(row, dict) for row in payload):
        raise EndpointError("unexpected_installation_list_shape")
    found, warnings = [], set()
    for row in payload:
        try:
            info = installation_info(row)
        except ValueError:
            warnings.add("invalid_installation_row")
            continue
        login = info["account_login"].casefold()
        if str(info["app_id"]) != app_id:
            warnings.add("app_installation_identity_mismatch")
        elif info["target_type"] == "Organization" and login in run.authorized_orgs:
            found.append(("org", info["account_login"], info))
        elif info["target_type"] == "Enterprise" and run.enterprise and login == run.enterprise.casefold():
            found.append(("enterprise", info["account_login"], info))
        # Another account's installation is only counted: received, not saved.
    return {"installations": found, "received_count": len(payload), "expected_count": None,
            "warnings": sorted(warnings), "generated_at": None}


def _process(spec, run, current, payload, headers, transport, app_id=None):
    kind = current["kind"]
    if kind == "app":
        output = {"contexts": [{"kind": "app_identity", "metadata": payload}], "warnings": [],
                  "generated_at": None}
    elif kind == "app_installations":
        output = _installations_listed(run, payload, app_id)
    elif kind == "installation_check":
        info = installation_info(payload)
        if (info["target_type"] != "Organization" or info["account_login"].casefold() != current["org"].casefold()
                or str(info["app_id"]) != app_id):
            raise EndpointError("installation_not_this_apps")
        output = {"installations": [("org", current["org"], info)], "warnings": [], "generated_at": None}
    elif kind in ("inventory", "organizations", "audit", "org_audit", "git_audit"):
        output = handle_enterprise_page(
            current, payload, headers, enterprise=run.enterprise, window=run.window,
            include_audit=spec.options.include_audit_events and spec.options.audit_scope != "enterprise",
            sources=tuple(spec.options.sources), include_actions=spec.options.include_actions,
            server=spec.edition == "enterprise_server")
        if run.check is not None:
            output["tasks"] = []
        elif not spec.options.github_inventory:
            output["tasks"] = [t for t in output.get("tasks", []) if t["kind"] == "org_audit"]
    else:
        options = {"include_actions": spec.options.include_actions,
                   "sources": spec.options.sources,
                   "run_window": _run_window(spec, run)}
        output = handle_page(current, payload, options=options)
        output.setdefault("warnings", [])
        output.setdefault("generated_at", None)
    output["next_path"] = (next_path(current["next_path"], headers.get("link"),
                                     api=transport.api) if current["paginated"] else None)
    if output["next_path"] and output["next_path"] == current["next_path"]:
        raise EndpointError("pagination_not_advancing")
    if kind in ACTION_TASKS:
        received = current.get("received_count", 0) + output["received_count"]
        expected = output["expected_count"]
        if current.get("expected_count", expected) != expected:
            output["warnings"].append("actions_total_count_changed")
        if received > expected or not output["next_path"] and received != expected:
            output["warnings"].append("actions_total_count_mismatch")
    return output


def _validate_pending_task(spec, run, current):
    """Validate persisted tasks before sending the App token to their endpoint."""
    kind = current["kind"]
    if not spec.options.github_inventory and kind not in {"app", "audit", "git_audit", "org_audit", "organizations", *CHECK_TASKS}:
        raise EndpointError("task_inventory_disabled")
    check_membership = run.check is not None and bool(run.enterprise) and kind == "organizations"
    if ((run.check is not None) != (kind in CHECK_TASKS - {"app"})
            and kind != "app" and not check_membership):
        raise EndpointError("task_not_part_of_this_run")
    if kind == "app":
        if current.get("org") or current.get("auth") != "app" or current["path"] != "/app" or current["paginated"]:
            raise EndpointError("task_app_endpoint_changed")
    elif kind in APP_JWT_TASKS:
        expected = "/app/installations" if kind == "app_installations" else f"/orgs/{current.get('org')}/installation"
        if (current.get("auth") != "app" or current["path"] != expected
                or (kind == "app_installations") == bool(current.get("org"))):
            raise EndpointError("task_installation_check_changed")
    elif kind not in {"inventory", "organizations", "audit", "org_audit", "git_audit"}:
        _validate_task(current, {"include_actions": spec.options.include_actions,
                                "run_window": _run_window(spec, run)})
    elif kind == "org_audit":
        if (not spec.options.include_audit_events or current.get("auth") != "org"
                or spec.options.audit_scope == "enterprise"
                or current["path"] != audit_path(current.get("org"), run.window)):
            raise EndpointError("task_audit_scope_changed")
    else:
        expected = {"inventory": f"/enterprises/{run.enterprise}/credentials/exports",
                    "organizations": f"/enterprises/{run.enterprise}/apps/installable_organizations",
                    "audit": audit_path(run.enterprise, run.window, enterprise=True),
                    "git_audit": audit_path(run.enterprise, _git_window(run.window), enterprise=True, include="git")}
        if (not run.enterprise or current.get("org") or current.get("auth") != "enterprise"
                or current["path"] != expected[kind]
                or kind == "inventory" and not spec.options.github_inventory
                or kind == "organizations" and spec.options.enterprise_only and run.check is None
                or kind in ("audit", "git_audit") and spec.options.audit_scope == "organization"
                or kind == "audit" and not spec.options.include_audit_events
                or kind == "git_audit" and not (spec.options.include_audit_events and spec.options.include_provider_hashes)):
            raise EndpointError("task_enterprise_endpoint_changed")
    if current.get("org") and current["org"].casefold() not in run.authorized_orgs:
        raise EndpointError("task_organization_out_of_scope")
    if (kind == "app_installations" and run.check is not None
            and not {org.casefold() for org in run.check["orgs"]} <= run.authorized_orgs):
        raise EndpointError("task_organization_out_of_scope")
    if current.get("enterprise", "") != run.enterprise:
        raise EndpointError("task_enterprise_out_of_scope")
    expected = urlsplit(first_path(current["path"], paginated=current["paginated"], page_size=spec.options.page_size))
    candidate = urlsplit(current["next_path"])
    if candidate.scheme or candidate.netloc or candidate.fragment or candidate.path != expected.path:
        raise EndpointError("task_pagination_endpoint_changed")
    original = parse_qs(expected.query, keep_blank_values=True, max_num_fields=20)
    following = parse_qs(candidate.query, keep_blank_values=True, max_num_fields=20)
    cursors = {"page", "after", "before"}
    if (set(following) - set(original) - cursors
            or any(len(value) != 1 for value in following.values())
            or any(following.get(key) != value for key, value in original.items() if key not in cursors)):
        raise EndpointError("task_pagination_scope_changed")


def _task_report(spec, run, current, *, generated_at=None):
    status = {"complete": "COMPLETE", "failed": "FAILED",
              "covered_by_enterprise": "NOT_REQUESTED"}[current["status"]]
    if status == "COMPLETE" and current.get("warnings"):
        status = "PARTIAL"
    result = report(
        spec, _scope_for(spec, current), "github." + current["kind"],
        status=status, reasons=[current["error"].upper()] if current.get("error") else [],
        pages=current["pages"], received=current.get("received_count", current["count"]), saved=current["count"],
        # Every report of an installation check run says so; the roster keys on it.
        resource_id=current["path"], mode="installation_check" if run.check is not None else spec.options.mode,
        purpose=("usage" if current["kind"] in ("audit", "org_audit", "git_audit") else "vault_metadata"
                 if current["kind"] in ACTION_TASKS - {"repo_environments"} else "issuer_inventory"),
        facts={"kind": current["kind"], "scope": current.get("org") or run.enterprise,
               "path": current["path"], "warnings": current.get("warnings") or None,
               "generated_at": generated_at or run.generated_at,
               "stage": current.get("export", {}).get("stage"),
               "row_index": current.get("export", {}).get("rows"),
               "window_start": (_git_window(run.window)[0] if current["kind"] == "git_audit"
                                else run.window[0] if current["kind"] in ("audit", "org_audit") else None),
               # The organizations a listing was checking: only they can be found absent from it.
               "organization": run.check["orgs"] if current["kind"] == "app_installations" else None,
               "selection": "one page is evidence, not a fully scanned organization"})
    result.expected_records = current.get("expected_count")
    return result


def native_snapshots(records):
    """The two programs' own JSON views, rebuilt from committed records."""
    from .snapshot import native_snapshots as build

    return build(records)


__all__ = ["collect_pages", "native_snapshots", "plan_recollection", "validate_machine_record",
           "validate_record", "validate_spec"]
