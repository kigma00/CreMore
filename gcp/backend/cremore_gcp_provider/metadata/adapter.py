"""GCP collection inside the shared lease, batch and checkpoint lifecycle.

One provider page is read outside any transaction, handed back with the cursor
that resumes after it, and committed by the worker together with that cursor. A
phase already recorded as done is never read again. Nothing here decides that a
credential is unused, revoked or unmanaged: an empty log window, a disabled API
and a refused read each keep their own reason.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
from copy import deepcopy
from datetime import UTC, datetime

from cremore.coverage.hasher import hash_value
from cremore.coverage.metadata_models import (
    MetadataConnectionSpec,
    MetadataPage,
    MetadataPayloadDigest,
    MetadataValueContract,
    checkpoint_json,
    in_metadata_scope,
)

from . import CONTRACT_VERSION, SOURCE_COMMIT, effective_access
from .collector import (
    API_KEY_NAME_RE,
    PROJECT_RE,
    REGION_RE,
    REGIONAL_SECRET_NAME_RE,
    SECRET_NAME_RE,
    SERVICES,
    VERSION_NAME_RE,
    Collector,
    resolved_error,
    secret_api_base,
)
from .normalization import observation, record_values, relation, report, value_match
from .relations import RelationshipCollector
from .snapshot import compare_records, native_snapshots
from .transport import DEFERRED, ApiError, Budget, Transport, adc_token
from .values import (
    MAX_SECRET_BYTES,
    read_api_key_string,
    read_secret_version,
    read_service_account_public_key,
)

ORIGIN = "https://googleapis.com"
_OBJECT_ID = {
    "principal": re.compile(
        r"^(?:serviceAccount:[^\s:]{3,320}"
        r"|gcp_principal:(?:serviceAccount|user):[^\s:]{3,320}"
        r"|iam_member:[A-Za-z0-9_./:@%~-]{1,320})$"
    ),
    "credential": re.compile(
        r"^(?:serviceAccountKey:[^\s:]{3,320}:[A-Za-z0-9_-]{1,128}|apiKey:[a-zA-Z0-9-]{1,128})$"
    ),
    "vault_item": re.compile(r"^secret:[a-z0-9-]{1,63}:[A-Za-z0-9_-]{1,255}$"),
    "vault_version": re.compile(
        r"^secretVersion:[a-z0-9-]{1,63}:[A-Za-z0-9_-]{1,255}/versions/[1-9][0-9]*$"
    ),
    "resource": re.compile(
        r"^(?:gcp_api:[a-z0-9][a-z0-9.-]{1,199}|[A-Za-z0-9_./:@%~-]{1,512})$"
    ),
}
# The order every run follows. A phase the connection's capabilities do not
# enable is reported as NOT_REQUESTED, never as an empty success.
PHASES = (
    "services",
    "service_accounts",
    "service_account_keys",
    "api_keys",
    "secret_manager",
    "secret_manager_locations",
    "secret_manager_regional",
    "secret_versions",
    "values",
    "relations_secret_access",
    "relations_activity",
    "relations_api_metrics",
    "relations_project_iam",
    "relations_secret_iam",
    "relations_key_creation",
    "relations_service_account_iam",
)
_VAULT_PHASES = {"secret_manager", "secret_manager_locations", "secret_manager_regional",
                 "secret_versions", "values"}


def validate_spec(spec):
    if spec.provider != "gcp" or spec.edition != "cloud":
        raise ValueError("GCP_EDITION_NOT_SUPPORTED")
    if spec.origin != ORIGIN:
        raise ValueError("GCP_ORIGIN_NOT_SUPPORTED")
    if spec.auth_type == "google_oauth":
        if set(spec.secret_refs) != {"client_id", "client_secret", "refresh_token"}:
            raise ValueError("GCP_OAUTH_REFERENCES_REQUIRED")
    elif spec.auth_type not in {"adc", "workload_identity"} or spec.secret_refs:
        raise ValueError("GCP_AMBIENT_CREDENTIALS_REQUIRED")
    if "inventory" not in spec.capabilities:
        raise ValueError("GCP_INVENTORY_CAPABILITY_REQUIRED")
    if set(spec.capabilities) - {"inventory", "vault_metadata", "relations", "vault_value",
                                 "issuer_value", "public_keys"}:
        raise ValueError("GCP_CAPABILITY_NOT_SUPPORTED")
    if spec.options.mode not in {"inventory", "discovery"} or spec.options.include_actions:
        raise ValueError("GCP_INVALID_COLLECTION_OPTION")
    if spec.principal_pin is not None:
        # The ADC identity is never read back during a run, so a pin cannot be
        # honoured without claiming a verification that did not happen.
        raise ValueError("GCP_PRINCIPAL_PIN_UNVERIFIABLE")
    if spec.options.include_audit_events:
        raise ValueError("GCP_AUDIT_EVENTS_NOT_SUPPORTED")
    if spec.options.mode == "discovery":
        from .discovery import validate_discovery_spec

        validate_discovery_spec(spec)
        return
    if len(spec.scopes) != 1 or spec.scopes[0].kind != "project":
        raise ValueError("GCP_SINGLE_PROJECT_SCOPE_REQUIRED")
    if not PROJECT_RE.fullmatch(spec.scopes[0].id):
        raise ValueError("GCP_INVALID_PROJECT")
    if any(not REGION_RE.fullmatch(name) or name == "global" for name in spec.options.locations):
        raise ValueError("GCP_INVALID_LOCATION")
    if (spec.options.locations or "vault_value" in spec.capabilities) and (
            "vault_metadata" not in spec.capabilities):
        raise ValueError("GCP_VAULT_CAPABILITY_REQUIRED")
    if spec.options.audit_lookback_days is not None and not (
            1 <= spec.options.audit_lookback_days <= 30):
        raise ValueError("GCP_INVALID_AUDIT_WINDOW")
    if set(spec.options.sources) - {"audit_logs", "api_metrics", "secret_iam", "service_account_iam", "effective_access"}:
        raise ValueError("GCP_SOURCE_NOT_SUPPORTED")
    if spec.options.sources and "relations" not in spec.capabilities:
        raise ValueError("GCP_RELATIONS_CAPABILITY_REQUIRED")
    if "secret_iam" in spec.options.sources and "vault_metadata" not in spec.capabilities:
        raise ValueError("GCP_SECRET_IAM_REQUIRES_VAULT_METADATA")


def _enabled(spec, phase):
    if phase == "values":
        return spec.options.include_values
    if phase in _VAULT_PHASES and "vault_metadata" not in spec.capabilities:
        return False
    if phase in {"secret_manager_locations", "secret_manager_regional"}:
        # Only operator-approved regions are read; with none, listing locations would only spend a permission.
        return bool(spec.options.locations)
    if phase.startswith("relations_"):
        if "relations" not in spec.capabilities:
            return False
        if phase == "relations_service_account_iam":
            return "service_account_iam" in spec.options.sources
        if phase in {"relations_secret_access", "relations_project_iam", "relations_secret_iam"} and (
                "vault_metadata" not in spec.capabilities):
            return False
        source = ("api_metrics" if phase == "relations_api_metrics" else "secret_iam"
                  if phase in {"relations_project_iam", "relations_secret_iam"} else "audit_logs")
        # An old relations connection selected all phases; keep its contract.
        return not spec.options.sources or source in spec.options.sources
    return True


def _purpose(phase):
    if phase.startswith("relations_"):
        return "usage"
    return "vault_metadata" if phase in _VAULT_PHASES else "issuer_inventory"


def _project_reference(project, name):
    """Normalise the project segment so a reference always names the scope."""
    parts = name.split("/")
    if len(parts) > 2 and parts[0] == "projects":
        parts[1] = project
    return "/".join(parts)


def validate_record(spec, item):
    try:
        validate_spec(spec)
    except ValueError:
        return False
    if spec.options.mode == "discovery":
        from .discovery import validate_discovery_record

        return validate_discovery_record(spec, item)
    if item.scope not in spec.scopes:
        return False
    if (item.provenance.contract_version != CONTRACT_VERSION
            or item.provenance.source_commit != SOURCE_COMMIT):
        return False
    operation = item.provenance.operation.removeprefix("gcp.")
    relation_phase = {
        "cloud_logging.secret_access": "relations_secret_access",
        "cloud_logging.service_account_activity": "relations_activity",
        "cloud_logging.key_creation": "relations_key_creation",
        "cloud_monitoring.api_request_count": "relations_api_metrics",
        "iam_allow_policy.project": "relations_project_iam",
        "iam_allow_policy.secret": "relations_secret_iam",
        "iam_allow_policy": "relations_secret_iam",
        "iam_allow_policy.service_account": "relations_service_account_iam",
    }.get(operation)
    if relation_phase and not _enabled(spec, relation_phase):
        return False
    project = spec.scopes[0].id
    for value in [getattr(item, name, None) for name in ("identity", "subject", "target")]:
        if value is None:
            continue
        if (value.provider, value.origin, value.tenant, value.tenant_confirmed) != (
                "gcp", spec.origin, spec.tenant, spec.tenant_confirmed):
            return False
        pattern = _OBJECT_ID.get(value.kind)
        if pattern is None or not pattern.fullmatch(value.object_id):
            return False
    if item.record_type == "entity_observation":
        vault = item.identity.kind in ("vault_item", "vault_version")
        if vault != (item.purpose == "vault_metadata"):
            return False
        if item.value_match is not None and not item.value_match.reference.startswith(
                f"projects/{project}/"):
            return False
    if item.record_type == "relation" and item.purpose != "usage":
        return False
    return in_metadata_scope(spec, item)


def validate_machine_record(spec, item):
    """An outside submission proves nothing about discovery, so it stays bounded.

    Only the connection's own project may appear, in the exact resource grammar
    the approved reads return. A traversal result is never accepted as scope.
    """
    if spec.options.mode == "discovery" or not validate_record(spec, item):
        return False
    project = spec.scopes[0].id
    resource = item.provenance.resource_id
    if not resource:
        return item.record_type == "operation_report"
    return resource.startswith((
        f"projects/{project}/", f"//iam.googleapis.com/projects/{project}/",
        "serviceruntime.googleapis.com/", f"projects/{project}#",
    ))


# -- run state ------------------------------------------------------------


def _config_hash(spec):
    from cremore.coverage.models import digest

    return digest(spec.model_dump())


def _derived(records):
    """Rebuild this run's work lists from the records already committed."""
    emails, secrets, api_keys, keys, account_ids, listed = [], [], [], {}, {}, {}
    for item in records:
        # A value read restates a listed object; the listing alone rebuilds the work lists.
        if item.get("record_type") != "entity_observation" or item.get("value_match"):
            continue
        values = record_values(item)
        name = values.get("resource_name")
        kind = item["identity"]["kind"]
        if kind == "principal" and values.get("service_account_email"):
            emails.append(values["service_account_email"])
            account_ids[values["service_account_email"]] = values.get("id")
        elif kind == "vault_item" and isinstance(name, str):
            secrets.append(name)
        elif kind == "vault_version" and isinstance(name, str):
            listed[name] = _listed_item(values)
        elif kind == "credential" and isinstance(name, str):
            if "/locations/global/keys/" in name:
                api_keys.append((values.get("uid") or "", name))
                listed[name] = _listed_item(values)
            elif values.get("service_account_email") and values.get("key_id"):
                keys[(values["service_account_email"], values["key_id"])] = name
    unique = (lambda seq: sorted(dict.fromkeys(seq)))
    return {"emails": unique(emails), "secrets": unique(secrets), "api_keys": unique(api_keys),
            "keys": keys, "account_ids": account_ids, "listed": listed}


def _listed_item(values):
    """The listed API key or secret version a committed observation recorded, as the collector built it."""
    name = values["resource_name"]
    if "/versions/" in name:
        return {"source": "gcp_secret_manager", "object_type": "vault_version",
                "credential_type": "secret_version", "project_id": values.get("project_id"),
                "source_id": name, "parent_secret": name.split("/versions/")[0], "state": values.get("state"),
                "created_at": values.get("created_at"), "destroyed_at": values.get("destroyed_at")}
    restrictions = values.get("restrictions") or {}
    return {"source": "gcp_api_keys", "object_type": "credential", "credential_type": "api_key",
            "project_id": values.get("project_id"), "source_id": name, "key_id": values.get("key_id"),
            "api_key_uid": values.get("uid"), "display_name": values.get("display_name"),
            "created_at": values.get("created_at"), "updated_at": values.get("updated_at"),
            "deleted_at": values.get("deleted_at"), "service_account_email": values.get("service_account_email"),
            "client_restriction_type": restrictions.get("type"), "api_target_count": restrictions.get("count"),
            "api_target_services": restrictions.get("service") or []}


def _inventory_index(project, secrets, emails, keys, api_keys):
    """The lookup tables the native relationship collector builds from items."""
    aliases, secret_map, seen = {project}, {}, {}
    for name in secrets:
        parts = name.split("/")
        if (SECRET_NAME_RE.fullmatch(name) or REGIONAL_SECRET_NAME_RE.fullmatch(name)) and parts[0] == "projects":
            aliases.add(parts[1])
            secret_map[name] = name
    missing = 0
    for uid, name in api_keys:
        if not uid or uid.lower() in seen:
            missing += 1
            continue
        seen[uid.lower()] = name
    return {"principals": {email: f"projects/{project}/serviceAccounts/{email}"
                           for email in emails},
            "keys": dict(keys), "api_keys": seen, "missing_api_uid": missing,
            "secrets": secret_map, "project_aliases": aliases}


class _Run:
    """Phase bookkeeping shared by collect_pages and its phase producers."""

    def __init__(self, spec, state, config_hash, now=None):
        self.spec = spec
        self.config_hash = config_hash
        self.project = spec.scopes[0].id
        self.scope = spec.scopes[0]
        self.done = list(state.get("done") or [])
        self.cursor = dict(state.get("cursor") or {})
        self.phase = state.get("phase") or PHASES[0]
        self.emitted = int(state.get("emitted", 0))
        self.requests = int(state.get("requests", 0))
        self.services = dict(state.get("services") or {})
        self.regions = list(state.get("regions") or [])
        self.reasons = set(state.get("reasons") or [])
        self.status = state.get("status", "COMPLETE")
        self.window_end = state.get("window_end") or (now or datetime.now(UTC)).isoformat()

    def checkpoint(self, *, phase=None, cursor=None):
        return checkpoint_json({
            "version": 1, "provider": "gcp", "config_hash": self.config_hash,
            "phase": phase or self.phase, "cursor": self.cursor if cursor is None else cursor,
            "done": sorted(self.done), "window_end": self.window_end,
            "emitted": self.emitted, "requests": self.requests, "services": self.services,
            "regions": self.regions, "reasons": sorted(self.reasons), "status": self.status,
        })

    def degrade(self, status, *reasons):
        self.reasons.update(code for code in reasons if code)
        if status == "FAILED" or self.status == "FAILED":
            self.status = "FAILED"
        elif status == "PARTIAL":
            self.status = "PARTIAL"

    def state(self, service):
        return self.services.get(service, {}).get("state", "unknown")

    def charge(self, records):
        if self.emitted + len(records) > self.spec.max_records:
            raise Budget("RECORD_BUDGET_EXCEEDED")
        self.emitted += len(records)


def _validated(spec, records):
    for item in records:
        if not validate_record(spec, item):
            raise ValueError("GCP_NORMALIZATION_FAILED")
    return records


def _counts(errors):
    return [{"code": code, "count": count} for code, count in sorted(errors.items())] or None


def _lazy_oauth_token(secrets):
    """One OAuth token source per run, created on first use.

    Creating it lazily keeps a broken stored authorization inside the caller's
    GcpAuthError handling, so discovery reports a FAILED page exactly like the
    inventory path instead of raising before its first request.
    """
    source = None

    def read():
        nonlocal source
        if source is None:
            from cremore_gcp_provider.oauth import oauth_token
            source = oauth_token(secrets)
        return source()

    return read


def collect_pages(spec, *, secrets, checkpoint, check, read_records=None, value_context=None,
                  transport=None, client=None, token=None, now=None):
    """Yield one provider page and the cursor that resumes after it."""
    if not isinstance(spec, MetadataConnectionSpec):
        spec = MetadataConnectionSpec.model_validate(spec)
    validate_spec(spec)
    if secrets and spec.auth_type != "google_oauth":
        raise ValueError("GCP_AMBIENT_CREDENTIALS_REQUIRED")
    if spec.options.mode == "discovery":
        from .discovery import collect_discovery_pages

        if spec.auth_type == "google_oauth" and token is None and transport is None:
            # Integration fix (refactoring + gcp-dashboard-oauth): discovery was added
            # after the OAuth branch split off and only knew the worker's ADC, so an
            # OAuth connection listed folders and projects as the worker, not the user
            # who authorized it. Hand discovery the user's token instead.
            token = _lazy_oauth_token(secrets)
        yield from collect_discovery_pages(
            spec, checkpoint=checkpoint, check=check, read_records=read_records,
            transport=transport, client=client, token=token,
        )
        return
    state = deepcopy(checkpoint or {})
    config_hash = _config_hash(spec)
    if state and (state.get("provider") != "gcp" or state.get("version") != 1
                  or state.get("config_hash") != config_hash):
        raise ValueError("GCP_CHECKPOINT_MISMATCH")
    if state and read_records is None:
        raise ValueError("GCP_RECORD_REPLAY_REQUIRED")
    if spec.options.include_values and value_context is None:
        raise ValueError("GCP_VALUE_CONTEXT_REQUIRED")
    run = _Run(spec, state, config_hash, now)
    derived = _derived(read_records()) if read_records is not None else _derived([])

    if run.phase == "done":
        yield MetadataPage(checkpoint=run.checkpoint(phase="done"), status=run.status,
                           reasons=sorted(run.reasons))
        return

    own_client = client is None and transport is None
    spent = run.requests
    try:
        from cremore_gcp_provider.gcp_auth import GcpAuthError
        if run.requests >= spec.max_requests:
            raise Budget("REQUEST_BUDGET_EXCEEDED")
        if transport is None:
            import httpx
            client = client or httpx.Client(timeout=spec.options.timeout_seconds, follow_redirects=False)
            if spec.auth_type == "google_oauth":
                from cremore_gcp_provider.oauth import oauth_token
                token_source = token or oauth_token(secrets)
            else:
                token_source = token or adc_token()
            check()
            token_source()  # Fail once with an actionable ADC code before listing sources.
            transport = Transport(client, token_source, options=spec.options,
                                  max_requests=max(0, spec.max_requests - run.requests), check=check)
        collector = Collector(run.project, transport, max_pages=spec.max_pages,
                              page_size=spec.options.page_size)
        try:
            yield from _phases(spec, run, collector, transport, derived,
                               datetime.fromisoformat(run.window_end), value_context)
        finally:
            run.requests = spent + transport.requests
    except GcpAuthError as exc:
        from cremore_gcp_provider.gcp_auth import TRANSIENT_AUTH_CODES

        if exc.code in TRANSIENT_AUTH_CODES:
            # Google's token service asked to retry (429, 5xx, unreachable): wait and resume this run
            # from its checkpoint like a throttled API read. Reauthorization codes still end the run.
            yield MetadataPage(checkpoint=run.checkpoint(), status="WAITING", reasons=[exc.code],
                               retry_after_seconds=max(1, min(3600, math.ceil(exc.retry_after or 60))))
            return
        yield MetadataPage(checkpoint=run.checkpoint(), status="FAILED", reasons=[exc.code])
    except Budget as exc:
        run.degrade("PARTIAL", exc.code)
        yield MetadataPage(checkpoint=run.checkpoint(), status=run.status,
                           reasons=sorted(run.reasons))
    except ApiError as exc:
        if exc.code in DEFERRED:
            yield MetadataPage(
                checkpoint=run.checkpoint(), status="WAITING", reasons=[exc.code.upper()],
                retry_after_seconds=max(1, min(3600, math.ceil(exc.retry_after or 60))))
            return
        run.degrade("FAILED", exc.code.upper())
        yield MetadataPage(checkpoint=run.checkpoint(), status=run.status,
                           reasons=sorted(run.reasons))
    finally:
        if own_client and client is not None:
            client.close()


def _phases(spec, run, collector, transport, derived, end, value_context):
    # The request total spans restarts: this run's transport starts at zero but
    # the budget it was given already excluded what earlier attempts spent.
    spent = run.requests
    context = {
        "spec": spec, "run": run, "collector": collector, "transport": transport,
        "scope": run.scope, "project": run.project, "emails": list(derived["emails"]),
        "secrets": list(derived["secrets"]), "listed": dict(derived["listed"]),
        "api_keys": list(derived["api_keys"]), "keys": dict(derived["keys"]), "end": end,
        "value_context": value_context, "account_ids": dict(derived["account_ids"]),
    }
    start = PHASES.index(run.phase) if run.phase in PHASES else 0
    for phase in PHASES[start:]:
        if phase in run.done:
            continue
        run.phase = phase
        cursor = deepcopy(run.cursor) if run.cursor.get("phase") == phase else {}
        if not _enabled(spec, phase):
            # A source that was not requested is reported under the purpose
            # the connection holds; claiming the purpose it would have had
            # would put the report outside the approved capabilities.
            records = _validated(spec, [report(
                spec, run.scope, "gcp." + phase, status="NOT_REQUESTED",
                reasons=["NOT_REQUESTED_BY_CONFIGURATION"], shape="empty",
                facts={"selection": _purpose(phase)})])
            run.charge(records)
            run.done.append(phase)
            yield MetadataPage(records=records, checkpoint=run.checkpoint(phase=phase))
            continue
        for records, next_cursor in _PRODUCERS[phase](context, cursor):
            _validated(spec, records)
            run.charge(records)
            run.requests = spent + transport.requests
            if next_cursor:
                # A copy: the producer keeps counting into its own dicts, and a later deferral must save this point.
                run.cursor = deepcopy({**next_cursor, "phase": phase})
                yield MetadataPage(records=records,
                                   checkpoint=run.checkpoint(phase=phase, cursor=run.cursor))
            else:
                run.done.append(phase)
                run.cursor = {}
                yield MetadataPage(records=records, checkpoint=run.checkpoint(phase=phase))
    run.phase = "done"
    yield MetadataPage(checkpoint=run.checkpoint(phase="done"), status=run.status,
                       reasons=sorted(run.reasons))


# -- paged list driver -----------------------------------------------------


def _service_for(phase):
    if phase.startswith("secret"):
        return "secretmanager.googleapis.com"
    return "apikeys.googleapis.com" if phase == "api_keys" else "iam.googleapis.com"


def _paged(context, cursor, *, phase, url, field_name, project_items, page_size=None,
           extra_params=None, purpose="issuer_inventory", operation=None, resource_id="",
           extra_cursor=None):
    """Drive one paged list: rows per page, one operation report when it ends."""
    spec, run, scope = context["spec"], context["run"], context["scope"]
    totals = dict(cursor.get("totals") or {"pages": 0, "received": 0, "saved": 0, "invalid": 0})
    for page in context["collector"].pages(url, field_name, cursor=cursor.get("page"),
                                           page_size=page_size, extra_params=extra_params):
        items, invalid = project_items(page.rows)
        totals.update(pages=page.pages, received=totals["received"] + page.received,
                      saved=totals["saved"] + len(items), invalid=totals["invalid"] + invalid)
        records = [observation(spec, scope, item) for item in items]
        if page.status == "running":
            yield records, {**(extra_cursor or {}), "page": page.cursor, "totals": totals}
            continue
        code = resolved_error(page.error, run.state(_service_for(phase)))
        status = "COMPLETE" if page.status == "complete" and not totals["invalid"] else "PARTIAL"
        reasons = [code.upper()] if code else (["INVALID_IDENTIFIERS"] if totals["invalid"] else [])
        if status != "COMPLETE":
            run.degrade("PARTIAL", *reasons)
        records.append(report(
            spec, scope, operation or ("gcp." + phase), purpose=purpose, status=status,
            reasons=reasons, pages=totals["pages"], received=totals["received"],
            saved=totals["saved"], shape="array", resource_id=resource_id,
            facts={"pages_read": totals["pages"], "objects_seen": totals["received"],
                   "invalid_identifiers": totals["invalid"] or None, "error_code": code}))
        yield records, None
        return


# -- phase producers -------------------------------------------------------


def _phase_services(context, cursor):
    spec, run, scope = context["spec"], context["run"], context["scope"]
    run.services = {service: context["collector"].service_state(service) for service in SERVICES}
    rows = [{"service": name, "state": value["state"], "error_code": value["error_code"]}
            for name, value in sorted(run.services.items())]
    # A disabled service is not an empty project: a list endpoint may still answer, so
    # the state is recorded here only. A list it breaks reports its own reason.
    yield [report(spec, scope, "gcp.service_usage", status="COMPLETE", pages=1, received=len(rows),
                  saved=len(rows), shape="object",
                  facts={"api_states": rows, "selection": "iam apikeys secretmanager"})], None


def _phase_service_accounts(context, cursor):
    def project_items(rows):
        items, invalid = context["collector"].service_accounts(rows)
        context["emails"].extend(item["service_account_email"] for item in items)
        context["account_ids"].update({item["service_account_email"]: item.get("unique_id") for item in items})
        return items, invalid

    yield from _paged(
        context, cursor, phase="service_accounts", project_items=project_items,
        url=f"https://iam.googleapis.com/v1/projects/{context['project']}/serviceAccounts",
        field_name="accounts")


def _phase_service_account_keys(context, cursor):
    spec, run, scope = context["spec"], context["run"], context["scope"]
    targets = sorted(dict.fromkeys(context["emails"]))
    index = int(cursor.get("index", 0))
    totals = dict(cursor.get("totals") or {"checked": 0, "saved": 0})
    errors = dict(cursor.get("errors") or {})
    public = "public_keys" in spec.capabilities
    relations = "relations" in spec.capabilities
    troubleshoot = "effective_access" in spec.options.sources
    while index < len(targets):
        email = targets[index]
        index += 1
        records = []
        try:
            items, key_errors = context["collector"].service_account_keys(email, account_id=context["account_ids"].get(email))
            totals["checked"] += 1
        except ApiError as exc:
            if exc.code in DEFERRED:
                raise
            code = resolved_error(exc.code, run.state("iam.googleapis.com"))
            errors[code] = errors.get(code, 0) + 1
            items, key_errors = [], {}
        for code, count in key_errors.items():
            errors[code] = errors.get(code, 0) + count
        # A key acts with its account's access: what the troubleshooter allows the account rides on each user-managed
        # key. At most MAX_PRINCIPALS accounts are asked a collection, and none after an account whose every call failed
        # (the API off, a refused caller, a blocked host); the rest stay unevaluated and are counted.
        managed = [item for item in items if item.get("credential_type") == "service_account_user_managed_key"]
        if troubleshoot and managed:
            if totals.get("asked", 0) < effective_access.MAX_PRINCIPALS and not totals.get("halted"):
                totals["asked"] = totals.get("asked", 0) + 1
                answers, troubles = effective_access.evaluate(context["transport"], context["project"], email)
                for code, count in troubles.items():
                    errors["troubleshooter_" + code] = errors.get("troubleshooter_" + code, 0) + count
                states = totals.setdefault("answers", {})
                for answer in answers:
                    states[answer["state"]] = states.get(answer["state"], 0) + 1
                answered = any(answer["state"] != "not_evaluated" for answer in answers)
                totals["evaluated" if answered else "unevaluated"] = totals.get(
                    "evaluated" if answered else "unevaluated", 0) + 1
                if not answered:
                    totals["halted"] = max(sorted(troubles), key=troubles.get)
                for item in managed:
                    item["effective_access"] = answers
            else:
                totals["unevaluated"] = totals.get("unevaluated", 0) + 1
        for item in items:
            if public:
                try:
                    item["public_key"] = read_service_account_public_key(
                        context["transport"], item["source_id"])
                except ApiError as exc:
                    if exc.code in DEFERRED:
                        raise
                    errors[exc.code] = errors.get(exc.code, 0) + 1
            context["keys"][(email, item["key_id"])] = item["source_id"]
            records.append(observation(spec, scope, item))
            if relations:
                records.append(relation(spec, scope, {
                    "source_id": f"projects/{context['project']}/serviceAccounts/{email}",
                    "target_id": item["source_id"], "relation": "service_account_owns_key",
                    "evidence_class": "provider_listing",
                    "evidence_source": "iam_service_account_keys",
                    "evidence_id": item["source_id"], "coverage_path": "service_account_keys",
                    "first_observed_at": None, "last_observed_at": None,
                }))
        totals["saved"] += len(items)
        last = index >= len(targets)
        if last:
            records.append(_key_report(spec, scope, run, totals, errors, len(targets)))
        yield records, None if last else {"index": index, "totals": totals, "errors": errors}
    if not targets:
        yield [_key_report(spec, scope, run, totals, errors, 0)], None


def _key_report(spec, scope, run, totals, errors, seen):
    selection = "all service account key types"
    if "effective_access" in spec.options.sources:
        # What the troubleshooter evaluated is enrichment: an account past the limit leaves the listing complete.
        halted = totals.get("halted")
        selection += (f"; effective access answered for {totals.get('evaluated', 0)} accounts with user-managed keys"
                      f", {totals.get('unevaluated', 0)} not evaluated (limit {effective_access.MAX_PRINCIPALS}"
                      + (f"; stopped after {halted}" if halted else "") + ")")
    troubles = {code: count for code, count in errors.items() if code.startswith("troubleshooter_")}
    listing = {code: count for code, count in errors.items() if code not in troubles}
    status = "COMPLETE" if not listing and totals["checked"] == seen else "PARTIAL"
    reasons = sorted({code.upper() for code in listing})
    if status != "COMPLETE":
        run.degrade("PARTIAL", *(reasons or ["SERVICE_ACCOUNT_KEYS_INCOMPLETE"]))
    return report(spec, scope, "gcp.service_account_keys", status=status, reasons=reasons,
                  received=totals["checked"], saved=totals["saved"], shape="array",
                  facts={"accounts_checked": totals["checked"], "accounts_seen": seen,
                         "selection": selection, "error_counts": _counts(errors),
                         # How Google answered each permission asked: can_access, cannot_access, unknown_info, ...
                         "effective_access": _counts(totals.get("answers") or {})})


def _phase_api_keys(context, cursor):
    def project_items(rows):
        items, invalid = context["collector"].api_keys(rows)
        context["api_keys"].extend((item.get("api_key_uid") or "", item["source_id"]) for item in items)
        context["listed"].update((item["source_id"], item) for item in items)
        return items, invalid

    yield from _paged(
        context, cursor, phase="api_keys", project_items=project_items,
        url=f"https://apikeys.googleapis.com/v2/projects/{context['project']}"
            "/locations/global/keys",
        field_name="keys",
        extra_params={"showDeleted": "true"} if context["spec"].options.include_deleted else None)


def _phase_secret_manager(context, cursor):
    def project_items(rows):
        items, invalid = context["collector"].secrets(rows)
        context["secrets"].extend(item["source_id"] for item in items)
        return items, invalid

    yield from _paged(
        context, cursor, phase="secret_manager", project_items=project_items, page_size=250,
        url=f"https://secretmanager.googleapis.com/v1/projects/{context['project']}/secrets",
        field_name="secrets", purpose="vault_metadata")


def _phase_secret_manager_locations(context, cursor):
    spec, run, scope = context["spec"], context["run"], context["scope"]
    totals = dict(cursor.get("totals") or {"pages": 0, "received": 0, "invalid": 0})
    found = list(cursor.get("found") or [])
    for page in context["collector"].pages(
        f"https://secretmanager.googleapis.com/v1/projects/{context['project']}/locations",
        "locations", cursor=cursor.get("page"), page_size=250,
    ):
        names, invalid = context["collector"].regions(page.rows)
        found.extend(names)
        totals.update(pages=page.pages, received=totals["received"] + page.received,
                      invalid=totals["invalid"] + invalid)
        if page.status == "running":
            yield [], {"page": page.cursor, "totals": totals,
                       "found": sorted(dict.fromkeys(found))}
            continue
        # Only locations the operator approved are read. The rest are counted
        # so the report never implies a sweep of every supported region.
        found = sorted(dict.fromkeys(found))
        run.regions = [name for name in found if name in spec.options.locations]
        missing = sorted(set(spec.options.locations) - set(found))
        code = resolved_error(page.error, run.state("secretmanager.googleapis.com"))
        reasons = ([code.upper()] if code else []) + (
            ["REQUESTED_LOCATION_NOT_SUPPORTED"] if missing else []) + (
            ["INVALID_IDENTIFIERS"] if totals["invalid"] else [])
        status = "COMPLETE" if page.status == "complete" and not reasons else "PARTIAL"
        if status != "COMPLETE":
            run.degrade("PARTIAL", *reasons)
        yield [report(spec, scope, "gcp.secret_manager_locations", purpose="vault_metadata",
                      status=status, reasons=reasons, pages=totals["pages"],
                      received=totals["received"], saved=len(run.regions), shape="array",
                      facts={"locations_seen": len(found), "locations_checked": len(run.regions),
                             "invalid_identifiers": totals["invalid"] or None, "error_code": code,
                             "selection": "operator approved locations"})], None
        return


def _each_target(context, cursor, targets, page_factory, *, carry=None):
    """Run one paged list per target, resuming at the target and page recorded."""
    index = int(cursor.get("index", 0))
    inner = cursor
    while index < len(targets):
        last_target = index == len(targets) - 1
        for records, next_cursor in page_factory(targets[index], inner, last_target):
            if next_cursor is not None:
                yield records, {**next_cursor, "index": index}
            elif last_target:
                yield records, None
                return
            else:
                yield records, {**(carry or {}), "index": index + 1}
        index += 1
        inner = {}


def _phase_secret_manager_regional(context, cursor):
    spec, run, scope = context["spec"], context["run"], context["scope"]
    targets = list(run.regions)
    if not targets:
        yield [report(spec, scope, "gcp.secret_manager_regional", purpose="vault_metadata",
                      status="COMPLETE", saved=0, shape="empty",
                      facts={"locations_checked": 0,
                             "selection": "operator approved locations"})], None
        return

    def factory(region, inner, _last):
        base = f"https://secretmanager.{region}.rep.googleapis.com/v1"
        return _paged(
            context, inner, phase="secret_manager_regional", page_size=250,
            url=f"{base}/projects/{context['project']}/locations/{region}/secrets",
            field_name="secrets", purpose="vault_metadata",
            operation="gcp.secret_manager_regional." + region, resource_id=region,
            project_items=lambda rows, region=region: _regional_items(context, rows, region))

    yield from _each_target(context, cursor, targets, factory)


def _regional_items(context, rows, region):
    items, invalid = context["collector"].secrets(rows, region=region)
    context["secrets"].extend(item["source_id"] for item in items)
    return items, invalid


def _phase_secret_versions(context, cursor):
    spec, scope = context["spec"], context["scope"]
    targets = sorted(dict.fromkeys(context["secrets"]))
    if not targets:
        yield [report(spec, scope, "gcp.secret_versions", purpose="vault_metadata",
                      status="COMPLETE", saved=0, shape="empty",
                      facts={"objects_seen": 0})], None
        return

    def factory(secret, inner, _last):
        if not context["collector"].project_resource(secret):
            context["run"].degrade("PARTIAL", "PROJECT_SCOPE_UNVERIFIED")
            yield [report(spec, scope, "gcp.secret_versions", purpose="vault_metadata",
                          status="PARTIAL", reasons=["PROJECT_SCOPE_UNVERIFIED"], shape="empty")], None
            return
        yield from _paged(
            context, inner, phase="secret_versions", page_size=250,
            url=f"{secret_api_base(secret)}/{secret}/versions", field_name="versions",
            purpose="vault_metadata", operation="gcp.secret_versions", resource_id=secret,
            project_items=lambda rows, secret=secret: _version_items(context, rows, secret))

    yield from _each_target(context, cursor, targets, factory)


def _version_items(context, rows, secret):
    items, invalid = context["collector"].versions(rows, secret)
    context["listed"].update((item["source_id"], item) for item in items)
    return items, invalid


# -- value reads -----------------------------------------------------------


# The HTTP refusals a deleted key's read can come back with (the transport's codes); nothing else is excused.
_DELETED_KEY_REFUSALS = frozenset({"http_400", "http_404"})


def _value_targets(spec, context):
    targets = []
    if "issuer_value" in spec.capabilities:
        targets.extend(("api_key", name) for _uid, name in sorted(context["api_keys"])
                       if API_KEY_NAME_RE.fullmatch(name))
    if "vault_value" in spec.capabilities:
        # A disabled or destroyed version has no accessible payload. Asking
        # for one would spend a request and return a denial that reads like
        # a missing permission.
        targets.extend(("secret_version", name) for name, item in sorted(context["listed"].items())
                       if item.get("credential_type") == "secret_version" and item.get("state") == "ENABLED"
                       and VERSION_NAME_RE.fullmatch(name))
    return targets


def _phase_values(context, cursor):
    """Read values in memory; commit only matching evidence and a private payload HMAC."""
    spec, run, scope = context["spec"], context["run"], context["scope"]
    project, holder = context["project"], context["value_context"]
    targets = _value_targets(spec, context)
    index = int(cursor.get("index", 0))
    totals = dict(cursor.get("totals") or {"read": 0, "matched": 0})
    errors = dict(cursor.get("errors") or {})
    while index < len(targets):
        kind, name = targets[index]
        index += 1
        reference = _project_reference(project, name)
        # The read is recorded on the listed object itself: the later observation becomes
        # the entity's current one, so it must keep the listing's name, dates and state.
        item = context["listed"][name]
        version = name.rsplit("/", 1)[-1] if kind == "secret_version" else ""
        # Google does not document whether a deleted key's string (restorable for 30 days) can still be read: one it
        # reads is compared as any other; only Google refusing that resource (400/404) is the key's own fact rather
        # than a gap. A malformed answer, a permission problem or an unverified scope stays a gap.
        deleted = kind == "api_key" and bool(item.get("deleted_at"))
        records = []
        bound = context["collector"].project_resource(name)
        try:
            if not bound:
                raise ApiError("project_scope_unverified")
            if kind == "api_key":
                data = read_api_key_string(context["transport"], name).encode()
            else:
                data = read_secret_version(context["transport"], name)
            totals["read"] += 1
            rows = hash_value(context["value_context"]["engine"], data, {"reference": reference},
                              max_bytes=MAX_SECRET_BYTES)
            payload_digest = MetadataPayloadDigest(
                scheme="cremore-gcp-payload-v1/hmac-sha256", key_id=holder["key_id"],
                fingerprint=hmac.new(holder["engine"].config.fingerprint_key,
                                     b"cremore/gcp-payload/v1\x00" + data, hashlib.sha256).hexdigest())
            del data
            if len(rows) > 25:
                errors["value_match_limit_reached"] = errors.get("value_match_limit_reached", 0) + 1
            for row in rows[:25]:
                records.append(observation(spec, scope, item, value_match=value_match(
                    holder, reference, version=version,
                    version_state="UNKNOWN" if kind == "secret_version" else "CURRENT",
                    observation_row=row), payload_digest=payload_digest))
            totals["matched"] += sum(1 for row in rows[:25] if row.evidence == "VALUE")
        except ApiError as exc:
            if exc.code in DEFERRED:
                raise
            if deleted and bound and exc.code in _DELETED_KEY_REFUSALS:
                totals["deleted_unread"] = totals.get("deleted_unread", 0) + 1
            else:
                errors[exc.code] = errors.get(exc.code, 0) + 1
            if bound:
                records.append(observation(spec, scope, item, value_match=value_match(
                    holder, reference, version=version, reason=exc.code.upper())))
        last = index >= len(targets)
        if last:
            records.append(_value_report(spec, scope, run, holder, totals, errors, len(targets)))
        yield records, None if last else {"index": index, "totals": totals, "errors": errors}
    if not targets:
        yield [_value_report(spec, scope, run, holder, totals, errors, 0)], None


def _value_report(spec, scope, run, holder, totals, errors, seen):
    # A deleted key Google would not hand out is not expected to be read (its reason stays on that key's record).
    expected = seen - totals.get("deleted_unread", 0)
    access = ("COMPLETE" if totals["read"] == expected and not errors
              else "FAILED" if not totals["read"] and errors else "PARTIAL")
    reasons = sorted({code.upper() for code in errors})
    if access != "COMPLETE":
        run.degrade("PARTIAL", *(reasons or ["VALUE_ACCESS_INCOMPLETE"]))
    return report(
        spec, scope, "gcp.value_access",
        purpose="vault_metadata" if "vault_value" in spec.capabilities else "issuer_inventory",
        status="COMPLETE" if access == "COMPLETE" else "PARTIAL", reasons=reasons, received=seen,
        saved=totals["read"], shape="array", value_access=access,
        value_contract=MetadataValueContract(key_id=holder["key_id"],
                                             engine_digest=holder["engine_digest"],
                                             policy_digest=holder["policy_digest"]),
        facts={"objects_seen": seen, "count": totals["matched"],
               "selection": "listed api keys and accessible secret versions",
               "error_counts": _counts({**errors, **({"deleted_api_key_unread": totals["deleted_unread"]}
                                                   if totals.get("deleted_unread") else {})})})


# -- relations -------------------------------------------------------------


def _relationship(context):
    spec, run = context["spec"], context["run"]
    selected_secrets = [name for name in dict.fromkeys(context["secrets"])
                       if (SECRET_NAME_RE.fullmatch(name) or REGIONAL_SECRET_NAME_RE.fullmatch(name))
                       and context["collector"].project_resource(name)]
    api_keys = [(uid, name) for uid, name in context["api_keys"] if context["collector"].project_resource(name)]
    if (any(not context["collector"].project_resource(name) for name in context["secrets"])
            or len(api_keys) != len(context["api_keys"])):
        run.degrade("PARTIAL", "PROJECT_SCOPE_UNVERIFIED")
    index = _inventory_index(context["project"], selected_secrets,
                             sorted(dict.fromkeys(context["emails"])), context["keys"],
                             api_keys)
    index["project_aliases"] = set(context["collector"].project_aliases)
    index["account_ids"] = context["account_ids"]
    return RelationshipCollector(
        context["project"], index, context["transport"], end=context["end"],
        lookback_hours=(spec.options.audit_lookback_days or 1) * 24, max_pages=spec.max_pages,
        max_edges=max(0, spec.max_records - run.emitted - 1))


def _relation_report(spec, scope, run, collector, operation, coverage_path, totals, *,
                     error=None, extra=None):
    issues = collector.issues
    status = "COMPLETE" if not issues and not error else "PARTIAL"
    reasons = sorted({code.upper() for code in issues} | ({error.upper()} if error else set()))
    if status != "COMPLETE":
        run.degrade("PARTIAL", *reasons)
    facts = {"coverage_path": coverage_path, "pages_read": totals.get("pages", 0),
             "objects_seen": totals.get("received", 0), "error_code": error,
             "selection": "observed access only; an empty window is unknown, not unused",
             "error_counts": _counts(issues), **(extra or {})}
    return report(spec, scope, operation, purpose="usage", status=status, reasons=reasons,
                  pages=totals.get("pages", 0), received=totals.get("received", 0),
                  saved=totals.get("saved", 0), shape="array",
                  window=(collector.start.isoformat(), collector.end.isoformat()), facts=facts)


def _log_phase(context, cursor, *, pages, operation, coverage_path):
    spec, run, scope = context["spec"], context["run"], context["scope"]
    collector = _relationship(context)
    collector.issues.update(cursor.get("issues") or {})
    totals = dict(cursor.get("totals") or {"pages": 0, "received": 0, "saved": 0})
    for page in pages(collector, cursor.get("page")):
        totals.update(pages=page.pages, received=totals["received"] + page.received,
                      saved=totals["saved"] + len(page.rows))
        records = [relation(spec, scope, edge) for edge in page.rows]
        if page.status == "running":
            yield records, {"page": page.cursor, "totals": totals, "issues": collector.issues}
            continue
        records.append(_relation_report(spec, scope, run, collector, operation, coverage_path,
                                        totals, error=page.error))
        yield records, None
        return


def _phase_relations_secret_access(context, cursor):
    yield from _log_phase(context, cursor,
                          pages=lambda c, cur: c.secret_access(cursor=cur),
                          operation="gcp.cloud_logging.secret_access",
                          coverage_path="secret_access_logs")


def _phase_relations_activity(context, cursor):
    yield from _log_phase(context, cursor,
                          pages=lambda c, cur: c.service_account_activity(cursor=cur),
                          operation="gcp.cloud_logging.service_account_activity",
                          coverage_path="service_account_activity_logs")


def _phase_relations_key_creation(context, cursor):
    yield from _log_phase(context, cursor, pages=lambda c, cur: c.key_creation(cursor=cur),
                          operation="gcp.cloud_logging.key_creation", coverage_path="key_creation_logs")


def _phase_relations_api_metrics(context, cursor):
    spec, run, scope = context["spec"], context["run"], context["scope"]
    collector = _relationship(context)
    collector.issues.update(cursor.get("issues") or {})
    targets = sorted(collector.api_keys.items())
    totals = dict(cursor.get("totals") or {"pages": 0, "received": 0, "saved": 0, "checked": 0})
    errors = dict(cursor.get("errors") or {})

    def finish():
        return _relation_report(
            spec, scope, run, collector, "gcp.cloud_monitoring.api_request_count",
            "api_key_usage_metrics", totals, error=next(iter(sorted(errors)), None),
            extra={"keys_checked": totals["checked"], "points_seen": totals["received"],
                   "series_seen": totals["saved"], "count": collector.missing_api_uid or None,
                   "selection": "no series means unknown, not unused",
                   "error_counts": _counts({**collector.issues, **errors})})

    if not targets:
        yield [finish()], None
        return

    def factory(target, inner, last):
        uid, source_id = target
        previous_pages = int((inner.get("page") or {}).get("page", 0))
        for page in collector.api_key_metrics(uid, source_id, cursor=inner.get("page")):
            totals.update(pages=totals["pages"] + page.pages - previous_pages,
                          received=totals["received"] + page.received,
                          saved=totals["saved"] + len(page.rows))
            previous_pages = page.pages
            records = [relation(spec, scope, edge) for edge in page.rows]
            if page.status == "running":
                yield records, {"page": page.cursor, "totals": totals,
                                "errors": errors, "issues": collector.issues}
                continue
            if page.error:
                errors[page.error] = errors.get(page.error, 0) + 1
            totals["checked"] += 1
            if last:
                records.append(finish())
            yield records, None
            return

    yield from _each_target(context, cursor, targets, factory,
                           carry={"totals": totals, "errors": errors, "issues": collector.issues})


def _phase_relations_project_iam(context, cursor):
    spec, run, scope = context["spec"], context["run"], context["scope"]
    collector = _relationship(context)
    try:
        edges, code = collector.project_policy(), None
    except ApiError as exc:
        if exc.code in DEFERRED:
            raise
        edges, code = [], exc.code
    records = [relation(spec, scope, edge) for edge in edges]
    records.append(_relation_report(spec, scope, run, collector, "gcp.iam_allow_policy.project",
                                    "project_iam_policy",
                                    {"pages": 1, "received": len(edges), "saved": len(edges)},
                                    error=code,
                                    extra={"selection": "roles including "
                                                        "secretmanager.versions.access"}))
    yield records, None


def _phase_relations_service_account_iam(context, cursor):
    spec, run, scope = context["spec"], context["run"], context["scope"]
    collector = _relationship(context)
    try:
        edges, code = collector.service_account_roles(), None
    except ApiError as exc:
        if exc.code in DEFERRED:
            raise
        edges, code = [], exc.code
    yield [*[relation(spec, scope, edge) for edge in edges],
           _relation_report(spec, scope, run, collector, "gcp.iam_allow_policy.service_account", "service_account_iam",
                            {"pages": 1, "received": len(edges), "saved": len(edges)}, error=code,
                            extra={"selection": "direct project allow bindings; inherited, deny and effective access not evaluated"})], None


def _phase_relations_secret_iam(context, cursor):
    spec, run, scope = context["spec"], context["run"], context["scope"]
    collector = _relationship(context)
    targets = sorted(collector.secrets.values())
    totals = dict(cursor.get("totals") or {"pages": 0, "received": 0, "saved": 0, "checked": 0})
    errors = dict(cursor.get("errors") or {})

    def finish():
        return _relation_report(
            spec, scope, run, collector, "gcp.iam_allow_policy.secret", "secret_iam_policies",
            totals, error=next(iter(sorted(errors)), None),
            extra={"count": totals["checked"], "objects_seen": len(targets),
                   "selection": "roles including secretmanager.versions.access",
                   "error_counts": _counts({**collector.issues, **errors})})

    if not targets:
        yield [finish()], None
        return
    index = int(cursor.get("index", 0))
    while index < len(targets):
        secret = targets[index]
        index += 1
        try:
            collector.max_edges = max(0, spec.max_records - run.emitted - 1)
            edges = collector.secret_policy(secret)
            totals["checked"] += 1
        except ApiError as exc:
            if exc.code in DEFERRED:
                raise
            errors[exc.code] = errors.get(exc.code, 0) + 1
            edges = []
        totals.update(pages=totals["pages"] + 1, received=totals["received"] + len(edges),
                      saved=totals["saved"] + len(edges))
        records = [relation(spec, scope, edge) for edge in edges]
        last = index >= len(targets)
        if last:
            records.append(finish())
        yield records, None if last else {"index": index, "totals": totals, "errors": errors}


_PRODUCERS = {
    "services": _phase_services,
    "service_accounts": _phase_service_accounts,
    "service_account_keys": _phase_service_account_keys,
    "api_keys": _phase_api_keys,
    "secret_manager": _phase_secret_manager,
    "secret_manager_locations": _phase_secret_manager_locations,
    "secret_manager_regional": _phase_secret_manager_regional,
    "secret_versions": _phase_secret_versions,
    "values": _phase_values,
    "relations_secret_access": _phase_relations_secret_access,
    "relations_activity": _phase_relations_activity,
    "relations_api_metrics": _phase_relations_api_metrics,
    "relations_project_iam": _phase_relations_project_iam,
    "relations_secret_iam": _phase_relations_secret_iam,
    "relations_key_creation": _phase_relations_key_creation,
    "relations_service_account_iam": _phase_relations_service_account_iam,
}


def link_service_account_key(records, candidate):
    """Identifier-only match for a discovered service-account JSON key.

    The caller keeps the candidate; only its client email and private key ID
    are read, and a match names the issued key, never a working credential.
    """
    from .linkage import match_service_account_key

    return match_service_account_key(native_snapshots(records)["inventory"], candidate)


def _compare_runs(before, after, *, spec, scope_id=None):
    """The native snapshot API receives current records before previous ones."""
    return compare_records(after, before, spec=spec)


__all__ = [
    "collect_pages", "compare_records", "link_service_account_key", "native_snapshots",
    "validate_machine_record", "validate_record", "validate_spec",
]
