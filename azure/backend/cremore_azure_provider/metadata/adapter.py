"""One vault, three listings, and an explicit account of what was not read.

Phases run in order and each one is checkpointed, so a run that is cancelled,
rate limited or restarted resumes where it stopped instead of re-reading. A
source the connection did not ask for is reported as NOT_REQUESTED rather than
left out, because a missing report and an empty one mean different things.
"""

from __future__ import annotations

import math
import re
from copy import deepcopy
from datetime import UTC, datetime

from cremore.coverage.metadata_models import (
    RECORD_ADAPTER,
    MetadataConnectionSpec,
    MetadataPage,
    MetadataScope,
)

from . import API_VERSION, CONTRACT_VERSION, SOURCE_COMMIT
from .normalization import (
    ROTATION_UNKNOWN,
    UPDATED_IS_NOT_ROTATION,
    object_id,
    observation,
    record_values,
    report,
    secret_name,
    version_id,
)
from .resources import SOURCES as RESOURCE_SOURCES
from .resources import collect_resources, resource_identity
from .transport import DEFERRED, ApiError, Budget, Transport, skip_token, vault_name

# In order. `versions` needs the names `secrets` found, so it never runs first.
PHASES = ("secrets", "versions", "deleted_secrets", "value_access", *RESOURCE_SOURCES, "public_certificates")
DEFAULT_SOURCES = ("secrets",)
SECRET_NAME = re.compile(r"[A-Za-z0-9-]{1,127}")
_OBJECT_ID = {
    "vault_item": re.compile(r"(?:secret|key|certificate):[A-Za-z][A-Za-z0-9-]{1,23}:[A-Za-z0-9-]{1,127}"),
    "vault_version": re.compile(
        r"(?:secret|key|certificate)Version:[A-Za-z][A-Za-z0-9-]{1,23}:[A-Za-z0-9-]{1,127}/versions/[A-Za-z0-9]{1,64}"
    ),
}


def validate_spec(spec):
    if spec.provider != "azure_key_vault" or spec.edition != "cloud":
        raise ValueError("AZURE_KEY_VAULT_EDITION_NOT_SUPPORTED")
    vault = vault_name(spec.origin)
    from cremore_azure_provider import app_certificate as certificate

    if not certificate.allowed(spec, public_cloud=spec.origin.endswith(".vault.azure.net")):
        # The worker's own Azure identity, or the app certificate CreMore made and renews itself.
        # A stored token would be a second copy of either, managed separately and expiring on its own.
        raise ValueError("AZURE_KEY_VAULT_AMBIENT_CREDENTIALS_REQUIRED")
    if "vault_metadata" not in spec.capabilities:
        raise ValueError("AZURE_KEY_VAULT_VAULT_CAPABILITY_REQUIRED")
    if set(spec.capabilities) - {"vault_metadata", "vault_value", "public_keys"}:
        # There is no issuer inventory, no audit and no relation source in the
        # Key Vault data plane; offering one would promise a collection that
        # cannot run.
        raise ValueError("AZURE_KEY_VAULT_CAPABILITY_NOT_SUPPORTED")
    if spec.options.mode != "inventory":
        raise ValueError("AZURE_KEY_VAULT_INVALID_COLLECTION_OPTION")
    if spec.principal_pin is not None:
        raise ValueError("AZURE_KEY_VAULT_PRINCIPAL_PIN_UNVERIFIABLE")
    if len(spec.scopes) != 1 or spec.scopes[0].kind != "vault":
        raise ValueError("AZURE_KEY_VAULT_SINGLE_VAULT_SCOPE_REQUIRED")
    if spec.scopes[0].id != vault:
        # The scope and the endpoint must name the same vault, or the records
        # would be filed under a vault they were not read from.
        raise ValueError("AZURE_KEY_VAULT_SCOPE_MUST_MATCH_ORIGIN")
    if set(spec.options.sources) - {"secrets", "versions", "deleted_secrets", *RESOURCE_SOURCES, "public_certificates"}:
        raise ValueError("AZURE_KEY_VAULT_SOURCE_NOT_SUPPORTED")
    selected = spec.options.sources or DEFAULT_SOURCES
    if ("versions" in selected or spec.options.include_values) and "secrets" not in selected:
        raise ValueError("AZURE_KEY_VAULT_SECRET_DISCOVERY_REQUIRED")
    if any(versions in selected and base not in selected for versions, base in (
            ("key_versions", "keys"), ("certificate_versions", "certificates"))):
        raise ValueError("AZURE_KEY_VAULT_RESOURCE_DISCOVERY_REQUIRED")
    if "public_certificates" in selected and ("certificates" not in selected or "public_keys" not in spec.capabilities):
        raise ValueError("AZURE_KEY_VAULT_PUBLIC_CERTIFICATES_REQUIRE_DISCOVERY_AND_PUBLIC_KEYS")


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
    if item.purpose != "vault_metadata":
        return False
    if item.provenance.operation == "azure.key_vault.public_certificates":
        from cremore_azure_provider.public_certificates import certificate_evidence

        if item.record_type == "entity_observation" and (
                "public_certificates" not in spec.options.sources or "public_keys" not in spec.capabilities
                or not certificate_evidence(item)):
            return False
    if item.record_type in ("relation", "provider_event"):
        return False
    vault = spec.scopes[0].id
    for value in [getattr(item, name, None) for name in ("identity", "subject", "target")]:
        if value is None:
            continue
        if (value.provider, value.origin, value.tenant, value.tenant_confirmed) != (
                "azure_key_vault", spec.origin, spec.tenant, spec.tenant_confirmed):
            return False
        pattern = _OBJECT_ID.get(value.kind)
        if pattern is None or not pattern.fullmatch(value.object_id):
            return False
        if value.object_id.split(":")[1] != vault:
            return False
    if item.record_type == "entity_observation" and item.value_match is not None:
        match = item.value_match
        resource = item.provenance.resource_id
        if (not spec.options.include_values or "vault_value" not in spec.capabilities
                or item.provenance.operation != "azure.key_vault.value_access"
                or not _listed_identifier(spec, {"id": resource})
                or match.reference != resource or match.version != version_id(resource)
                or item.normalized_state == "DELETED"):
            return False
    return not (item.record_type == "operation_report" and item.value_access != "NOT_REQUESTED"
            and (not spec.options.include_values or "vault_value" not in spec.capabilities
                or item.provenance.operation != "azure.key_vault.value_access"
                or item.value_contract is None))


def validate_machine_record(spec, item):
    """An outside submission proves nothing about discovery, so it stays bounded.

    Only this vault's own resource names may appear, in the grammar the
    approved reads return.
    """
    if not validate_record(spec, item):
        return False
    resource = item.provenance.resource_id
    if not resource:
        return item.record_type == "operation_report"
    parsed = resource_identity(spec, resource)
    if parsed:
        return (item.record_type == "entity_observation" and item.value_match is None
                and item.identity.object_id == parsed[3])
    if not _listed_identifier(spec, {"id": resource}):
        return False
    return (item.record_type != "entity_observation"
            or item.identity.object_id == object_id(spec.scopes[0].id, {"id": resource}))


def _enabled(spec, phase):
    if phase == "value_access":
        return spec.options.include_values
    return phase in (spec.options.sources or DEFAULT_SOURCES)


def _config_hash(spec):
    from cremore.coverage.models import digest

    return digest(spec.model_dump())


def _validate_checkpoint(spec, state):
    if not state:
        return
    if (state.get("phase") not in (*PHASES, "done")
            or not isinstance(state.get("done"), list)
            or any(phase not in PHASES for phase in state["done"])
            or state.get("status") not in {"COMPLETE", "PARTIAL", "FAILED"}
            or not isinstance(state.get("cursor"), dict)):
        raise ValueError("AZURE_KEY_VAULT_CHECKPOINT_MISMATCH")
    for name, maximum in (("requests", spec.max_requests), ("records", spec.max_records)):
        if type(state.get(name)) is not int or not 0 <= state[name] <= maximum:
            raise ValueError("AZURE_KEY_VAULT_CHECKPOINT_MISMATCH")
    cursor = state["cursor"]
    for name in ("pages", "received", "saved", "index", "read"):
        if name in cursor and (type(cursor[name]) is not int or not 0 <= cursor[name] <= 10_000_000):
            raise ValueError("AZURE_KEY_VAULT_CHECKPOINT_MISMATCH")
    if not isinstance(cursor.get("seen", []), list):
        raise ValueError("AZURE_KEY_VAULT_CHECKPOINT_MISMATCH")  # noqa: TRY004 -- invalid persisted value
    tokens = [cursor.get("skiptoken", ""), *cursor.get("seen", [])]
    if (len(tokens) > spec.max_pages + 1 or any(not isinstance(token, str) or len(token) > 4096
            or token and not re.fullmatch(r"[A-Za-z0-9._~%+/=-]+", token) for token in tokens)):
        raise ValueError("AZURE_KEY_VAULT_CHECKPOINT_MISMATCH")
    MetadataPage(checkpoint=state)


class _Run:
    """The part of a run that survives a restart."""

    def __init__(self, spec, state, config_hash):
        self.spec = spec
        self.config_hash = config_hash
        self.scope = MetadataScope(kind="vault", id=spec.scopes[0].id)
        self.vault = spec.scopes[0].id
        self.phase = state.get("phase") or PHASES[0]
        self.done = [value for value in state.get("done", []) if value in PHASES]
        self.cursor = dict(state.get("cursor") or {})
        self.requests = int(state.get("requests") or 0)
        self.records = int(state.get("records") or 0)
        self.status = state.get("status") or "COMPLETE"
        self.reasons = set(state.get("reasons") or [])

    def checkpoint(self, *, phase=None, cursor=None):
        return {"provider": "azure_key_vault", "version": 1, "config_hash": self.config_hash,
                "phase": phase or self.phase, "done": sorted(set(self.done)),
                "cursor": self.cursor if cursor is None else cursor,
                "requests": self.requests, "records": self.records,
                "status": self.status, "reasons": sorted(self.reasons)}

    def charge(self, records):
        if self.records + len(records) > self.spec.max_records:
            raise Budget("RECORD_BUDGET_EXCEEDED")
        self.records += len(records)

    def degrade(self, status, reason):
        order = {"COMPLETE": 0, "PARTIAL": 1, "FAILED": 2}
        if order[status] > order.get(self.status, 0):
            self.status = status
        self.reasons.add(reason)


def _validated(spec, records):
    for record in records:
        item = RECORD_ADAPTER.validate_python(record.model_dump())
        if not validate_record(spec, item) or not validate_machine_record(spec, item):
            raise ValueError("AZURE_KEY_VAULT_RECORD_REJECTED")
    return records


def _page(transport, path, cursor, *, origin):
    params = {"maxresults": min(25, transport.options.page_size)}
    if cursor.get("skiptoken"):
        params["$skiptoken"] = cursor["skiptoken"]
    payload = transport.get(path, params)
    rows = payload.get("value")
    if not isinstance(rows, list):
        raise ApiError("invalid_response")
    return rows, skip_token(payload.get("nextLink"), origin=origin, path=path)


def _listed_identifier(spec, row, *, name=None, base=False):
    if not isinstance(row, dict) or not isinstance(row.get("id"), str):
        return False
    match = re.fullmatch(re.escape(spec.origin) + r"/secrets/([A-Za-z0-9-]{1,127})(?:/([A-Za-z0-9]{1,64}))?", row["id"])
    return bool(match and (not base or match[2] is None)
                and (name is None or (match[1] == name and match[2])))


def _list(context, cursor, *, phase, path, operation, deleted=False, resource=""):
    """One listing, page by page, yielding (records, next cursor) per page."""
    spec, run, transport = context["spec"], context["run"], context["transport"]
    seen = set(cursor.get("seen") or [])
    pages = int(cursor.get("pages") or 0)
    received = int(cursor.get("received") or 0)
    saved = int(cursor.get("saved") or 0)
    token = cursor.get("skiptoken") or ""
    while True:
        rows, next_token = _page(transport, path, {"skiptoken": token}, origin=spec.origin)
        pages += 1
        received += len(rows)
        records = []
        for row in rows:
            if not _listed_identifier(spec, row, base=True):
                continue
            records.append(observation(spec, run.scope, run.vault, row,
                                       operation=operation, deleted=deleted))
            if phase == "secrets":
                context["names"].append(secret_name(row["id"]))
        saved += len(records)
        if next_token and next_token in seen:
            raise ApiError("invalid_response")
        if next_token:
            seen.add(next_token)
        if next_token and pages < spec.max_pages:
            yield records, {"skiptoken": next_token, "seen": sorted(seen), "pages": pages,
                            "received": received, "saved": saved}
            token = next_token
            continue
        reasons = [ROTATION_UNKNOWN, UPDATED_IS_NOT_ROTATION]
        status = "COMPLETE"
        if next_token:
            status, reasons = "PARTIAL", [*reasons, "PAGE_LIMIT_REACHED"]
        if received != saved:
            status, reasons = "PARTIAL", [*reasons, "INVALID_IDENTIFIERS"]
        yield [*records, report(spec, run.scope, operation, status=status, reasons=reasons,
                                pages=pages, received=received, saved=saved,
                                resource_id=resource)], {}
        return


def _secrets(context, cursor):
    yield from _list(context, cursor, phase="secrets", path="/secrets",
                     operation="azure.key_vault.secrets")


def _deleted_secrets(context, cursor):
    yield from _list(context, cursor, phase="deleted_secrets", path="/deletedsecrets",
                     operation="azure.key_vault.deleted_secrets", deleted=True)


def _complete_operation(records, scope, operation):
    reports = [item for item in records if item.get("record_type") == "operation_report"
               and item.get("scope") == scope and item.get("provenance", {}).get("operation") == operation]
    return bool(reports) and all(item.get("status") == "COMPLETE" for item in reports)


def _versions(context, cursor):
    """Every version of every secret the listing found.

    Versions are the only place a Key Vault secret records that a new value was
    actually set, so this is where a rotation claim could ever come from. The
    reading is left to whoever reads the records: this package stores the
    versions and their times, and asserts nothing about them.
    """
    spec, run, transport = context["spec"], context["run"], context["transport"]
    parent_complete = _complete_operation(context["records"], run.scope.model_dump(), "azure.key_vault.secrets")
    names = [name for name in context["names"] if SECRET_NAME.fullmatch(name)]
    start = int(cursor.get("index") or 0)
    pages = int(cursor.get("pages") or 0)
    received = int(cursor.get("received") or 0)
    saved = int(cursor.get("saved") or 0)
    if not names:
        # No secret was listed, so there is nothing whose versions to read. The
        # difference between that and "read and found none" is the reason.
        yield [report(spec, run.scope, "azure.key_vault.versions", status="COMPLETE" if parent_complete else "PARTIAL",
                      reasons=[ROTATION_UNKNOWN, "NO_SECRET_LISTED_TO_READ_VERSIONS_FOR",
                               *([] if parent_complete else ["PARENT_LISTING_INCOMPLETE"])],
                      pages=0, received=0, saved=0, shape="empty")], {}
        return
    for index in range(start, len(names)):
        name = names[index]
        token = cursor.get("skiptoken") if index == start else ""
        seen = set(cursor.get("seen") or []) if index == start else set()
        while True:
            rows, next_token = _page(transport, f"/secrets/{name}/versions",
                                     {"skiptoken": token or ""}, origin=spec.origin)
            pages += 1
            received += len(rows)
            records = [observation(spec, run.scope, run.vault, row,
                                   operation="azure.key_vault.versions")
                       for row in rows if _listed_identifier(spec, row, name=name)]
            saved += len(records)
            if next_token and next_token in seen:
                raise ApiError("invalid_response")
            if next_token:
                seen.add(next_token)
            more = bool(next_token) and pages < spec.max_pages
            if more:
                yield records, {"index": index, "skiptoken": next_token, "pages": pages,
                                "received": received, "saved": saved, "seen": sorted(seen)}
                token = next_token
                continue
            last = index == len(names) - 1 or pages >= spec.max_pages
            if not last:
                yield records, {"index": index + 1, "pages": pages, "received": received, "saved": saved}
                break
            status = "PARTIAL" if next_token or index < len(names) - 1 else "COMPLETE"
            reasons = [ROTATION_UNKNOWN]
            if status == "PARTIAL":
                reasons.append("PAGE_LIMIT_REACHED")
            if received != saved:
                status = "PARTIAL"
                reasons.append("INVALID_IDENTIFIERS")
            if not parent_complete:
                status = "PARTIAL"
                reasons.append("PARENT_LISTING_INCOMPLETE")
            yield [*records, report(spec, run.scope, "azure.key_vault.versions", status=status,
                                    reasons=reasons, pages=pages, received=received,
                                    saved=saved)], {}
            return


def _values(context, cursor):
    from .values import collect_values

    yield from collect_values(context, cursor)


_PRODUCERS = {"secrets": _secrets, "versions": _versions,
              "deleted_secrets": _deleted_secrets, "value_access": _values}


def collect_pages(spec, *, secrets, checkpoint, check, read_records=None, value_context=None,
                  transport=None, client=None, token=None, now=None):
    """Yield one provider page and the cursor that resumes after it."""
    if not isinstance(spec, MetadataConnectionSpec):
        spec = MetadataConnectionSpec.model_validate(spec)
    validate_spec(spec)
    from cremore_azure_provider import app_certificate as certificate

    if bool(secrets) != certificate.signs_in(spec):
        raise ValueError("AZURE_KEY_VAULT_AMBIENT_CREDENTIALS_REQUIRED")
    if spec.options.include_values:
        from .values import validate_context

        validate_context(value_context)
    state = deepcopy(checkpoint or {})
    config_hash = _config_hash(spec)
    if state and (state.get("provider") != "azure_key_vault" or state.get("version") != 1
                  or state.get("config_hash") != config_hash):
        raise ValueError("AZURE_KEY_VAULT_CHECKPOINT_MISMATCH")
    _validate_checkpoint(spec, state)
    if state and read_records is None:
        raise ValueError("AZURE_KEY_VAULT_RECORD_REPLAY_REQUIRED")
    run = _Run(spec, state, config_hash)
    # Resuming into `versions` needs the names the earlier phase found; they are
    # rebuilt from the records already committed, never re-listed.
    previous = list(read_records()) if read_records is not None else []
    names = _names(previous)

    if run.phase == "done":
        yield MetadataPage(checkpoint=run.checkpoint(phase="done"), status=run.status,
                           reasons=sorted(run.reasons))
        return

    own_client = client is None and transport is None
    if transport is None:
        import httpx

        from .transport import token_for_origin

        client = client or httpx.Client(timeout=spec.options.timeout_seconds,
                                        follow_redirects=False)
        token = token or (certificate.TokenSource(secrets, certificate.SCOPES["vault"], client=client)
                          if certificate.signs_in(spec) else token_for_origin(spec.origin))
        transport = Transport(client, token, origin=spec.origin,
                              options=spec.options, api_version=API_VERSION,
                              include_values=spec.options.include_values,
                              include_public_certificates="public_certificates" in spec.options.sources,
                              max_requests=max(0, spec.max_requests - run.requests), check=check)
    spent = run.requests
    try:
        if run.requests >= spec.max_requests:
            raise Budget("REQUEST_BUDGET_EXCEEDED")
        try:
            yield from _phases(spec, run, transport, names, now or datetime.now(UTC),
                               previous, value_context)
        finally:
            run.requests = spent + transport.requests
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


def _names(records) -> list[str]:
    """The secret names an earlier page already recorded."""
    found = []
    for item in records or []:
        if item.get("record_type") != "entity_observation":
            continue
        if item.get("identity", {}).get("kind") != "vault_item":
            continue
        name = record_values(item).get("secret_id")
        if isinstance(name, str) and SECRET_NAME.fullmatch(name) and name not in found:
            found.append(name)
    return found


def _phases(spec, run, transport, names, end, previous, value_context):
    # The request total spans restarts: this run's transport starts at zero but
    # the budget it was given already excluded what earlier attempts spent.
    spent = run.requests
    context = {"spec": spec, "run": run, "transport": transport, "names": list(names),
               "end": end, "records": list(previous), "value_context": value_context}
    start = PHASES.index(run.phase) if run.phase in PHASES else 0
    for phase in PHASES[start:]:
        if phase in run.done:
            continue
        run.phase = phase
        cursor = deepcopy(run.cursor) if run.cursor.get("phase") == phase else {}
        if not _enabled(spec, phase):
            records = _validated(spec, [report(
                spec, run.scope, "azure.key_vault." + phase, status="NOT_REQUESTED",
                reasons=["NOT_REQUESTED_BY_CONFIGURATION"], shape="empty",
                facts={"selection": phase})])
            run.charge(records)
            run.done.append(phase)
            yield MetadataPage(records=records, checkpoint=run.checkpoint(phase=phase))
            continue
        if phase == "public_certificates":
            from .certificates import collect_certificates

            produced = collect_certificates(context, cursor)
        else:
            produced = (collect_resources(context, cursor, phase=phase) if phase in RESOURCE_SOURCES
                        else _PRODUCERS[phase](context, cursor))
        for records, next_cursor in produced:
            _validated(spec, records)
            run.charge(records)
            if phase != "value_access":
                context["records"].extend(record.model_dump() for record in records)
            run.requests = spent + transport.requests
            for record in records:
                if record.record_type == "operation_report" and record.status in ("PARTIAL", "FAILED"):
                    for reason in record.reasons:
                        run.degrade(record.status, reason)
            if next_cursor:
                run.cursor = {**next_cursor, "phase": phase}
                yield MetadataPage(records=records,
                                   checkpoint=run.checkpoint(phase=phase, cursor=run.cursor))
            else:
                run.done.append(phase)
                run.cursor = {}
                yield MetadataPage(records=records, checkpoint=run.checkpoint(phase=phase))
    run.phase = "done"
    yield MetadataPage(checkpoint=run.checkpoint(phase="done"), status=run.status,
                       reasons=sorted(run.reasons))


def native_snapshots(records):
    """The native adapter's own record shape, rebuilt from what was stored.

    ``last_rotated_at`` is absent on purpose: the native adapter filled it from
    ``updated_on``, which is not a rotation. Every other field it produced is
    here, so an existing consumer sees the same document minus the one claim
    that was never true.
    """
    secrets = []
    for item in records or []:
        # Live secrets only: deleted secrets and value reads share the identity but are not the listing.
        if (item.get("record_type") != "entity_observation"
                or item.get("provenance", {}).get("operation") != "azure.key_vault.secrets"):
            continue
        if item.get("identity", {}).get("kind") != "vault_item":
            continue
        values = record_values(item)
        secrets.append({
            "provider": "azure_key_vault",
            "identifier": values.get("resource_name"),
            "name": values.get("secret_id"),
            "created_at": values.get("created_at"),
            "updated_at": values.get("updated_at"),
            "expires_at": values.get("expires_at"),
            "rotation_enabled": None,
            "next_rotation_at": None,
            "rotation_interval_days": None,
            "owner_service": None,
            "tags": None,
        })
    return [{"kind": "cloud_secret_metadata_inventory", "schema_version": API_VERSION,
             "secret_count": len(secrets), "secrets": secrets,
             "omitted": [{"field": "last_rotated_at", "reason": UPDATED_IS_NOT_ROTATION},
                         {"field": "rotation_enabled", "reason": ROTATION_UNKNOWN},
                         {"field": "tags", "reason": "TAGS_ARE_AN_OPERATOR_DECLARATION_NOT_PROVIDER_STATE"}]}]


def _compare_runs(before, after, *, spec, scope_id=None):
    """Key Vault compares only committed observations; no spec argument is needed."""
    return compare_records(before, after)


def compare_records(previous, current):
    """What changed between two runs, in the vocabulary an operator can act on."""
    def index(records):
        return {object_id_of(item): item for item in records or []
                if item.get("record_type") == "entity_observation"}

    def object_id_of(item):
        return item.get("identity", {}).get("object_id", "")

    before, after = index(previous), index(current)
    added = sorted(set(after) - set(before))
    reports = [item for item in current or [] if item.get("record_type") == "operation_report"]
    removed, unlisted = [], []
    for key in sorted(set(before) - set(after)):
        item = before[key]
        operation = item.get("provenance", {}).get("operation")
        complete = _complete_operation(reports, item.get("scope"), operation)
        parent = {"azure.key_vault.versions": "azure.key_vault.secrets",
                  "azure.key_vault.key_versions": "azure.key_vault.keys",
                  "azure.key_vault.certificate_versions": "azure.key_vault.certificates"}.get(operation)
        if parent:
            complete = complete and _complete_operation(reports, item.get("scope"), parent)
        if complete:
            removed.append(key)
        else:
            unlisted.append({"object_id": key, "reason": "source_not_completely_listed"})
    changed = []
    for key in sorted(set(before) & set(after)):
        old, new = record_values(before[key]), record_values(after[key])
        fields = sorted(field for field in set(old) | set(new) if old.get(field) != new.get(field))
        if fields:
            changed.append({"object_id": key, "fields": fields})
    return {"added": added, "removed": removed, "changed": changed, "absence_not_evaluated": unlisted,
            # A changed updated_at is a property change of some kind; it does
            # not say the secret's value was replaced. A new version does.
            "notes": [UPDATED_IS_NOT_ROTATION]}


__all__ = ["collect_pages", "compare_records", "native_snapshots", "validate_machine_record",
           "validate_record", "validate_spec"]
