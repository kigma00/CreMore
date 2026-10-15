"""Durable, read-only Entra application, SP and federation inventories."""

from __future__ import annotations

import math
import re
from copy import deepcopy

from cremore.coverage.metadata_models import RECORD_ADAPTER, MetadataConnectionSpec, MetadataPage
from cremore.coverage.models import digest
from cremore_azure_provider import app_certificate as certificate
from cremore_azure_provider.metadata.transport import DEFERRED, ApiError, Budget

from . import CONTRACT_VERSION
from .normalization import entity_records, federated_record, guid, report
from .permissions import SOURCES as APP_SOURCES
from .transport import CLOUDS, GUID, GraphTransport, cursor_from_link, token_for_spec, valid_cursor

# app_access re-emits the credentials it reads for, so it runs before public_certificates, which copies the latest
# observation of each certificate (with its permissions) and adds its fingerprint. It runs when either of its options
# (APP_SOURCES: app_permissions, app_azure_roles) is a source; it is not a source itself.
PHASES = ("applications", "service_principals", "app_access", "federated_identity_credentials",
          "public_certificates", "credential_sign_ins", "directory_audits")
DEFAULT_SOURCES = PHASES[:2]
CHECKPOINT_VERSION = 2  # 1: before app_access took the third phase
_IDENTITIES = {
    "principal": re.compile(r"(?:application|service_principal):" + GUID),
    "credential": re.compile(r"(?:application|service_principal):" + GUID + r":(?:passwordCredentials|keyCredentials):" + GUID),
    "public_key": re.compile(r"(?:application|service_principal):" + GUID + r":keyCredentials:" + GUID),
    "trust": re.compile(r"application:" + GUID + r":federated_identity:" + GUID),
}


def validate_spec(spec):
    if spec.provider != "azure_entra" or spec.edition != "cloud" or spec.origin not in CLOUDS:
        raise ValueError("AZURE_ENTRA_GRAPH_ORIGIN_REQUIRED")
    if (not spec.tenant_confirmed or not guid(spec.tenant) or spec.tenant != guid(spec.tenant)
            or len(spec.scopes) != 1 or spec.scopes[0].kind != "organization"
            or spec.scopes[0].id != spec.tenant):
        raise ValueError("AZURE_ENTRA_CONFIRMED_TENANT_REQUIRED")
    if not certificate.allowed(spec, public_cloud=spec.origin == certificate.GRAPH):
        raise ValueError("AZURE_ENTRA_WORKLOAD_IDENTITY_REQUIRED")
    if spec.principal_pin is not None:
        raise ValueError("AZURE_ENTRA_PRINCIPAL_PIN_UNSUPPORTED")
    if "inventory" not in spec.capabilities or set(spec.capabilities) - {"inventory", "policy", "public_keys", "audit"}:
        raise ValueError("AZURE_ENTRA_CAPABILITY_UNSUPPORTED")
    if spec.options.mode != "inventory" or spec.options.include_values:
        raise ValueError("AZURE_ENTRA_METADATA_ONLY")
    selected = spec.options.sources or DEFAULT_SOURCES
    if set(selected) - set(PHASES) - set(APP_SOURCES) or "app_access" in selected:
        raise ValueError("AZURE_ENTRA_SOURCE_UNSUPPORTED")
    if {"credential_sign_ins", "directory_audits"} & set(selected) and ("audit" not in spec.capabilities
            or not set(selected) & set(DEFAULT_SOURCES) or (spec.options.audit_lookback_days or 1) > 30):
        raise ValueError("AZURE_ENTRA_SIGN_INS_REQUIRE_INVENTORY_AND_AUDIT")
    if "federated_identity_credentials" in selected and (
            "applications" not in selected or "policy" not in spec.capabilities):
        raise ValueError("AZURE_ENTRA_FEDERATION_REQUIRES_APPLICATIONS_AND_POLICY")
    if "public_certificates" in selected and ("public_keys" not in spec.capabilities
            or not set(selected) & set(DEFAULT_SOURCES)):
        raise ValueError("AZURE_ENTRA_PUBLIC_CERTIFICATES_REQUIRE_DISCOVERY_AND_PUBLIC_KEYS")
    if set(APP_SOURCES) & set(selected) and ("service_principals" not in selected or "policy" not in spec.capabilities):
        raise ValueError("AZURE_ENTRA_APP_PERMISSIONS_REQUIRE_SERVICE_PRINCIPALS_AND_POLICY")
    # Azure roles are read through Azure Resource Manager's public cloud.
    if "app_azure_roles" in selected and spec.origin != certificate.GRAPH:
        raise ValueError("AZURE_ENTRA_AZURE_ROLES_REQUIRE_THE_PUBLIC_CLOUD")


def _selected(spec):
    """The phases a spec runs: its sources, and app_access when an option of it is one."""
    selected = set(spec.options.sources or DEFAULT_SOURCES)
    return selected | {"app_access"} if selected & set(APP_SOURCES) else selected


def validate_record(spec, item):
    try:
        validate_spec(spec)
    except ValueError:
        return False
    operation = item.provenance.operation.removeprefix("azure.entra.")
    if operation == "directory_audits" and item.purpose == "usage":
        if (operation not in spec.options.sources or "audit" not in spec.capabilities or item.purpose != "usage"
                or item.scope != spec.scopes[0] or item.provenance.contract_version != CONTRACT_VERSION
                or item.provenance.operation != "azure.entra.directory_audits"):
            return False
        if item.record_type == "operation_report":
            return item.value_access == "NOT_REQUESTED" and item.value_contract is None
        if (item.record_type != "relation" or item.relation != "created_by" or item.confidence != "EXACT"
                or item.match_basis != "AUDIT_REFERENCE" or item.facts
                or not re.fullmatch(re.escape(spec.origin + "/v1.0/auditLogs/directoryAudits/") + r"[A-Za-z0-9_-]{1,200}", item.provenance.resource_id)):
            return False
        for identity in (item.subject, item.target):
            if (identity.provider, identity.origin, identity.tenant, identity.tenant_confirmed) != (spec.provider, spec.origin, spec.tenant, True):
                return False
        return (item.subject.kind in {"credential", "public_key"} and bool(_IDENTITIES[item.subject.kind].fullmatch(item.subject.object_id))
                and item.target.kind == "principal" and bool(re.fullmatch(r"(?:user|service_principal):" + GUID, item.target.object_id)))
    if operation == "credential_sign_ins" and item.purpose == "usage":
        if "credential_sign_ins" not in spec.options.sources or "audit" not in spec.capabilities:
            return False
        if (item.scope != spec.scopes[0] or item.provenance.contract_version != CONTRACT_VERSION
                or item.provenance.operation != "azure.entra.credential_sign_ins"):
            return False
        if item.record_type == "operation_report":
            return item.value_access == "NOT_REQUESTED" and item.value_contract is None
        if (item.record_type != "provider_event" or item.event_type != "token_activity" or item.subject is None
                or item.target is not None or item.value_match is not None or item.confidence != "EXACT"
                or item.match_basis != "PROVIDER_EXPLICIT" or not guid(item.event_id)
                or item.provenance.resource_id != spec.origin + "/beta/auditLogs/signIns"):
            return False
        identity = item.subject
        return ((identity.provider, identity.origin, identity.tenant, identity.tenant_confirmed) ==
                (spec.provider, spec.origin, spec.tenant, True) and identity.kind in {"credential", "public_key"}
                and bool(_IDENTITIES[identity.kind].fullmatch(identity.object_id)))
    if (item.scope != spec.scopes[0] or item.purpose != "issuer_inventory"
            or item.provenance.contract_version != CONTRACT_VERSION
            or item.provenance.operation != "azure.entra." + operation or operation not in PHASES):
        return False
    if item.record_type == "operation_report":
        return (item.value_access == "NOT_REQUESTED" and item.value_contract is None
                and item.provenance.resource_id == "")
    if item.record_type != "entity_observation" or item.value_match is not None:
        return False
    if operation == "public_certificates":
        from cremore_azure_provider.public_certificates import certificate_evidence

        if "public_certificates" not in spec.options.sources or "public_keys" not in spec.capabilities or not certificate_evidence(item):
            return False
    identity = item.identity
    if (identity.provider, identity.origin, identity.tenant, identity.tenant_confirmed) != (
            spec.provider, spec.origin, spec.tenant, True):
        return False
    pattern = _IDENTITIES.get(identity.kind)
    if pattern is None or not pattern.fullmatch(identity.object_id):
        return False
    if operation == "app_access" and ("app_access" not in _selected(spec)
                                      or identity.kind not in {"credential", "public_key"}):
        return False
    family, parent, *_ = identity.object_id.split(":")
    endpoint = "applications" if family == "application" else "servicePrincipals"
    expected = spec.origin + "/v1.0/" + endpoint + "/" + parent
    if identity.kind == "trust":
        expected += "/federatedIdentityCredentials"
        if operation != "federated_identity_credentials" or "policy" not in spec.capabilities:
            return False
    elif operation not in {"public_certificates", "app_access"} and operation != (
            "applications" if family == "application" else "service_principals"):
        return False
    return item.provenance.resource_id == expected


def validate_machine_record(spec, item):
    return validate_record(spec, item)


def _initial(spec, checkpoint):
    state = deepcopy(checkpoint or {})
    if state.get("version") == 1 and type(state.get("phase")) is int:
        # A run from before app_access resumes at the same phase, now one further along.
        state.update(version=CHECKPOINT_VERSION, phase=state["phase"] + (state["phase"] >= 2))
    if state and (state.get("provider") != "azure_entra" or state.get("version") != CHECKPOINT_VERSION
                  or state.get("config_hash") != digest(spec.model_dump())):
        raise ValueError("AZURE_ENTRA_CHECKPOINT_MISMATCH")
    if not state:
        state = {"provider": "azure_entra", "version": CHECKPOINT_VERSION, "config_hash": digest(spec.model_dump()),
                 "phase": 0, "cursor": {}, "requests": 0, "records": 0,
                 "status": "COMPLETE", "reasons": []}
    if (type(state.get("phase")) is not int or not 0 <= state["phase"] <= len(PHASES)
            or state.get("status") not in {"COMPLETE", "PARTIAL"}
            or not isinstance(state.get("cursor"), dict)):
        raise ValueError("AZURE_ENTRA_CHECKPOINT_MISMATCH")
    for name, maximum in (("requests", spec.max_requests), ("records", spec.max_records)):
        if type(state.get(name)) is not int or not 0 <= state[name] <= maximum:
            raise ValueError("AZURE_ENTRA_CHECKPOINT_MISMATCH")
    cursor = state["cursor"]
    for name in ("pages", "received", "saved", "index"):
        if name in cursor and (type(cursor[name]) is not int or not 0 <= cursor[name] <= 10_000_000):
            raise ValueError("AZURE_ENTRA_CHECKPOINT_MISMATCH")
    if cursor.get("skiptoken") and not valid_cursor(cursor["skiptoken"]):
        raise ValueError("AZURE_ENTRA_CHECKPOINT_MISMATCH")
    # app_access keeps the read errors it counted and the kinds it stopped asking, each by a code.
    errors, halted = cursor.get("errors", {}), cursor.get("halted", {})
    if (not isinstance(errors, dict) or len(errors) > 100 or any(
            not isinstance(code, str) or not re.fullmatch(r"[a-z0-9_]{1,96}", code) or type(count) is not int or count < 0
            for code, count in errors.items())
            or not isinstance(halted, dict) or any(
                not isinstance(kind, str) or not re.fullmatch(r"[a-z_]{1,64}", kind)
                or not isinstance(code, str) or not re.fullmatch(r"[a-z0-9_]{1,96}", code) for kind, code in halted.items())):
        raise ValueError("AZURE_ENTRA_CHECKPOINT_MISMATCH")
    if (not isinstance(cursor.get("seen", []), list)
            or len(cursor.get("seen", [])) > spec.max_pages
            or any(not valid_cursor(token) for token in cursor.get("seen", []))):
        raise ValueError("AZURE_ENTRA_CHECKPOINT_MISMATCH")
    MetadataPage(checkpoint=state)
    return state


def _application_ids(records):
    return sorted({item["identity"]["object_id"].split(":")[1] for item in records
                   if item.get("record_type") == "entity_observation"
                   and item.get("identity", {}).get("kind") == "principal"
                   and re.fullmatch(r"application:" + GUID, item["identity"]["object_id"])})


def _degrade(state, reasons):
    state["status"] = "PARTIAL"
    state["reasons"] = sorted(set(state["reasons"]) | set(reasons))


def _page(spec, state, records, committed):
    if len(records) > 5000 or state["records"] + len(records) > spec.max_records:
        state.clear()
        state.update(committed)
        raise Budget("RECORD_BUDGET_EXCEEDED")
    for item in records:
        if not validate_record(spec, RECORD_ADAPTER.validate_python(item.model_dump())):
            raise ValueError("AZURE_ENTRA_RECORD_REJECTED")
    state["records"] += len(records)
    return MetadataPage(records=records, checkpoint=deepcopy(state))


def collect_pages(spec, *, secrets, checkpoint, check, read_records=None, value_context=None,
                  transport=None, client=None, token=None, roles=None):
    """``roles`` reads Azure role assignments for app_azure_roles; an injected ``transport`` serves both when
    it is left out."""
    if not isinstance(spec, MetadataConnectionSpec):
        spec = MetadataConnectionSpec.model_validate(spec)
    validate_spec(spec)
    if bool(secrets) != certificate.signs_in(spec):
        raise ValueError("AZURE_ENTRA_WORKLOAD_IDENTITY_REQUIRED")
    if value_context is not None:
        raise ValueError("AZURE_ENTRA_METADATA_ONLY")
    state = _initial(spec, checkpoint)
    if checkpoint and read_records is None:
        raise ValueError("AZURE_ENTRA_RECORD_REPLAY_REQUIRED")
    previous = list(read_records()) if read_records else []
    if state["phase"] == len(PHASES):
        yield MetadataPage(checkpoint=state, status=state["status"], reasons=state["reasons"])
        return
    own_client = client is None and transport is None
    if transport is None:
        import httpx

        client = client or httpx.Client(timeout=spec.options.timeout_seconds, follow_redirects=False)
        token = token or (certificate.TokenSource(secrets, certificate.SCOPES["graph"], client=client)
                          if certificate.signs_in(spec) else token_for_spec(spec))
        transport = GraphTransport(client, token, origin=spec.origin,
                                   options=spec.options, max_requests=spec.max_requests - state["requests"],
                                   check=check)
        if roles is None and "app_azure_roles" in spec.options.sources:
            from cremore_azure_provider.arm.transport import token_for_spec as arm_token

            from .permissions import RoleTransport

            roles = RoleTransport(client, certificate.TokenSource(secrets, certificate.SCOPES["arm"], client=client)
                                  if certificate.signs_in(spec) else arm_token(spec), tenant=spec.tenant,
                                  options=spec.options, charge=transport._charge, pace=transport._pace, check=check)
    roles = roles or transport
    spent = state["requests"]
    try:
        check()
        if spent >= spec.max_requests:
            raise Budget("REQUEST_BUDGET_EXCEEDED")
        identity = transport.get("/v1.0/organization", {"$select": "id"})
        organizations = identity.get("value")
        if (not isinstance(organizations, list) or len(organizations) != 1
                or not isinstance(organizations[0], dict)
                or guid(organizations[0].get("id")) != spec.tenant
                or identity.get("@odata.nextLink")):
            raise ApiError("tenant_mismatch")
        state["requests"] = spent + transport.requests
        yield from _phases(spec, state, transport, previous, spent, check, roles)
    except Budget as exc:
        _degrade(state, [exc.code])
        state["requests"] = spent + transport.requests
        yield MetadataPage(checkpoint=state, status="PARTIAL", reasons=state["reasons"])
    except ApiError as exc:
        state["requests"] = spent + transport.requests
        if exc.code in DEFERRED:
            yield MetadataPage(checkpoint=state, status="WAITING", reasons=[exc.code.upper()],
                                retry_after_seconds=max(1, min(3600, math.ceil(exc.retry_after or 60))))
        else:
            yield MetadataPage(checkpoint=state, status="FAILED", reasons=[exc.code.upper()])
    finally:
        if own_client and client is not None:
            client.close()


def _phases(spec, state, transport, previous, spent, check, roles):
    selected = _selected(spec)
    while state["phase"] < len(PHASES):
        check()
        committed = deepcopy(state)
        phase = PHASES[state["phase"]]
        cursor = deepcopy(state["cursor"])
        if phase not in selected:
            state["phase"] += 1
            state["cursor"] = {}
            yield _page(spec, state, [report(spec, phase, status="NOT_REQUESTED",
                                            reasons=["NOT_REQUESTED_BY_CONFIGURATION"])], committed)
            continue
        if phase == "public_certificates":
            from .certificates import collect_certificates

            yield from collect_certificates(spec, state, transport, previous, spent, check)
            continue
        if phase == "app_access":
            from .permissions import collect_access

            for page in collect_access(spec, state, transport, roles, previous, spent, check):
                previous.extend(record.model_dump() for record in page.records)
                yield page
            continue
        if phase in {"credential_sign_ins", "directory_audits"}:
            from .audit import collect_sign_ins

            yield from collect_sign_ins(spec, state, transport, previous, spent, check, directory=phase == "directory_audits")
            continue
        federated = phase == "federated_identity_credentials"
        applications = _application_ids(previous) if federated else []
        index = cursor.get("index", 0)
        reasons = set(cursor.get("reasons", []))
        if federated:
            if len(applications) > spec.options.max_targets:
                reasons.add("TARGET_LIMIT_REACHED")
                applications = applications[:spec.options.max_targets]
            if index > len(applications):
                raise ValueError("AZURE_ENTRA_CHECKPOINT_MISMATCH")
            if index == len(applications):
                if state["status"] != "COMPLETE":
                    reasons.add("APPLICATION_DISCOVERY_INCOMPLETE")
                records = [report(spec, phase, status="PARTIAL" if reasons else "COMPLETE", reasons=reasons)]
                if reasons:
                    _degrade(state, reasons)
                state["phase"] += 1
                state["cursor"] = {}
                yield _page(spec, state, records, committed)
                continue
            path = "/v1.0/applications/" + applications[index] + "/federatedIdentityCredentials"
            fields = "id,name,issuer,subject,audiences"
        else:
            path = "/v1.0/" + ("applications" if phase == "applications" else "servicePrincipals")
            fields = "id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials"
            if phase == "service_principals":
                fields += ",accountEnabled,servicePrincipalType"
        params = {"$select": fields, "$top": min(spec.options.page_size, 25)}
        if federated:
            # This endpoint documents $select/$filter, not $top.
            params.pop("$top")
        if cursor.get("skiptoken"):
            params["$skiptoken"] = cursor["skiptoken"]
        records, next_token = [], ""
        pages = cursor.get("pages", 0)
        received, saved = cursor.get("received", 0), cursor.get("saved", 0)
        try:
            payload = transport.get(path, params)
            rows = payload.get("value")
            if not isinstance(rows, list):
                raise ApiError("invalid_response")
            pages += 1
            received += len(rows)
            next_token = cursor_from_link(payload.get("@odata.nextLink"), spec.origin, path)
            if next_token and next_token in cursor.get("seen", []):
                raise ApiError("pagination_cycle")
            for row in rows:
                if federated:
                    record = federated_record(spec, applications[index], row)
                    projected, invalid = ([record], set()) if record else ([], {"INVALID_FEDERATED_IDENTITY"})
                else:
                    projected, invalid = entity_records(spec, phase, row)
                records.extend(projected)
                reasons.update(invalid)
                saved += int(bool(projected))
        except ApiError as exc:
            if exc.code in DEFERRED:
                raise
            reasons.add(exc.code.upper())
            next_token = ""
        state["requests"] = spent + transport.requests
        more = bool(next_token) or federated and index + 1 < len(applications)
        if more and pages >= spec.max_pages:
            reasons.add("PAGE_LIMIT_REACHED")
            more = False
        if more:
            state["cursor"] = {
                "index": index if next_token else index + 1, "skiptoken": next_token,
                "seen": [*cursor.get("seen", []), next_token] if next_token else [],
                "pages": pages, "received": received, "saved": saved, "reasons": sorted(reasons)}
        else:
            records.append(report(spec, phase, status="PARTIAL" if reasons else "COMPLETE",
                                   reasons=reasons, pages=pages, received=received, saved=saved))
            if reasons:
                _degrade(state, reasons)
            state["phase"] += 1
            state["cursor"] = {}
        # Cursor and records form one commit; a refused batch rolls back.
        page = _page(spec, state, records, committed)
        previous.extend(record.model_dump() for record in records)
        yield page
    yield MetadataPage(checkpoint=state, status=state["status"], reasons=state["reasons"])


def native_snapshots(records):
    """Export the same safe typed records; there is no hidden native response."""
    return [{"kind": "azure_entra_credential_inventory", "schema_version": CONTRACT_VERSION,
             "records": list(records or [])}]
