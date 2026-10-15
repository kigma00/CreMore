"""Configured subscription discovery and explicitly approved Storage keys."""

import re
from copy import deepcopy
from urllib.parse import urlencode

from cremore.coverage.metadata_models import RECORD_ADAPTER, MetadataConnectionSpec, MetadataPage
from cremore.coverage.models import digest
from cremore_azure_provider import app_certificate as certificate
from cremore_azure_provider.entra.normalization import guid
from cremore_azure_provider.metadata.transport import DEFERRED, ApiError, Budget
from cremore_azure_provider.metadata.values import validate_context

from . import CONTRACT_VERSION, ORIGIN, STORAGE_VERSION, SUBSCRIPTION_VERSION, VAULT_VERSION
from .normalization import report, resource_record, storage_key_records, subscription_record
from .transport import STORAGE_ID, VAULT_ID, ArmTransport, page_query, token_for_spec

SOURCES = ("subscriptions", "vaults", "storage_accounts", "storage_keys")


def validate_spec(spec):
    if spec.provider != "azure_resource_manager" or spec.origin != ORIGIN or spec.edition != "cloud":
        raise ValueError("AZURE_ARM_ORIGIN_REQUIRED")
    if (not spec.tenant_confirmed or guid(spec.tenant) != spec.tenant
            or not spec.tenant or not certificate.allowed(spec)):
        raise ValueError("AZURE_ARM_CONFIRMED_TENANT_AND_WORKLOAD_IDENTITY_REQUIRED")
    if spec.principal_pin is not None:
        raise ValueError("AZURE_ARM_PRINCIPAL_PIN_UNSUPPORTED")
    if "inventory" not in spec.capabilities or set(spec.capabilities) - {"inventory", "issuer_value"}:
        raise ValueError("AZURE_ARM_CAPABILITY_UNSUPPORTED")
    selected = _sources(spec)
    if set(selected) - set(SOURCES):
        raise ValueError("AZURE_ARM_COLLECTION_OPTION_UNSUPPORTED")
    discovery = spec.options.mode == "discovery"
    if discovery:
        if (len(spec.scopes) != 1 or spec.scopes[0].kind != "organization"
                or spec.scopes[0].id != spec.tenant or selected != ["subscriptions"]):
            raise ValueError("AZURE_ARM_DISCOVERY_TENANT_SCOPE_REQUIRED")
    elif spec.options.mode != "inventory" or any(s.kind != "subscription" or guid(s.id) != s.id for s in spec.scopes):
        raise ValueError("AZURE_ARM_APPROVED_SUBSCRIPTIONS_REQUIRED")
    if spec.options.include_values != ("storage_keys" in selected):
        raise ValueError("AZURE_STORAGE_KEY_SOURCE_AND_VALUE_OPT_IN_REQUIRED")
    if "storage_keys" in selected:
        if discovery or "issuer_value" not in spec.capabilities or not spec.options.azure_storage_accounts:
            raise ValueError("AZURE_STORAGE_EXPLICIT_ACCOUNT_APPROVAL_REQUIRED")
    elif spec.options.azure_storage_accounts:
        raise ValueError("AZURE_STORAGE_KEY_SOURCE_REQUIRED")
    approved_subscriptions = {s.id for s in spec.scopes}
    if any(not STORAGE_ID.fullmatch(account) or account.split("/")[2].lower() not in approved_subscriptions
           for account in spec.options.azure_storage_accounts):
        raise ValueError("AZURE_STORAGE_ACCOUNT_OUTSIDE_SUBSCRIPTION_SCOPE")


def _sources(spec):
    return spec.options.sources or (["subscriptions"] if spec.options.mode == "discovery"
                                    else ["vaults", "storage_accounts"])


def _tasks(spec):
    output = []
    selected = _sources(spec)
    for scope in spec.scopes:
        for phase in SOURCES:
            if phase not in selected:
                continue
            if phase == "storage_keys":
                accounts = [account for account in spec.options.azure_storage_accounts
                            if account.split("/")[2].casefold() == scope.id]
                output.extend((scope, phase, account) for account in accounts or [""])
            else:
                output.append((scope, phase, ""))
    return output


def validate_record(spec, item):
    try:
        validate_spec(spec)
    except ValueError:
        return False
    phase = item.provenance.operation.removeprefix("azure.arm.")
    if (item.scope not in spec.scopes or item.purpose != "issuer_inventory"
            or item.provenance.operation != "azure.arm." + phase or phase not in _sources(spec)
            or item.provenance.contract_version != CONTRACT_VERSION):
        return False
    if item.record_type == "operation_report":
        return (not item.provenance.resource_id and (item.value_access == "NOT_REQUESTED"
                or phase == "storage_keys" and item.value_contract is not None))
    if item.record_type != "entity_observation":
        return False
    identity = item.identity
    if (identity.provider, identity.origin, identity.tenant, identity.tenant_confirmed) != (
            spec.provider, spec.origin, spec.tenant, True):
        return False
    identifier = identity.object_id
    if phase == "subscriptions":
        return (identity.kind == "resource" and item.value_match is None
                and identifier.casefold().startswith("/subscriptions/")
                and guid(identifier.split("/")[-1]) is not None
                and len(identifier.split("/")) == 3
                and (item.scope.kind == "organization" or identifier.split("/")[-1].lower() == item.scope.id)
                and item.provenance.resource_id == identifier)
    if phase in {"vaults", "storage_accounts"}:
        pattern = VAULT_ID if phase == "vaults" else STORAGE_ID
        matched = pattern.fullmatch(identifier)
        return (bool(matched) and matched[1].lower() == item.scope.id and identity.kind == "resource"
                and item.value_match is None and item.provenance.resource_id == identifier)
    account, separator, key = identifier.rpartition("/keys/")
    match = item.value_match
    return (identity.kind == "credential" and bool(separator) and key in {"key1", "key2"}
            and account.casefold() in {value.casefold() for value in spec.options.azure_storage_accounts}
            and account.split("/")[2].lower() == item.scope.id
            and item.provenance.resource_id == spec.origin + account + "/listKeys"
            and match is not None and match.reference == identifier
            and match.evidence in {"VALUE", "UNRESOLVED"}
            and match.credential_type == "AZURE_STORAGE_KEY")


def validate_machine_record(spec, item):
    return validate_record(spec, item)


def _state(spec, checkpoint, tasks):
    state = deepcopy(checkpoint or {})
    if not state:
        return {"provider": spec.provider, "version": 1, "config_hash": digest(spec.model_dump()),
                "index": 0, "cursor": {}, "requests": 0, "records": 0,
                "status": "COMPLETE", "reasons": []}
    if (state.get("provider") != spec.provider or state.get("version") != 1
            or state.get("config_hash") != digest(spec.model_dump())
            or type(state.get("index")) is not int or not 0 <= state["index"] <= len(tasks)
            or not isinstance(state.get("cursor"), dict) or state.get("status") not in {"COMPLETE", "PARTIAL"}):
        raise ValueError("AZURE_ARM_CHECKPOINT_MISMATCH")
    for field, maximum in (("requests", spec.max_requests), ("records", spec.max_records)):
        if type(state.get(field)) is not int or not 0 <= state[field] <= maximum:
            raise ValueError("AZURE_ARM_CHECKPOINT_MISMATCH")
    cursor = state["cursor"]
    for field in ("pages", "received", "saved"):
        if field in cursor and (type(cursor[field]) is not int or not 0 <= cursor[field] <= 10_000_000):
            raise ValueError("AZURE_ARM_CHECKPOINT_MISMATCH")
    if (not isinstance(cursor.get("seen", []), list) or len(cursor.get("seen", [])) > spec.max_pages
            or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in cursor.get("seen", []))):
        raise ValueError("AZURE_ARM_CHECKPOINT_MISMATCH")
    for values in (state.get("reasons", []), cursor.get("reasons", [])):
        if (not isinstance(values, list) or len(values) > 100
                or any(not isinstance(value, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", value) for value in values)):
            raise ValueError("AZURE_ARM_CHECKPOINT_MISMATCH")
    if cursor.get("continuation"):
        value = cursor["continuation"]
        if (state["index"] == len(tasks) or not isinstance(value, dict)
                or not isinstance(value.get("path"), str) or not isinstance(value.get("params"), dict)
                or any(not isinstance(k, str) or not isinstance(v, str) for k, v in value["params"].items())):
            raise ValueError("AZURE_ARM_CHECKPOINT_MISMATCH")
        scope, phase, _ = tasks[state["index"]]
        if phase == "storage_keys":
            raise ValueError("AZURE_ARM_CHECKPOINT_MISMATCH")
        try:
            page_query(spec.origin + value["path"] + "?" + urlencode(value["params"]),
                       path=_path(scope, phase)[0], subscription=scope.id, vaults=phase == "vaults")
        except ApiError:
            raise ValueError("AZURE_ARM_CHECKPOINT_MISMATCH") from None
    MetadataPage(checkpoint=state)
    return state


def _path(scope, phase):
    if phase == "subscriptions":
        return ("/subscriptions" if scope.kind == "organization" else "/subscriptions/" + scope.id,
                {"api-version": SUBSCRIPTION_VERSION})
    family = "Microsoft.KeyVault/vaults" if phase == "vaults" else "Microsoft.Storage/storageAccounts"
    return (f"/subscriptions/{scope.id}/providers/{family}",
            {"api-version": VAULT_VERSION if phase == "vaults" else STORAGE_VERSION})


def _verify_tenant(spec, scope, transport):
    if scope.kind == "subscription":
        payload = transport.get("/subscriptions/" + scope.id, {"api-version": SUBSCRIPTION_VERSION})
        if subscription_record(spec, scope, payload) is None:
            raise ApiError("tenant_or_subscription_mismatch")
        return
    path, params, seen = "/tenants", {"api-version": SUBSCRIPTION_VERSION}, set()
    for _ in range(spec.max_pages):
        payload = transport.get(path, params)
        rows = payload.get("value")
        if not isinstance(rows, list):
            raise ApiError("invalid_tenant_response")
        if any(isinstance(row, dict) and guid(row.get("tenantId")) == spec.tenant for row in rows):
            return
        next_page = page_query(payload.get("nextLink"), path="/tenants", subscription="")
        if not next_page:
            raise ApiError("tenant_not_accessible")
        marker = digest(next_page)
        if marker in seen:
            raise ApiError("tenant_pagination_cycle")
        seen.add(marker)
        path, params = next_page["path"], next_page["params"]
    raise Budget("TENANT_DISCOVERY_PAGE_LIMIT")


def collect_pages(spec, *, secrets, checkpoint, check, read_records=None, value_context=None,
                  transport=None, client=None, token=None):
    if not isinstance(spec, MetadataConnectionSpec):
        spec = MetadataConnectionSpec.model_validate(spec)
    validate_spec(spec)
    if bool(secrets) != certificate.signs_in(spec):
        raise ValueError("AZURE_ARM_WORKLOAD_IDENTITY_REQUIRED")
    if spec.options.include_values:
        validate_context(value_context)
    tasks = _tasks(spec)
    state = _state(spec, checkpoint, tasks)
    if state["index"] == len(tasks):
        yield MetadataPage(checkpoint=state, status=state["status"], reasons=state["reasons"])
        return
    own_client = client is None and transport is None
    if transport is None:
        import httpx

        client = client or httpx.Client(timeout=spec.options.timeout_seconds, follow_redirects=False)
        token = token or (certificate.TokenSource(secrets, certificate.SCOPES["arm"], client=client)
                          if certificate.signs_in(spec) else token_for_spec(spec))
        transport = ArmTransport(client, token, spec=spec,
                                  max_requests=spec.max_requests - state["requests"], check=check)
    spent = state["requests"]
    try:
        if spent >= spec.max_requests:
            raise Budget("REQUEST_BUDGET_EXCEEDED")
        yield from _collect(spec, state, tasks, transport, value_context, spent, check)
    except Budget as exc:
        state["requests"] = spent + transport.requests
        yield MetadataPage(checkpoint=state, status="PARTIAL", reasons=sorted(set(state["reasons"]) | {exc.code}))
    except ApiError as exc:
        state["requests"] = spent + transport.requests
        yield MetadataPage(checkpoint=state, status="WAITING" if exc.code in DEFERRED else "FAILED",
                            reasons=[exc.code.upper()], retry_after_seconds=max(1, min(3600, int(exc.retry_after or 60))))
    finally:
        if own_client and client is not None:
            client.close()


def _vault_details(spec, scope, row, transport):
    if not isinstance(row, dict) or not isinstance(row.get("id"), str):
        return row
    match = VAULT_ID.fullmatch(row["id"])
    if (not match or match[1].casefold() != scope.id
            or str(row.get("type", "")).casefold() != "microsoft.keyvault/vaults"):
        return row
    properties = row.get("properties") if isinstance(row.get("properties"), dict) else {}
    if properties.get("tenantId") and guid(properties["tenantId"]) != spec.tenant:
        return row
    if properties.get("tenantId") and properties.get("vaultUri"):
        return row
    details = transport.get(row["id"], {"api-version": VAULT_VERSION})
    if str(details.get("id", "")).casefold() != row["id"].casefold():
        raise ApiError("vault_resource_mismatch")
    return details


def _collect(spec, state, tasks, transport, context, spent, check):
    verified = set()
    while state["index"] < len(tasks):
        check()
        committed = deepcopy(state)
        scope, phase, account = tasks[state["index"]]
        if scope.id not in verified:
            _verify_tenant(spec, scope, transport)
            verified.add(scope.id)
        cursor = state["cursor"]
        records, reasons, next_page = [], set(cursor.get("reasons", [])), None
        pages, received, saved = (cursor.get(name, 0) for name in ("pages", "received", "saved"))
        try:
            if phase == "storage_keys":
                if account:
                    payload = transport.list_keys(account)
                    records, invalid = storage_key_records(spec, scope, account, payload, context)
                    reasons.update(invalid)
                    received, saved, pages = len(payload.get("keys", [])) if isinstance(payload.get("keys"), list) else 0, len(records), 1
            else:
                path, params = _path(scope, phase)
                if cursor.get("continuation"):
                    continuation = cursor["continuation"]
                    checked = page_query(spec.origin + continuation["path"] + "?" + urlencode(continuation["params"]),
                                         path=path, subscription=scope.id, vaults=phase == "vaults")
                    path, params = checked["path"], checked["params"]
                payload = transport.get(path, params)
                rows = [payload] if phase == "subscriptions" and scope.kind == "subscription" else payload.get("value")
                if not isinstance(rows, list):
                    raise ApiError("invalid_response")
                pages += 1
                received += len(rows)
                next_page = page_query(payload.get("nextLink"), path=_path(scope, phase)[0],
                                       subscription=scope.id, vaults=phase == "vaults")
                if next_page and digest(next_page) in cursor.get("seen", []):
                    raise ApiError("pagination_cycle")
                for row in rows:
                    if (phase == "subscriptions" and isinstance(row, dict) and guid(row.get("tenantId"))
                            and guid(row["tenantId"]) != spec.tenant):
                        continue  # Explicitly another tenant; never becomes an approved subscription.
                    if phase == "vaults":
                        try:
                            row = _vault_details(spec, scope, row, transport)
                        except ApiError as exc:
                            if exc.code in DEFERRED:
                                raise
                            reasons.add(exc.code.upper())
                            continue
                    record = (subscription_record(spec, scope, row) if phase == "subscriptions"
                              else resource_record(spec, scope, phase, row))
                    if record:
                        records.append(record)
                    else:
                        reasons.add("INVALID_OR_OUT_OF_SCOPE_RESOURCES")
                saved += len(records)
        except ApiError as exc:
            if exc.code in DEFERRED:
                raise
            reasons.add(exc.code.upper())
            next_page = None
        state["requests"] = spent + transport.requests
        if next_page and pages >= spec.max_pages:
            reasons.add("PAGE_LIMIT_REACHED")
            next_page = None
        if next_page:
            state["cursor"] = {"continuation": next_page, "pages": pages, "received": received, "saved": saved,
                               "seen": [*cursor.get("seen", []), digest(next_page)], "reasons": sorted(reasons)}
        else:
            no_approval = phase == "storage_keys" and not account
            records.append(report(spec, scope, phase,
                                  reasons=["NO_APPROVED_STORAGE_ACCOUNTS_IN_SCOPE"] if no_approval else reasons,
                                  status="NOT_REQUESTED" if no_approval else None, pages=pages,
                                  received=received, saved=saved,
                                  context=context if phase == "storage_keys" and account else None))
            state["index"] += 1
            state["cursor"] = {}
        if reasons:
            state["status"] = "PARTIAL"
            state["reasons"] = sorted(set(state["reasons"]) | reasons)
        if len(records) > 5000 or state["records"] + len(records) > spec.max_records:
            state.clear()
            state.update(committed)
            raise Budget("RECORD_BUDGET_EXCEEDED")
        for record in records:
            if not validate_record(spec, RECORD_ADAPTER.validate_python(record.model_dump())):
                raise ValueError("AZURE_ARM_RECORD_REJECTED")
        state["records"] += len(records)
        yield MetadataPage(records=records, checkpoint=deepcopy(state))
    yield MetadataPage(checkpoint=state, status=state["status"], reasons=state["reasons"])


def native_snapshots(records):
    return [{"kind": "azure_resource_manager_inventory", "schema_version": CONTRACT_VERSION,
             "records": list(records or [])}]
