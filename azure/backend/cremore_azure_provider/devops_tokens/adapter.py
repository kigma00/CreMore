"""Checkpointed Azure DevOps PAT inventory: organization users, then each user's tokens."""

from __future__ import annotations

import re
from copy import deepcopy
from datetime import UTC, datetime

from cremore.coverage.metadata_models import (
    RECORD_ADAPTER,
    MetadataConnectionSpec,
    MetadataPage,
    checkpoint_json,
    in_metadata_scope,
)
from cremore.coverage.models import digest

from . import CONTRACT_VERSION, ORIGIN, SOURCES, TOKEN_API_VERSION
from .normalization import observation as token_observation
from .normalization import operation, project, record_values, report, resource, uuid_text
from .transport import DESCRIPTOR, ReadError, Transport, cursor_text

ORGANIZATION = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,48}[A-Za-z0-9])?")
_COUNTS = ("task", "user", "requests", "pages", "records", "retries", "op_pages", "received", "saved",
           "invalid", "duplicates")
_FIELDS = {"authorization_id", "status", "created_at", "expires_at", "display_name", "scopes", "user_id",
           "client_id", "owner"}
# Graph user origins: aad is a Microsoft Entra user, msa a Microsoft account.
ORIGINS = ("aad", "msa", "vsts", "ad")
GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _reason(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Z0-9_]{1,96}", value))


def validate_spec(spec):
    if spec.provider != "azure_devops" or spec.edition != "cloud" or spec.origin != ORIGIN:
        raise ValueError("AZURE_DEVOPS_SERVICES_REQUIRED")
    from cremore_azure_provider import app_certificate as certificate

    if not (spec.auth_type == "token" and set(spec.secret_refs) == {"token"} or certificate.allowed(spec)):
        raise ValueError("AZURE_DEVOPS_TOKEN_REFERENCE_REQUIRED")
    if set(spec.capabilities) != {"inventory"} or spec.principal_pin is not None:
        raise ValueError("AZURE_DEVOPS_INVENTORY_CAPABILITY_REQUIRED")
    if not spec.scopes or any(scope.kind != "organization" or not ORGANIZATION.fullmatch(scope.id)
                              for scope in spec.scopes):
        raise ValueError("AZURE_DEVOPS_ORGANIZATION_SCOPE_REQUIRED")
    if (spec.options.mode != "inventory" or spec.options.page_size > 100
            or spec.options.include_values
            or spec.options.include_audit_events or spec.options.include_actions
            or spec.options.locations or spec.options.include_deleted
            or spec.options.audit_created_after or spec.options.audit_lookback_days
            or set(spec.options.sources) - set(SOURCES)):
        raise ValueError("AZURE_DEVOPS_COLLECTION_OPTION_NOT_SUPPORTED")


def validate_record(spec, item):
    try:
        validate_spec(spec)
        if (not in_metadata_scope(spec, item) or item.purpose != "issuer_inventory"
                or item.provenance.operation != operation()
                or item.provenance.contract_version != CONTRACT_VERSION
                or item.provenance.source_commit is not None
                or item.provenance.resource_id != resource(item.scope)):
            return False
        if item.record_type == "operation_report":
            return (record_values(item.model_dump()) == {"coverage_basis": "ORGANIZATION_GRAPH_USERS_ONLY"}
                    and item.native_schema_version == TOKEN_API_VERSION
                    and item.report_type == "azure_devops_token_admin_report" and item.collection_mode == "inventory"
                    and item.saved_records <= item.received_records
                    and item.record_quality.records == item.received_records
                    and item.record_quality.identified == item.saved_records
                    and item.value_access == "NOT_REQUESTED" and item.value_contract is None
                    and (not item.proves_completeness or item.status == "COMPLETE"))
        if (item.record_type != "entity_observation" or item.value_match is not None or item.permissions
                or item.effective_at is not None or any(fact.state != "PRESENT" for fact in item.facts)):
            return False
        # Rebuild the observation from its own kept fields: extra facts or forged states fail.
        values = record_values(item.model_dump())
        if set(values) - _FIELDS or "authorization_id" not in values or values.get("status") not in ("valid", "invalid"):
            return False
        uuid_text(values["authorization_id"])
        rebuilt = project(spec, item.scope, values, observed_at=item.provenance.observed_at)
        return (rebuilt.identity == item.identity and rebuilt.facts == item.facts
                and rebuilt.provider_state == item.provider_state
                and rebuilt.normalized_state == item.normalized_state and rebuilt.state_basis == item.state_basis)
    except (ValueError, TypeError, AttributeError, KeyError, OverflowError):
        return False


validate_machine_record = validate_record


def _initial(spec):
    return {"provider": "azure_devops", "version": 1, "config_hash": digest(spec.model_dump()),
            **dict.fromkeys(_COUNTS, 0), "phase": "users", "users_cursor": "", "tokens_cursor": "",
            "members": [], "reasons": [], "op_reasons": []}


def _state(spec, checkpoint):
    state = deepcopy(checkpoint) if checkpoint else _initial(spec)
    base = _initial(spec)
    members = state.get("members")
    if (not isinstance(state, dict) or set(state) != set(base) or state["provider"] != "azure_devops"
            or state["version"] != 1 or state["config_hash"] != base["config_hash"]
            or any(type(state[key]) is not int or state[key] < 0 for key in _COUNTS)
            or state["task"] > len(spec.scopes) or state["phase"] not in ("users", "tokens")
            or state["requests"] > spec.max_requests or state["pages"] > spec.max_pages
            or state["records"] > spec.max_records or state["saved"] > state["received"]
            or not isinstance(members, list) or len(members) > 5000 or state["user"] > len(members)
            or any(not isinstance(member, dict) or set(member) - {"descriptor", "name", "email", "origin", "origin_id"}
                   or not DESCRIPTOR.fullmatch(str(member.get("descriptor", ""))) for member in members)
            or any(state[key] and not isinstance(state[key], str) for key in ("users_cursor", "tokens_cursor"))
            or any(not isinstance(state[key], list) or len(state[key]) > 100 or any(not _reason(v) for v in state[key])
                   for key in ("reasons", "op_reasons"))):
        raise ValueError("AZURE_DEVOPS_CHECKPOINT_MISMATCH")
    for key in ("users_cursor", "tokens_cursor"):
        if state[key]:
            cursor_text(state[key])
    return checkpoint_json(state)


def _degrade(state, code):
    state["reasons"] = sorted({*state["reasons"], code})
    state["op_reasons"] = sorted({*state["op_reasons"], code})


def _advance_scope(state):
    state["task"] += 1
    for key in ("user", "retries", "op_pages", "received", "saved", "invalid", "duplicates"):
        state[key] = 0
    state.update(phase="users", users_cursor="", tokens_cursor="", members=[], op_reasons=[])


def _replay(spec, read_records, state):
    seen, count = set(), 0
    for raw in read_records() if read_records is not None else ():
        count += 1
        item = RECORD_ADAPTER.validate_python(raw)
        if not validate_record(spec, item):
            raise ValueError("AZURE_DEVOPS_REPLAY_RECORD_REJECTED")
        if item.record_type == "entity_observation":
            seen.add((item.scope.id, item.identity.object_id))
    if count != state["records"]:
        raise ValueError("AZURE_DEVOPS_REPLAY_COUNT_MISMATCH")
    return seen


def _member(row):
    """A Graph user as the checkpoint keeps it: descriptor, display identity and, for a
    Microsoft Entra user, its object id (originId), which names the person in Entra ID."""
    descriptor = row.get("descriptor") if isinstance(row, dict) else None
    if not isinstance(descriptor, str) or not DESCRIPTOR.fullmatch(descriptor):
        raise ValueError("AZURE_DEVOPS_INVALID_USER")
    member = {"descriptor": descriptor}
    for key, field in (("name", "principalName"), ("email", "mailAddress")):
        if isinstance(row.get(field), str) and row[field] and len(row[field]) <= 256:
            member[key] = row[field]
    if row.get("origin") in ORIGINS:
        member["origin"] = row["origin"]
        if row["origin"] == "aad" and isinstance(row.get("originId"), str) and GUID.fullmatch(row["originId"].lower()):
            member["origin_id"] = row["originId"].lower()
    return member


def collect_pages(spec, *, secrets, checkpoint, check, read_records=None, client=None, now=None, sleep=None):
    if not isinstance(spec, MetadataConnectionSpec):
        spec = MetadataConnectionSpec.model_validate(spec)
    validate_spec(spec)
    from cremore_azure_provider import app_certificate as certificate

    if spec.auth_type != "token":
        # The Microsoft connection's app: tokens for Azure DevOps from its certificate or the worker's identity.
        if bool(secrets) != certificate.signs_in(spec):
            raise ValueError("AZURE_DEVOPS_TOKEN_REQUIRED")
    elif (set(secrets) != {"token"} or not isinstance(secrets["token"], str) or not secrets["token"]
            or len(secrets["token"]) > 4096 or any(char.isspace() for char in secrets["token"])):
        raise ValueError("AZURE_DEVOPS_TOKEN_REQUIRED")
    state = _state(spec, checkpoint)
    if checkpoint and read_records is None:
        raise ValueError("AZURE_DEVOPS_RECORD_REPLAY_REQUIRED")
    seen = _replay(spec, read_records, state)
    own_client = client is None
    if own_client:
        import httpx

        client = httpx.Client(timeout=spec.options.timeout_seconds, follow_redirects=False)
    if spec.auth_type == "token":
        secret = secrets["token"]
    elif certificate.signs_in(spec):
        secret = certificate.TokenSource(secrets, certificate.SCOPES["devops"], client=client)
    else:
        from cremore_azure_provider.metadata.transport import default_token

        secret = default_token(certificate.SCOPES["devops"])
    transport = Transport(client, spec, secret, check, requests=state["requests"],
                          **({"sleep": sleep} if sleep else {}))
    try:
        while state["task"] < len(spec.scopes):
            check()
            previous = deepcopy(state)
            scope = spec.scopes[state["task"]]
            stamp = (now or datetime.now(UTC)).isoformat()
            if state["pages"] >= spec.max_pages:
                _degrade(state, "PAGE_BUDGET_EXCEEDED")
                break
            records, finished, requested = [], False, False
            try:
                if state["phase"] == "users":
                    requested = True
                    rows, following = transport.users(scope, state["users_cursor"])
                    members = []
                    for row in rows:
                        try:
                            members.append(_member(row))
                        except ValueError:
                            state["invalid"] += 1
                            _degrade(state, "AZURE_DEVOPS_INVALID_USER")
                    state.update(members=members, user=0, users_cursor=following, phase="tokens")
                else:
                    member = state["members"][state["user"]] if state["user"] < len(state["members"]) else None
                    if member is not None:
                        requested = True
                        rows, following = transport.personal_access_tokens(scope, member["descriptor"],
                                                                           state["tokens_cursor"])
                        state["received"] += len(rows)
                        for row in rows:
                            try:
                                item = token_observation(spec, scope, row, member, observed_at=stamp)
                                if not validate_record(spec, item):
                                    raise ValueError("AZURE_DEVOPS_INVALID_RECORD")
                            except (ValueError, TypeError, AttributeError, OverflowError):
                                state["invalid"] += 1
                                _degrade(state, "AZURE_DEVOPS_INVALID_RECORD")
                                continue
                            key = (scope.id, item.identity.object_id)
                            if key in seen:
                                state["duplicates"] += 1
                                continue
                            if any(o.reason == "TOKEN_VALUE_NOT_COLLECTED" for o in item.omissions):
                                _degrade(state, "AZURE_DEVOPS_TOKEN_VALUE_OMITTED")
                            records.append(item)
                            seen.add(key)
                        state["saved"] += len(records)
                        state["tokens_cursor"] = following
                        if not following:
                            state["user"] += 1
            except ReadError as exc:
                state["requests"] = transport.requests
                if exc.retryable and state["retries"] < min(spec.options.max_retries,
                                                            spec.options.max_consecutive_rate_limits):
                    state["retries"] += 1
                    yield MetadataPage(checkpoint=deepcopy(state), status="WAITING", reasons=[exc.code],
                                       retry_after_seconds=exc.retry_after)
                    return
                _degrade(state, exc.code)
                if exc.retryable:
                    _degrade(state, "AZURE_DEVOPS_RETRY_LIMIT")
                if state["phase"] == "tokens" and exc.code == "AZURE_DEVOPS_HTTP_404":
                    # The user left the organization after it was listed; nothing more to read for it.
                    state.update(tokens_cursor="", user=state["user"] + 1)
                else:
                    finished = True
            else:
                state["requests"] = transport.requests
                if requested:
                    state["pages"] += 1
                    state["op_pages"] += 1
                    state["retries"] = 0
            if (not finished and state["phase"] == "tokens" and state["user"] >= len(state["members"])):
                if state["users_cursor"]:
                    state["phase"] = "users"
                else:
                    finished = True
            if finished:
                status = "PARTIAL" if state["op_reasons"] and state["op_pages"] else "FAILED" if state["op_reasons"] else "COMPLETE"
                records.append(report(scope, observed_at=stamp, status=status, reasons=state["op_reasons"],
                                      pages=state["op_pages"], received=state["received"], saved=state["saved"],
                                      invalid=state["invalid"], duplicates=state["duplicates"],
                                      complete=status == "COMPLETE"))
            if state["records"] + len(records) > spec.max_records:
                requests, pages = state["requests"], state["pages"]
                state = previous
                state["requests"], state["pages"] = requests, pages
                _degrade(state, "RECORD_BUDGET_EXCEEDED")
                break
            for item in records:
                if not validate_record(spec, item):
                    raise ValueError("AZURE_DEVOPS_RECORD_REJECTED")
            state["records"] += len(records)
            if finished:
                _advance_scope(state)
            check()
            yield MetadataPage(records=records, checkpoint=deepcopy(state))
        status = "COMPLETE" if not state["reasons"] else "PARTIAL" if state["pages"] else "FAILED"
        yield MetadataPage(checkpoint=deepcopy(state), status=status, reasons=state["reasons"])
    finally:
        transport.secret = ""
        if own_client:
            client.close()


def native_snapshots(records):
    groups = {}
    for item in records or []:
        if item.get("provenance", {}).get("operation") != operation():
            continue
        scope = item.get("scope", {}).get("id", "")
        target = groups.setdefault(scope, {"organization": scope, "source": SOURCES[0], "api_version": TOKEN_API_VERSION,
                                           "records": [], "reports": [], "credential_match": "UNAVAILABLE",
                                           "match_reason": "TOKEN_VALUES_AND_HASHES_NOT_RETURNED"})
        if item.get("record_type") == "entity_observation":
            target["records"].append(record_values(item))
        elif item.get("record_type") == "operation_report":
            target["reports"].append(item)
    return list(groups.values())
