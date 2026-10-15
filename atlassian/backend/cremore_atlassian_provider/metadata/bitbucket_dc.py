"""Bitbucket Data Center 10.4 documented HTTP-token metadata listings.

Only approved user/project/repository scopes are read. No token value, creation,
mutation, undocumented endpoint or discovered-credential authentication is used.
"""

from __future__ import annotations

import datetime as _dt
import re
import time
from copy import deepcopy

from cremore.coverage.metadata_models import (
    EntityIdentity,
    EntityObservation,
    MetadataFact,
    MetadataPage,
    MetadataProvenance,
    OperationReport,
    timestamp,
)
from cremore.coverage.models import digest

from .http import BearerReadClient, Limits
from .metadata import utc_now
from .snapshot import metadata_snapshot
from .steps import CollectionInterrupted

CONTRACT = "bitbucket-dc-10.4-http-tokens-v1"
SEGMENT = re.compile(r"[A-Za-z0-9_~][A-Za-z0-9_.@~-]{0,254}")
TOKEN_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
OPERATIONS = {kind: f"dc-{kind}-http-tokens" for kind in ("user", "project", "repository")}
LIMITATION = "SELECTED_SCOPE_METADATA_ONLY"


def api_path(spec):
    path = spec.options.api_path
    if not re.fullmatch(r"(?:/[A-Za-z0-9_-]+)*", path):
        raise ValueError("BITBUCKET_DC_INVALID_CONTEXT_PATH")
    return path


def scope_path(scope):
    parts = scope.id.split("/")
    if (scope.kind not in OPERATIONS
            or len(parts) != (2 if scope.kind == "repository" else 1)
            or not all(SEGMENT.fullmatch(part) for part in parts)):
        raise ValueError("BITBUCKET_DC_INVALID_SCOPE")
    if scope.kind == "user":
        return "/users/" + parts[0]
    path = "/projects/" + parts[0]
    return path + "/repos/" + parts[1] if scope.kind == "repository" else path


def endpoint(spec, scope):
    return spec.origin + api_path(spec) + "/rest/access-tokens/latest" + scope_path(scope)


def validate_spec(spec):
    if spec.provider != "bitbucket" or spec.edition != "data_center":
        raise ValueError("BITBUCKET_DC_EDITION_REQUIRED")
    api_path(spec)
    if spec.auth_type != "bearer" or set(spec.secret_refs) != {"token"}:
        raise ValueError("BITBUCKET_DC_BEARER_REQUIRED")
    if (spec.options.mode != "inventory" or set(spec.capabilities) != {"inventory"}
            or spec.options.sources or spec.options.include_values
            or spec.options.include_actions):
        raise ValueError("BITBUCKET_DC_METADATA_LISTING_ONLY")
    if spec.principal_pin:
        raise ValueError("BITBUCKET_DC_PRINCIPAL_PIN_UNVERIFIABLE")
    for scope in spec.scopes:
        scope_path(scope)


class Client(BearerReadClient):
    def __init__(self, spec, scope, secrets, limits, check, **kwargs):
        validate_spec(spec)
        self.url = endpoint(spec, scope)
        self.page_size = min(spec.options.page_size, 1000)
        super().__init__(secrets["token"], limits, check=check,
                         max_response_bytes=spec.options.max_response_bytes, **kwargs)

    def fetch_page(self, start):
        if type(start) is not int or not 0 <= start <= 2147483647:
            raise ValueError("BITBUCKET_DC_INVALID_CURSOR")
        return self._request(f"{self.url}?start={start}&limit={self.page_size}")


def provenance(spec, scope, observed_at):
    return MetadataProvenance(operation=OPERATIONS[scope.kind], observed_at=observed_at,
                              resource_id=endpoint(spec, scope), contract_version=CONTRACT)


def identity(spec, scope, token_id):
    return EntityIdentity(provider="bitbucket", origin=spec.origin, tenant=spec.tenant,
                          tenant_confirmed=spec.tenant_confirmed, kind="credential",
                          object_id=f"dc:{api_path(spec)}:{scope.kind}:{scope.id}:{token_id}")


def observation(spec, scope, row, observed_at, sensitive):
    """The official RestAccessToken schema guarantees no expiry or permissions."""
    if not isinstance(row, dict):
        return None, True
    clean, _ = metadata_snapshot({key: row[key] for key in ("id", "name", "createdDate")
                                 if key in row}, sensitive_values=(sensitive,))
    token_id = clean.get("id")
    if not isinstance(token_id, str) or not TOKEN_ID.fullmatch(token_id):
        return None, True
    fields, invalid = [MetadataFact(name="id", value=token_id)], False
    for source, target in (("name", "name"), ("createdDate", "created_at")):
        state, value = "PRESENT", clean.get(source)
        if source not in clean:
            state, value = "MISSING", None
        elif value is None:
            state = "NULL"
        elif source == "createdDate" and type(value) is int and 0 <= value < 253402300800000:
            # The access-token REST reference serialises createdDate as epoch milliseconds.
            value = (_dt.datetime.fromtimestamp(value // 1000, _dt.UTC)
                     + _dt.timedelta(milliseconds=value % 1000)).isoformat()
        elif not isinstance(value, str) or len(value) > 512:
            state, value, invalid = "INVALID", None, True
        elif source == "createdDate":
            try:
                value = timestamp(value)
            except ValueError:
                state, value, invalid = "INVALID", None, True
        try:
            fields.append(MetadataFact(name=target, state=state, value=value,
                                       reason="INVALID_METADATA" if state == "INVALID" else None))
        except ValueError:
            fields.append(MetadataFact(name=target, state="INVALID", reason="INVALID_METADATA"))
            invalid = True
    return EntityObservation(scope=scope, identity=identity(spec, scope, token_id),
                             provenance=provenance(spec, scope, observed_at), facts=fields), invalid


def validate_record(spec, record):
    try:
        validate_spec(spec)
        scope = record.scope
        if (scope not in spec.scopes or record.purpose != "issuer_inventory"
                or record.provenance.contract_version != CONTRACT
                or record.provenance.source_commit is not None
                or record.provenance.provider_generated_at is not None
                or record.provenance.operation != OPERATIONS[scope.kind]
                or record.provenance.resource_id != endpoint(spec, scope)
                or record.omissions):
            return False
        if record.record_type == "operation_report":
            return (not record.proves_completeness and not record.facts
                    and record.value_access == "NOT_REQUESTED" and record.value_contract is None
                    and record.collection_mode == "inventory"
                    and record.report_type == "bitbucket_dc_http_token_listing")
        if record.record_type != "entity_observation":
            return False
        facts = {fact.name: fact for fact in record.facts}
        if set(facts) != {"id", "name", "created_at"}:
            return False
        token_id = facts["id"].value
        if (facts["id"].state != "PRESENT" or not isinstance(token_id, str)
                or not TOKEN_ID.fullmatch(token_id)):
            return False
        for name, fact in facts.items():
            if fact.container is not None or fact.children:
                return False
            if fact.state == "PRESENT":
                if not isinstance(fact.value, str) or len(fact.value) > 512:
                    return False
                if name == "created_at" and timestamp(fact.value) != fact.value:
                    return False
        return (record.identity == identity(spec, scope, token_id)
                and record.value_match is None and not record.permissions
                and record.normalized_state == "UNKNOWN" and record.provider_state == "UNKNOWN"
                and record.state_basis == "UNKNOWN" and record.effective_at is None)
    except (TypeError, ValueError, KeyError):
        return False


def current_record_status(spec, body, reports):
    if body.get("record_type") != "entity_observation":
        return None
    matching = [value.model_dump() if hasattr(value, "model_dump") else value for value in reports]
    matching = [report for report in matching if report.get("scope") == body.get("scope")
                and report.get("provenance", {}).get("contract_version") == CONTRACT
                and report.get("provenance", {}).get("resource_id")
                == body.get("provenance", {}).get("resource_id")]
    if len(matching) != 1:
        return None
    status = matching[0].get("status")
    return status if status in {"COMPLETE", "PARTIAL"} else None


def _state(spec, checkpoint, recollection_plan=None):
    config = spec.model_dump(exclude={"name", "secret_refs", "freshness_hours"})
    initial = {"version": 1, "provider": "bitbucket", "contract": CONTRACT,
               "config_hash": digest(config), "scope_index": 0, "start": 0, "pages": 0,
               "requests": 0, "records": 0, "scope_pages": 0, "received": 0, "saved": 0,
               "scope_reasons": [], "partial": False, "succeeded": False}
    if recollection_plan is not None:
        initial["recollection_hash"] = digest(recollection_plan)
    if not checkpoint:
        return initial
    if set(checkpoint) != set(initial) or any(checkpoint[key] != initial[key] for key in (
            "version", "provider", "contract", "config_hash")):
        raise ValueError("BITBUCKET_DC_CHECKPOINT_MISMATCH")
    if checkpoint.get("recollection_hash") != initial.get("recollection_hash"):
        raise ValueError("BITBUCKET_DC_CHECKPOINT_MISMATCH")
    for key in ("scope_index", "start", "pages", "requests", "records", "scope_pages", "received", "saved"):
        if type(checkpoint[key]) is not int or checkpoint[key] < 0:
            raise ValueError("BITBUCKET_DC_INVALID_CHECKPOINT")
    if (checkpoint["scope_index"] > len(spec.scopes) or checkpoint["start"] > 2147483647
            or checkpoint["saved"] > checkpoint["received"]
            or checkpoint["scope_pages"] > checkpoint["pages"]
            or checkpoint["records"] > min(spec.max_records, 100000)
            or checkpoint["pages"] > min(spec.max_pages, 1000)
            or checkpoint["requests"] > min(spec.max_requests, 1000)
            or any(type(checkpoint[key]) is not bool for key in ("partial", "succeeded"))
            or not isinstance(checkpoint["scope_reasons"], list)
            or set(checkpoint["scope_reasons"]) - {"INVALID_METADATA", "DUPLICATE_IDENTIFIERS"}):
        raise ValueError("BITBUCKET_DC_INVALID_CHECKPOINT")
    return deepcopy(checkpoint)


def _pagination(body, start):
    if (not isinstance(body, dict) or not isinstance(body.get("values"), list)
            or type(body.get("isLastPage")) is not bool
            or type(body.get("start")) is not int or body["start"] != start
            or type(body.get("size")) is not int or body["size"] != len(body["values"])):
        return None, "INVALID_PAGINATION"
    if body["isLastPage"]:
        return None, None
    following = body.get("nextPageStart")
    if type(following) is not int or not start < following <= 2147483647:
        return None, "INVALID_PAGINATION"
    return following, None


def collect_pages(spec, *, secrets, checkpoint, check, read_records=None, client_factory=None,
                  now=utc_now, recollection_plan=None):
    validate_spec(spec)
    selected = None
    if recollection_plan is not None:
        from .bitbucket_dc_replay import selected_scopes
        selected = selected_scopes(spec, recollection_plan)
    if set(secrets) != {"token"}:
        raise ValueError("BITBUCKET_DC_BEARER_REQUIRED")
    state = _state(spec, checkpoint, recollection_plan)
    if checkpoint and read_records is None:
        raise ValueError("BITBUCKET_DC_COMMITTED_RECORD_READER_REQUIRED")
    committed = list(read_records()) if read_records else []
    limits = Limits(max_pages=min(spec.max_pages, 1000), max_records=min(spec.max_records, 100000),
                    max_requests=min(spec.max_requests, 1000), retries=min(spec.options.max_retries, 5),
                    timeout=min(spec.options.timeout_seconds, 30))
    factory = client_factory or Client
    deadline = time.monotonic() + limits.max_seconds
    try:
        for index in range(state["scope_index"], len(spec.scopes)):
            check()
            scope = spec.scopes[index]
            if selected is not None and (scope.kind, scope.id) not in selected:
                state.update(scope_index=index + 1, partial=True)
                yield MetadataPage(records=[OperationReport(
                    scope=scope, provenance=provenance(spec, scope, now()), status="NOT_REQUESTED",
                    reasons=[LIMITATION, "NOT_SELECTED_FOR_RECOLLECTION"], collection_mode="inventory",
                    report_type="bitbucket_dc_http_token_listing")], checkpoint=deepcopy(state))
                continue
            client = factory(spec, scope, secrets, limits, check)
            client.restrict_time(max(0, deadline - time.monotonic()))
            client.requests = state["requests"]
            seen = set()
            for record in committed:
                record = record.model_dump() if hasattr(record, "model_dump") else record
                if record.get("scope") == scope.model_dump() and record.get("record_type") == "entity_observation":
                    seen.add(record["identity"]["object_id"])
            reason = None
            while True:
                check()
                records = []
                if state["pages"] >= limits.max_pages:
                    reason = "PAGE_LIMIT"
                    break
                if state["records"] >= limits.max_records:
                    reason = "RECORD_LIMIT"
                    break
                response = client.fetch_page(state["start"])
                state["requests"] = client.requests
                if response.reason or response.status != 200:
                    reason = (response.reason.upper() if response.reason in {
                        "request_limit", "time_limit", "response_too_large", "transport_error",
                        "invalid_json", "retry_wait_exceeds_limit",
                    } else "HTTP_" + str(response.status) if type(response.status) is int
                              else "COLLECTION_FAILED")
                    break
                body = response.body
                following, reason = _pagination(body, state["start"])
                rows = body.get("values") if isinstance(body, dict) else None
                if not isinstance(rows, list) or len(rows) > min(spec.options.page_size, 1000):
                    reason = "INVALID_RESPONSE"
                    break
                state["pages"] += 1
                state["scope_pages"] += 1
                state["received"] += len(rows)
                state["succeeded"] = True
                for row in rows:
                    check()
                    if state["records"] >= limits.max_records:
                        reason = "RECORD_LIMIT"
                        break
                    record, invalid = observation(spec, scope, row, now(), secrets["token"])
                    if invalid:
                        state["scope_reasons"] = sorted(set(state["scope_reasons"]) | {"INVALID_METADATA"})
                    if record is None:
                        continue
                    if record.identity.object_id in seen:
                        state["scope_reasons"] = sorted(set(state["scope_reasons"]) | {"DUPLICATE_IDENTIFIERS"})
                    seen.add(record.identity.object_id)
                    records.append(record)
                    state["records"] += 1
                    state["saved"] += 1
                if reason or following is None:
                    break
                state["start"] = following
                check()
                yield MetadataPage(records=records, checkpoint=deepcopy(state))
            # Publish the terminal page and its report in one durable batch. A
            # resumed reader never confuses an unfinished scope with an empty one.
            reasons = sorted(set(state["scope_reasons"]) | ({reason} if reason else set()))
            status = ("PARTIAL" if state["scope_pages"] else "FAILED") if reasons else "COMPLETE"
            state["partial"] |= status != "COMPLETE"
            report = OperationReport(scope=scope, provenance=provenance(spec, scope, now()),
                                     status=status, reasons=[LIMITATION, *reasons],
                                     pages=state["scope_pages"], received_records=state["received"],
                                     saved_records=state["saved"], collection_mode="inventory",
                                     report_type="bitbucket_dc_http_token_listing")
            state.update(scope_index=index + 1, start=0, scope_pages=0, received=0, saved=0,
                         scope_reasons=[])
            check()
            yield MetadataPage(records=[*records, report],
                               checkpoint=deepcopy(state))
        status = "PARTIAL" if state["partial"] and state["succeeded"] else "FAILED" if state["partial"] else "COMPLETE"
        check()
        yield MetadataPage(checkpoint=deepcopy(state), status=status, reasons=[LIMITATION])
    except CollectionInterrupted as interrupted:
        raise interrupted.cause from None
