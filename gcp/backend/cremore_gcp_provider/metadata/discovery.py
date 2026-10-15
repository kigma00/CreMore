"""Bounded Resource Manager v3 hierarchy discovery; it grants no project access.

Only the explicitly approved organization/folder is a collection scope. Every
descendant keeps that scope and is a resource, never an issued credential. The
queue is rebuilt from committed parent/child observations after a restart.
"""

from __future__ import annotations

import math
import re
from copy import deepcopy

from cremore_gcp.resources import PROJECT_RE

# Integration: moved from cremore.coverage.providers.facts, whose package import ran the adapter
# registry (every provider) and the coverage store; this module loads neither.
from cremore.coverage.facts import FactWriter
from cremore.coverage.metadata_models import (
    RECORD_ADAPTER,
    EntityObservation,
    MetadataPage,
    checkpoint_json,
    in_metadata_scope,
)
from cremore.coverage.models import digest
from cremore_gcp_provider.gcp_auth import TRANSIENT_AUTH_CODES, GcpAuthError

from . import CONTRACT_VERSION, SOURCE_COMMIT
from .collector import response_pages, time_value
from .normalization import identity, provenance, record_values, report
from .transport import DEFERRED, ApiError, Budget, Transport, adc_token

BASE = "https://cloudresourcemanager.googleapis.com/v3/"
_NUMBER = re.compile(r"[1-9][0-9]{0,19}")
_PARENT = re.compile(r"(?:organizations|folders)/[1-9][0-9]{0,19}")
_RESOURCE = re.compile(r"(?:projects|folders)/[1-9][0-9]{0,19}")
_KINDS = ("projects", "folders")
_OPERATIONS = {"gcp.resource_manager." + kind: kind for kind in _KINDS}


def validate_discovery_spec(spec):
    if (len(spec.scopes) != 1 or spec.scopes[0].kind not in {"organization", "folder"}
            or not _NUMBER.fullmatch(spec.scopes[0].id)):
        raise ValueError("GCP_DISCOVERY_ROOT_REQUIRED")
    if set(spec.capabilities) != {"inventory"}:
        raise ValueError("GCP_DISCOVERY_INVENTORY_ONLY")
    if (spec.options.include_values or spec.options.locations
            or spec.options.audit_lookback_days is not None or spec.options.sources
            or spec.options.include_provider_hashes):
        raise ValueError("GCP_DISCOVERY_OPTION_NOT_SUPPORTED")


def root_name(spec):
    scope = spec.scopes[0]
    return ("organizations/" if scope.kind == "organization" else "folders/") + scope.id


def validate_discovery_record(spec, item):
    if (item.scope != spec.scopes[0] or item.purpose != "issuer_inventory"
            or item.provenance.contract_version != CONTRACT_VERSION
            or item.provenance.source_commit != SOURCE_COMMIT
            or item.provenance.operation not in _OPERATIONS
            or not in_metadata_scope(spec, item)):
        return False
    values = record_values(item)
    if values.get("selection") != "context_only":
        return False
    if item.record_type == "entity_observation":
        name = values.get("resource_name")
        parent = values.get("parent_id")
        kind = _OPERATIONS[item.provenance.operation]
        return (item.identity.kind == "resource" and item.value_match is None
                and isinstance(name, str) and bool(_RESOURCE.fullmatch(name))
                and name.startswith(kind + "/")
                and item.identity.object_id == name and item.provenance.resource_id == name
                and isinstance(parent, str) and bool(_PARENT.fullmatch(parent))
                and (kind != "projects" or isinstance(values.get("project_id"), str)
                     and len(values["project_id"]) <= 30
                     and bool(PROJECT_RE.fullmatch(values["project_id"]))))
    return (item.record_type == "operation_report" and not item.proves_completeness
            and item.value_access == "NOT_REQUESTED" and item.value_contract is None
            and bool(_PARENT.fullmatch(item.provenance.resource_id)))


def _observation(spec, kind, parent, row):
    name = row.get("name")
    if (not isinstance(name, str) or not _RESOURCE.fullmatch(name)
            or not name.startswith(kind + "/")):
        return None, "GCP_INVALID_DISCOVERY_RESOURCE"
    if row.get("parent") != parent:
        return None, "GCP_DISCOVERY_PARENT_MISMATCH"
    if kind == "projects" and (not isinstance(row.get("projectId"), str)
                              or len(row["projectId"]) > 30
                              or not PROJECT_RE.fullmatch(row["projectId"])):
        return None, "GCP_INVALID_DISCOVERY_PROJECT_ID"
    values = {"resource_name": name, "parent_id": parent, "selection": "context_only",
              "resource_type": kind[:-1]}
    if kind == "projects":
        values.update(project_id=row["projectId"], project_number=name.split("/")[1])
    display_name = row.get("displayName")
    if isinstance(display_name, str) and len(display_name) <= 256:
        values["display_name"] = display_name
    for source, target in (("createTime", "created_at"), ("updateTime", "updated_at"),
                           ("deleteTime", "deleted_at")):
        if value := time_value(row.get(source)):
            values[target] = value
    state = row.get("state")
    if state not in {"ACTIVE", "DELETE_REQUESTED", "STATE_UNSPECIFIED"}:
        state = "UNKNOWN"
    values["state"] = state
    writer = FactWriter()
    result = EntityObservation(
        scope=spec.scopes[0], purpose="issuer_inventory", identity=identity(spec, "resource", name),
        provenance=provenance("gcp.resource_manager." + kind, name),
        facts=writer.facts(values), omissions=writer.omissions, provider_state=state,
        normalized_state="ACTIVE" if state == "ACTIVE" else "UNKNOWN",
        state_basis="PROVIDER_REPORTED" if state != "UNKNOWN" else "UNKNOWN",
    )
    return result, "GCP_INVALID_DISCOVERY_METADATA" if writer.omissions or state == "UNKNOWN" else None


def _replay(spec, records):
    """Authenticate traversal ancestry through committed records, not a cursor queue."""
    root = root_name(spec)
    parents, seen, completed, page_counts = [root], {root}, set(), {}
    pending, incomplete = [], set()
    for raw in records:
        item = RECORD_ADAPTER.validate_python(raw)
        if not validate_discovery_record(spec, item):
            raise ValueError("GCP_DISCOVERY_REPLAY_INVALID")
        if item.record_type == "entity_observation":
            pending.append(item)
            continue
        key = (item.provenance.resource_id, _OPERATIONS[item.provenance.operation])
        if key in completed:
            raise ValueError("GCP_DISCOVERY_REPLAY_INVALID")
        page_counts[key] = page_counts.get(key, 0) + item.pages
        if record_values(item).get("completed") is True:
            completed.add(key)
            incomplete.discard(key)
        else:
            incomplete.add(key)
    # Parents always precede their descendants in this traversal. Replaying
    # records out of ancestry order is unnecessary and must not widen the root.
    for item in pending:
        values = record_values(item)
        name, parent = values["resource_name"], values["parent_id"]
        if parent not in parents or name in seen:
            raise ValueError("GCP_DISCOVERY_REPLAY_INVALID")
        seen.add(name)
        if name.startswith("folders/") and item.provider_state == "ACTIVE":
            parents.append(name)
    if any(parent not in parents for parent, _ in page_counts) or len(incomplete) > 1:
        raise ValueError("GCP_DISCOVERY_REPLAY_INVALID")
    return parents, seen, completed, page_counts, incomplete


def _state(spec, checkpoint, records):
    state = deepcopy(checkpoint or {})
    config_hash = digest(spec.model_dump())
    if not state:
        if records:
            raise ValueError("GCP_DISCOVERY_CHECKPOINT_REQUIRED")
        return {"version": 1, "provider": "gcp", "mode": "discovery",
                "config_hash": config_hash, "cursor": {}, "requests": 0, "emitted": 0,
                "pages": 0, "finished": False, "reasons": []}
    if (state.get("version") != 1 or state.get("provider") != "gcp"
            or state.get("mode") != "discovery" or state.get("config_hash") != config_hash):
        raise ValueError("GCP_CHECKPOINT_MISMATCH")
    if set(state) != {"version", "provider", "mode", "config_hash", "cursor", "requests",
                      "emitted", "pages", "finished", "reasons"}:
        raise ValueError("GCP_DISCOVERY_CHECKPOINT_INVALID")
    if any(type(state.get(key)) is not int or state[key] < 0
           for key in ("requests", "emitted", "pages")):
        raise ValueError("GCP_DISCOVERY_CHECKPOINT_INVALID")
    if (state["emitted"] != len(records) or state["emitted"] > spec.max_records
            or state["pages"] > spec.max_pages or not state["pages"] <= state["requests"] <= spec.max_requests
            or type(state.get("finished")) is not bool
            or not isinstance(state.get("reasons"), list)
            or len(state["reasons"]) > 100
            or any(not isinstance(x, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", x)
                   for x in state["reasons"])):
        raise ValueError("GCP_DISCOVERY_CHECKPOINT_INVALID")
    return state


def _cursor(state, parents, completed, page_counts, incomplete):
    cursor = state.get("cursor")
    if not isinstance(cursor, dict) or state["pages"] != sum(page_counts.values()):
        raise ValueError("GCP_DISCOVERY_CHECKPOINT_INVALID")
    if not cursor:
        if incomplete:
            raise ValueError("GCP_DISCOVERY_CHECKPOINT_INVALID")
        return
    key = (cursor.get("parent"), cursor.get("kind"))
    if (set(cursor) != {"parent", "kind", "page", "page_token", "seen"}
            or key[0] not in parents or key[1] not in _KINDS or key in completed
            or incomplete != {key} or type(cursor.get("page")) is not int
            or cursor["page"] != page_counts.get(key)
            or not isinstance(cursor.get("page_token"), str)
            or not 1 <= len(cursor["page_token"]) <= 8192
            or not isinstance(cursor.get("seen"), list)
            or len(cursor["seen"]) != cursor["page"]
            or any(not isinstance(x, str) or not 1 <= len(x) <= 8192 for x in cursor["seen"])
            or len(set(cursor["seen"])) != len(cursor["seen"])
            or cursor["page_token"] not in cursor["seen"]):
        raise ValueError("GCP_DISCOVERY_CHECKPOINT_INVALID")


def collect_discovery_pages(spec, *, checkpoint, check, read_records=None,
                            transport=None, client=None, token=None):
    if checkpoint and read_records is None:
        raise ValueError("GCP_RECORD_REPLAY_REQUIRED")
    records = list(read_records()) if read_records else []
    state = _state(spec, checkpoint, records)
    parents, seen, completed, counts, incomplete = _replay(spec, records)
    _cursor(state, parents, completed, counts, incomplete)
    reasons = set(state["reasons"])
    for item in records:
        if item.get("record_type") == "operation_report":
            reasons.update(item.get("reasons", []))

    def saved_state():
        state["reasons"] = sorted(reasons)
        return checkpoint_json(state)

    def finish():
        state["finished"] = True
        return MetadataPage(checkpoint=saved_state(),
                            status="PARTIAL" if reasons else "COMPLETE", reasons=sorted(reasons))

    if state["finished"]:
        if (any((parent, kind) not in completed for parent in parents for kind in _KINDS)
                and not reasons.intersection({"TARGET_BUDGET_EXCEEDED", "PAGE_BUDGET_EXCEEDED",
                                              "REQUEST_BUDGET_EXCEEDED", "RECORD_BUDGET_EXCEEDED"})):
            raise ValueError("GCP_DISCOVERY_CHECKPOINT_INVALID")
        yield finish()
        return
    own_client = transport is None and client is None
    prior_requests = state["requests"]
    try:
        check()
        if prior_requests >= spec.max_requests:
            raise Budget("REQUEST_BUDGET_EXCEEDED")
        if transport is None:
            import httpx

            client = client or httpx.Client(timeout=spec.options.timeout_seconds, follow_redirects=False)
            token_source = token or adc_token()
            token_source()
            transport = Transport(client, token_source, options=spec.options,
                                  max_requests=spec.max_requests - prior_requests, check=check)
        transport_start = transport.requests
        while True:
            check()
            if len(parents) > spec.options.max_targets:
                reasons.add("TARGET_BUDGET_EXCEEDED")
            allowed_parents = parents[:spec.options.max_targets]
            tasks = [(parent, kind) for parent in allowed_parents for kind in _KINDS
                     if (parent, kind) not in completed]
            if not tasks:
                yield finish()
                return
            cursor = state["cursor"]
            parent, kind = (cursor["parent"], cursor["kind"]) if cursor else tasks[0]
            if (parent, kind) not in tasks:
                raise ValueError("GCP_DISCOVERY_CHECKPOINT_INVALID")
            if state["pages"] >= spec.max_pages:
                raise Budget("PAGE_BUDGET_EXCEEDED")
            if state["requests"] >= spec.max_requests:
                raise Budget("REQUEST_BUDGET_EXCEEDED")

            def request(page_token, parent=parent, kind=kind):
                params = {"parent": parent, "pageSize": spec.options.page_size,
                          "showDeleted": "true" if spec.options.include_deleted else "false"}
                if page_token:
                    params["pageToken"] = page_token
                return transport.get(BASE + kind, params)

            try:
                page = next(response_pages(request, kind, max_pages=spec.max_pages, cursor=cursor))
            finally:
                state["requests"] = prior_requests + transport.requests - transport_start
            rows, page_reasons, new_parents, new_names = [], set(), [], set()
            for raw in page.rows:
                item, reason = _observation(spec, kind, parent, raw)
                if reason:
                    page_reasons.add(reason)
                if item is None:
                    continue
                name = item.identity.object_id
                if name in seen or name in new_names:
                    page_reasons.add("GCP_DUPLICATE_DISCOVERY_RESOURCE")
                    continue
                new_names.add(name)
                rows.append(item)
                if kind == "folders" and item.provider_state == "ACTIVE":
                    new_parents.append(name)
            if page.error:
                page_reasons.add(page.error.upper())
            if page.cursor and len(page.cursor["page_token"]) > 8192:
                page.cursor = None
                page_reasons.add("INVALID_PAGE_TOKEN")
            next_cursor = ({**page.cursor, "parent": parent, "kind": kind} if page.cursor else {})
            try:
                checkpoint_json(next_cursor)
            except ValueError:
                next_cursor = {}
                page_reasons.add("INVALID_PAGE_TOKEN")
            page_increment = max(0, page.pages - int(cursor.get("page", 0)))
            rows.append(report(
                spec, spec.scopes[0], "gcp.resource_manager." + kind, resource_id=parent,
                status="PARTIAL" if page_reasons else "UNKNOWN" if next_cursor else "COMPLETE",
                reasons=page_reasons, pages=page_increment, received=page.received, saved=len(rows),
                facts={"selection": "context_only", "completed": not bool(next_cursor)},
                shape="array",
            ))
            if state["emitted"] + len(rows) > spec.max_records:
                raise Budget("RECORD_BUDGET_EXCEEDED")
            if not all(validate_discovery_record(spec, item) for item in rows):
                raise ValueError("GCP_NORMALIZATION_FAILED")
            reasons.update(page_reasons)
            state["pages"] += page_increment
            state["emitted"] += len(rows)
            state["cursor"] = next_cursor
            parents.extend(new_parents)
            seen.update(new_names)
            if not next_cursor:
                completed.add((parent, kind))
            yield MetadataPage(records=rows, checkpoint=saved_state())
    except GcpAuthError as exc:
        if exc.code in TRANSIENT_AUTH_CODES:
            # Google's token service asked to retry (429, 5xx, unreachable): wait and resume this run
            # from its checkpoint like a throttled API read. Reauthorization codes still end the run.
            yield MetadataPage(checkpoint=saved_state(), status="WAITING", reasons=[exc.code],
                               retry_after_seconds=max(1, min(3600, math.ceil(exc.retry_after or 60))))
        else:
            yield MetadataPage(checkpoint=saved_state(), status="FAILED", reasons=[exc.code])
    except Budget as exc:
        reasons.add(exc.code)
        yield finish()
    except ApiError as exc:
        if exc.code in DEFERRED:
            yield MetadataPage(checkpoint=saved_state(), status="WAITING", reasons=[exc.code.upper()],
                               retry_after_seconds=max(1, min(3600, math.ceil(exc.retry_after or 60))))
        else:
            yield MetadataPage(checkpoint=saved_state(), status="FAILED", reasons=[exc.code.upper()])
    finally:
        if own_client and client is not None:
            client.close()


def native_discovery(records):
    resources, operations = [], []
    for item in records:
        if item.get("provenance", {}).get("operation") not in _OPERATIONS:
            continue
        if item.get("record_type") == "entity_observation":
            resources.append({"object_type": "resource", **record_values(item)})
        elif item.get("record_type") == "operation_report":
            operations.append({"operation": item["provenance"]["operation"],
                               "parent": item["provenance"]["resource_id"],
                               "status": item["status"], "reasons": item["reasons"],
                               "proves_completeness": False, **record_values(item)})
    return {"scope": "approved_hierarchy_context_only", "resources": resources,
            "operations": operations, "project_inventory_authorized": False}
