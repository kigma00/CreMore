"""Scan-scope selection: catalogs, approved profiles, drafts, plans and runs.

The console (web/console/views/integrations/targets.tsx, a credential panel's rescan) works from a
*catalog* of a connection's resources (metadata only — listing never approves
content), an Admin-saved *profile* of exact resource ids with per-resource
options, a fixed *plan* previewing what a run would read, and *runs* that
execute one plan under its budgets. This module holds the pure logic; the
dashboard routes and the worker call into it.
"""

from __future__ import annotations

import copy
import datetime as _dt
import hashlib
import json
import re
import uuid

from cremore.collectors.base import path_under
from cremore.domain.models import ScopeCatalog, ScopePlan, ScopeProfile, SelectionDraft
from cremore.sources.registry import BY_RESOURCE_TYPE, BY_SOURCE, EXACT_FIELDS, PROVIDERS

RESOURCE_TYPES = tuple(EXACT_FIELDS)
SELECTABLE_READINESS = ("READY", "NEEDS_RUNTIME_CHECK", "NOT_PROBED")
PAGE_MODES = ("PAGE_ONLY", "PAGE_WITH_DESCENDANTS", "DATA_SOURCE_SELECTED_PAGES")
SORTS = ("name_asc", "name_desc", "updated_desc")
PLAN_TTL = _dt.timedelta(minutes=15)
DRAFT_TTL = _dt.timedelta(minutes=30)
MAX_ROOTS = 10_000
MAX_PAGE = 200
MAX_BUDGET = {"bytes": 1 << 40, "requests": 10_000_000, "seconds": 7 * 24 * 3600}
DEFAULT_BUDGET = {"bytes": 536_870_912_000, "requests": 2_000_000, "seconds": 21_600}
NOT_RECORDED = "0001-01-01T00:00:00Z"
_COMMON_FILTERS = ["q", "resource_type", "access_status", "last_sync_status", "last_scan_status",
                   "synced_after", "synced_before", "scanned_after", "scanned_before", "selected", "exclude"]
FILTERS = {provider: _COMMON_FILTERS + list(module.FILTERS) for provider, module in PROVIDERS.items()}
_DATE_FILTERS = {"edited_after": ("last_edited_at", False), "edited_before": ("last_edited_at", True),
                 "synced_after": ("last_synced_at", False), "synced_before": ("last_synced_at", True),
                 "scanned_after": ("last_scan_at", False), "scanned_before": ("last_scan_at", True)}
_EXACT_FILTERS = ("resource_type", "account_id", "region", "organization_id", "visibility", "parent_id", "language")
_STRING_KEYS = ("prefixes", "excluded_prefixes", "paths", "excluded_paths", "descendant_ids")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class ScopeError(ValueError):
    def __init__(self, code: str, message: str = "", *, http_status: int = 422) -> None:
        super().__init__(message or code)
        self.code = code
        self.http_status = http_status


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


def _iso(value) -> str | None:
    return value.isoformat() if isinstance(value, _dt.datetime) else None


def parse_stamp(value) -> _dt.datetime | None:
    """ISO-8601 with any fractional precision (the dashboard sends nine digits)."""

    if not isinstance(value, str) or not value:
        return None
    text = re.sub(r"(\.\d{6})\d+", r"\1", value.replace("Z", "+00:00"))
    try:
        parsed = _dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=_dt.UTC)


# --- resources ---------------------------------------------------------------


def resource_id(kind: str, connection_id, resource_type: str, provider_resource_id: str) -> str:
    """A stable, opaque id for one resource of one connection."""

    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"cremore:scope:{kind}:{connection_id}:{resource_type}:{provider_resource_id}"))


def root_identity(connection_id, root):
    """Durable checkpoint identity; retain the original fields and serialization."""
    fields = (
        "resource_type", "provider_resource_id", "all_current_objects", "prefixes",
        "excluded_prefixes", "paths", "excluded_paths", "ref", "page_mode", "descendant_ids",
    )
    value = [str(connection_id), {key: root.get(key) for key in fields}]
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def resource(kind: str, connection_id, resource_type: str, provider_resource_id: str, display_name: str,
             canonical_reference: str, provider_instance_id: str, *, now: _dt.datetime | None = None, **extra) -> dict:
    """One ScopeResource as the dashboard reads it. Metadata only."""

    out = {
        "id": resource_id(kind, connection_id, resource_type, provider_resource_id),
        "provider_resource_id": provider_resource_id, "resource_type": resource_type,
        "display_name": display_name or provider_resource_id, "canonical_reference": canonical_reference,
        "provider_instance_id": provider_instance_id, "visibility": "UNKNOWN", "list_visibility": "VISIBLE",
        "content_readiness": "NOT_PROBED", "last_sync_status": "METADATA_OBSERVED",
        "last_synced_at": (now or _now()).isoformat(), "subtree_expansion_allowed": False,
    }
    out.update({k: v for k, v in extra.items() if v is not None})
    return out


def selectable(item: dict) -> bool:
    return item.get("list_visibility") == "VISIBLE" and item.get("content_readiness") in SELECTABLE_READINESS \
        and item.get("resource_type") in RESOURCE_TYPES


def provider_of(kind: str, target) -> str:
    return "aws" if kind == "aws" else (target.provider or "").lower()


def auth_revision(kind: str, target) -> str:
    """Changes when the connection's *authorization* changes (a different
    credential or role), not on every re-check of the same one."""

    if kind == "aws":
        parts = ("aws", str(target.id), target.scanner_role_arn or "", target.external_id or "", target.validation_status)
        if getattr(target, "access", "ROLE") != "ROLE":  # appended only when set, so existing approvals stay bound
            parts += (target.access,)
    else:
        evidence = target.credential_evidence or {}
        parts = ("source", str(target.id), target.secret_ref or "", str(evidence.get("revoked_at") or ""),
                 str(evidence.get("owner") or ""), str(evidence.get("workspace") or ""))
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def new_snapshot_id() -> str:
    return uuid.uuid4().hex


def apply_refresh(existing: list[dict], listed: list[dict], *, replace: bool) -> list[dict]:
    if replace:
        return list(listed)
    merged = {item["id"]: item for item in existing}
    for item in listed:
        merged[item["id"]] = item
    return list(merged.values())


# --- catalog queries ---------------------------------------------------------


def normalize_query(params: dict, *, allow_exclude: bool = True) -> dict:
    """Validate the dashboard's ScopeQuery (query string or search body)."""

    if not isinstance(params, dict):
        raise ScopeError("SCOPE_QUERY_INVALID", "query must be an object")
    out: dict = {}
    q = params.get("q", "")
    if not isinstance(q, str) or len(q) > 256 or _CONTROL.search(q):
        raise ScopeError("SCOPE_QUERY_INVALID", "q must be a short text")
    out["q"] = q.strip()
    sort = params.get("sort") or "name_asc"
    if sort not in SORTS:
        raise ScopeError("SCOPE_QUERY_INVALID", "sort is not supported")
    out["sort"] = sort
    try:
        size = int(params.get("page_size") or 50)
    except (TypeError, ValueError):
        raise ScopeError("SCOPE_QUERY_INVALID", "page_size must be an integer")
    out["page_size"] = max(1, min(size, MAX_PAGE))
    if params.get("resource_type") and params["resource_type"] not in RESOURCE_TYPES:
        raise ScopeError("SCOPE_QUERY_INVALID", "resource_type is not supported")
    for key in ("resource_type", "account_id", "region", "organization_id", "visibility", "parent_id",
                "known_root_id", "language", "topic", "access_status", "last_scan_status", "last_sync_status", "cursor"):
        value = params.get(key)
        if value in (None, ""):
            continue
        if not isinstance(value, str) or len(value) > 512 or _CONTROL.search(value):
            raise ScopeError("SCOPE_QUERY_INVALID", f"{key} must be a short text")
        out[key] = value
    for key in _DATE_FILTERS:
        value = params.get(key)
        if value in (None, ""):
            continue
        stamp = parse_stamp(value)
        if stamp is None:
            raise ScopeError("SCOPE_QUERY_INVALID", f"{key} must be an ISO-8601 timestamp")
        out[key] = stamp.isoformat()
    for key in ("archived", "fork"):
        value = params.get(key)
        if value in (None, ""):
            continue
        if value not in ("true", "false", "unknown"):
            raise ScopeError("SCOPE_QUERY_INVALID", f"{key} must be true, false or unknown")
        out[key] = value
    selected = params.get("selected")
    if selected not in (None, ""):
        if selected not in ("true", "false"):
            raise ScopeError("SCOPE_QUERY_INVALID", "selected must be true or false")
        ids = params.get("selected_ids") or []
        if not isinstance(ids, list) or len(ids) > MAX_ROOTS or not all(isinstance(i, str) and i for i in ids):
            raise ScopeError("SCOPE_QUERY_INVALID", "selected_ids must be a list of ids")
        out["selected"] = selected
        out["selected_ids"] = sorted(set(ids))
    if params.get("exclude"):
        if not allow_exclude or not isinstance(params["exclude"], dict):
            raise ScopeError("SCOPE_QUERY_INVALID", "exclude must be one filter object")
        excluded = normalize_query(params["exclude"], allow_exclude=False)
        excluded = {k: v for k, v in excluded.items() if k not in ("sort", "page_size", "cursor") and v != ""}
        if not excluded:
            raise ScopeError("SCOPE_QUERY_INVALID", "exclude must contain a filter")
        out["exclude"] = excluded
    return out


def _matches(item: dict, query: dict) -> bool:
    if query.get("exclude") and _matches(item, query["exclude"]):
        return False
    q = query.get("q", "").lower()
    if q and q not in str(item.get("display_name", "")).lower() \
            and q not in str(item.get("provider_resource_id", "")).lower() and q != item.get("id"):
        return False
    for key in _EXACT_FILTERS:
        want = query.get(key)
        if not want:
            continue
        have = item.get(key)
        if want == "UNKNOWN":
            if have not in (None, "", "UNKNOWN"):
                return False
        elif have != want:
            return False
    want = query.get("topic")
    if want:
        topics = item.get("topics")
        if want == "UNKNOWN":
            if topics is not None:
                return False
        elif want not in (topics or []):
            return False
    want = query.get("known_root_id")
    if want and want not in (item.get("known_root_ids") or []):
        return False
    want = query.get("access_status")
    if want and item.get("content_readiness", "UNKNOWN") != want:
        return False
    for key in ("last_sync_status", "last_scan_status"):
        want = query.get(key)
        if want and item.get(key, "UNKNOWN") != want:
            return False
    for key in ("archived", "fork"):
        want = query.get(key)
        if not want:
            continue
        have = item.get(key)
        if {"true": True, "false": False, "unknown": None}[want] is not have:
            return False
    for key, (field, is_end) in _DATE_FILTERS.items():
        bound = query.get(key)
        if not bound:
            continue
        stamp = parse_stamp(item.get(field))
        if stamp is None:
            return False  # an unknown date never satisfies a date bound
        limit = parse_stamp(bound)
        if (stamp > limit) if is_end else (stamp < limit):
            return False
    selected = query.get("selected")
    if selected:
        chosen = item.get("id") in set(query.get("selected_ids") or [])
        if chosen != (selected == "true"):
            return False
    return True


def filter_items(items: list[dict], query: dict) -> list[dict]:
    matched = [item for item in items if _matches(item, query)]
    sort = query.get("sort", "name_asc")
    if sort == "updated_desc":
        matched.sort(key=lambda i: (i.get("last_edited_at") or i.get("last_synced_at") or "", i.get("id", "")), reverse=True)
    else:
        matched.sort(key=lambda i: (str(i.get("display_name", "")).lower(), i.get("id", "")), reverse=sort == "name_desc")
    return matched


def catalog_page(catalog: ScopeCatalog | None, kind: str, connection_id, provider: str, auth: str, query: dict, *,
                 reason_code: str | None = None, metadata_search_enabled: bool = False) -> dict:
    """The dashboard's ScopeCatalog page for one query."""

    items = filter_items(catalog.items if catalog else [], query)
    snapshot = catalog.snapshot_id if catalog else ""
    offset = 0
    cursor = query.get("cursor")
    if cursor:
        head, _, tail = cursor.partition(":")
        if head != snapshot or not tail.isdigit():
            raise ScopeError("SCOPE_CURSOR_EXPIRED", "the catalog changed since this page was read", http_status=410)
        offset = int(tail)
    size = query.get("page_size", 50)
    page = items[offset:offset + size]
    has_more = offset + size < len(items)
    out = {
        "kind": kind, "connection_id": str(connection_id), "catalog_snapshot_id": snapshot,
        "auth_revision": (catalog.auth_revision if catalog and catalog.snapshot_id else auth) or auth,
        "items": page, "catalog_completeness": catalog.completeness if catalog else "UNKNOWN",
        "last_refreshed_at": _iso(catalog.refreshed_at) if catalog and catalog.refreshed_at else NOT_RECORDED,
        "known_count": len(items), "count_accuracy": "EXACT", "has_more": has_more,
        "available_filters": FILTERS.get(provider, _COMMON_FILTERS), "metadata_search_enabled": metadata_search_enabled,
    }
    if has_more:
        out["next_cursor"] = f"{snapshot}:{offset + size}"
    code = reason_code or (catalog.reason_code if catalog else None) or (None if snapshot else "NOT_COLLECTED")
    if code:
        out["reason_code"] = code
    return out


# --- drafts ------------------------------------------------------------------


def draft_public(draft: SelectionDraft, resources: list[dict]) -> dict:
    ready = draft.status == "READY"
    ids = list(draft.resource_ids) if ready else []
    n = len(ids)
    return {"kind": draft.kind, "connection_id": str(draft.connection_id), "id": str(draft.id),
            "catalog_snapshot_id": draft.catalog_snapshot_id, "auth_revision": draft.auth_revision,
            "resource_ids": ids, "resources": resources if ready else [], "known_count": n,
            "unknown_remainder": bool(draft.unknown_remainder), "expires_at": _iso(draft.expires_at) or NOT_RECORDED,
            "resolution_status": draft.status, "processed_count": n, "total_count": n}


# --- profiles ----------------------------------------------------------------


def _text(value, what: str, limit: int, *, required: bool) -> str:
    if value in (None, ""):
        if required:
            raise ScopeError("SCOPE_PROFILE_INVALID", f"{what} is required")
        return ""
    if not isinstance(value, str) or len(value) > limit or _CONTROL.search(value):
        raise ScopeError("SCOPE_PROFILE_INVALID", f"{what} must be plain text up to {limit} characters")
    if required and not value.strip():
        raise ScopeError("SCOPE_PROFILE_INVALID", f"{what} is required")
    return value


def _strings(value, what: str, limit: int = 20_000) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > limit or not all(isinstance(v, str) and v and len(v) <= 4096 for v in value):
        raise ScopeError("SCOPE_PROFILE_INVALID", f"{what} must be a list of non-empty strings")
    return list(dict.fromkeys(value))


def _root(value) -> dict:
    if not isinstance(value, dict) or not isinstance(value.get("resource_id"), str) or not value["resource_id"]:
        raise ScopeError("SCOPE_PROFILE_INVALID", "each selected root needs a resource_id")
    root = {"resource_id": _text(value["resource_id"], "resource_id", 4096, required=True)}
    for flag in ("all_current_objects", "include_future_descendants"):
        choice = value.get(flag, False)
        if not isinstance(choice, bool):
            raise ScopeError("SCOPE_PROFILE_INVALID", f"{flag} must be a boolean")
        root[flag] = choice
    priority = value.get("priority", 0)
    if not isinstance(priority, int) or isinstance(priority, bool) or not -1000 <= priority <= 1000:
        raise ScopeError("SCOPE_PROFILE_INVALID", "priority must be an integer between -1000 and 1000")
    root["priority"] = priority
    for key in _STRING_KEYS:
        root[key] = _strings(value.get(key), key)
    ref = value.get("ref")
    if ref is not None and ref != "":
        root["ref"] = _text(ref, "ref", 256, required=False)
    mode = value.get("page_mode")
    if mode is not None and mode != "":
        if mode not in PAGE_MODES:
            raise ScopeError("SCOPE_PROFILE_INVALID", "page_mode is not supported")
        root["page_mode"] = mode
    return root


def validate_profile_input(body: dict) -> dict:
    """The dashboard's ScopeProfileInput, validated and normalised."""

    if not isinstance(body, dict):
        raise ScopeError("SCOPE_PROFILE_INVALID", "request must be an object")
    roots_in = body.get("selected_roots", [])
    if not isinstance(roots_in, list) or len(roots_in) > MAX_ROOTS:
        raise ScopeError("SCOPE_PROFILE_INVALID", f"selected_roots must hold at most {MAX_ROOTS} entries")
    roots = [_root(r) for r in roots_in]
    if len({r["resource_id"] for r in roots}) != len(roots):
        raise ScopeError("SCOPE_PROFILE_INVALID", "selected_roots must not repeat a resource")
    budgets_in = body.get("budgets") or {}
    if not isinstance(budgets_in, dict):
        raise ScopeError("SCOPE_PROFILE_INVALID", "budgets must be an object")
    budgets = {}
    for key, cap in MAX_BUDGET.items():
        value = budgets_in.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0 or value > cap:
            raise ScopeError("SCOPE_PROFILE_INVALID", f"budgets.{key} must be a positive integer")
        budgets[key] = value
    schedule = body.get("schedule_minutes", 0)
    if not isinstance(schedule, int) or isinstance(schedule, bool) or schedule < 0 or schedule > 43_200 or 0 < schedule < 5:
        raise ScopeError("SCOPE_PROFILE_INVALID", "schedule_minutes must be 0 or between 5 and 43200")
    full = body.get("full_scan_minutes")
    if full is not None and (type(full) is not int or full != 0 and not 60 <= full <= 1440):
        raise ScopeError("SCOPE_PROFILE_INVALID", "full_scan_minutes must be 0 or between 60 and 1440")
    event_mode = body.get("event_mode", "DISABLED")
    if event_mode not in ("DISABLED", "ENABLED"):
        raise ScopeError("SCOPE_PROFILE_INVALID", "event_mode must be DISABLED or ENABLED")
    expected = body.get("expected_version", 0)
    if not isinstance(expected, int) or isinstance(expected, bool) or expected < 0:
        raise ScopeError("SCOPE_PROFILE_INVALID", "expected_version must be a non-negative integer")
    return {
        "name": _text(body.get("name"), "name", 128, required=True).strip(),
        "change_reason": _text(body.get("change_reason"), "change_reason", 512, required=True).strip(),
        "selected_roots": roots, "excluded_ids": _strings(body.get("excluded_ids"), "excluded_ids", MAX_ROOTS),
        "budgets": budgets, "schedule_minutes": schedule, "event_mode": event_mode,
        **({"full_scan_minutes": full} if "full_scan_minutes" in body else {}),
        "catalog_snapshot_id": _text(body.get("catalog_snapshot_id"), "catalog_snapshot_id", 128, required=False),
        "expected_version": expected,
    }


def effective_roots(profile: ScopeProfile) -> list[dict]:
    excluded = set(profile.excluded_ids)
    return sorted((r for r in profile.selected_roots if r["resource_id"] not in excluded),
                  key=lambda r: -r.get("priority", 0))


def profile_state(profile: ScopeProfile, *, auth: str, enabled: bool) -> str:
    if not enabled:
        return "PAUSED"
    if profile.auth_revision != auth:
        return "NEEDS_SCOPE_REVIEW"
    return "READY" if effective_roots(profile) else "NO_TARGETS_SELECTED"


def connection_state(states: list[str], *, enabled: bool) -> str:
    if not enabled:
        return "PAUSED"
    if "NEEDS_SCOPE_REVIEW" in states:
        return "NEEDS_SCOPE_REVIEW"
    return "READY" if "READY" in states else "NO_TARGETS_SELECTED"


def profile_public(p: ScopeProfile, state: str) -> dict:
    return {"kind": p.kind, "connection_id": str(p.connection_id), "id": str(p.id), "name": p.name, "version": p.version,
            "state": state, "selected_roots": p.selected_roots, "excluded_ids": p.excluded_ids, "budgets": p.budgets,
            "schedule_minutes": p.schedule_minutes, "full_scan_minutes": p.full_scan_minutes,
            "event_mode": p.event_mode, "change_reason": p.change_reason,
            "catalog_snapshot_id": p.catalog_snapshot_id, "auth_revision": p.auth_revision,
            "approved_by": p.approved_by, "approved_at": _iso(p.approved_at) or ""}


def exact_selection(roots: list[dict], excluded_ids: list[str], budgets: dict, schedule_minutes: int,
                    event_mode: str, catalog_snapshot_id: str, full_scan_minutes: int | None = None) -> dict:
    """The canonical form the dashboard compares saved scopes by."""

    return {
        "roots": sorted(({"resource_id": r["resource_id"], "all_current_objects": r["all_current_objects"],
                          "prefixes": sorted(r.get("prefixes", [])), "excluded_prefixes": sorted(r.get("excluded_prefixes", [])),
                          "ref": r.get("ref") or "", "paths": sorted(r.get("paths", [])),
                          "excluded_paths": sorted(r.get("excluded_paths", [])), "page_mode": r.get("page_mode") or "",
                          "descendant_ids": sorted(r.get("descendant_ids", [])),
                          "include_future_descendants": r["include_future_descendants"],
                          **({"priority": r["priority"]} if r.get("priority") else {})} for r in roots),
                        key=lambda r: r["resource_id"]),
        "excluded_ids": sorted(excluded_ids),
        "budgets": {k: budgets.get(k) for k in ("bytes", "requests", "seconds")},
        "schedule_minutes": schedule_minutes, "event_mode": event_mode, "catalog_snapshot_id": catalog_snapshot_id,
        **({"full_scan_minutes": full_scan_minutes} if full_scan_minutes is not None else {}),
    }


# --- plans -------------------------------------------------------------------


def _root_problem(root: dict, item: dict) -> str | None:
    if root.get("include_future_descendants"):
        return "FUTURE_DESCENDANTS_NOT_SUPPORTED"
    rt = item["resource_type"]
    if rt in ("S3_BUCKET", "GCS_BUCKET") and not root.get("all_current_objects") and not root.get("prefixes"):
        return "BUCKET_OBJECT_SELECTION_REQUIRED"
    if rt == "NOTION_DATA_SOURCE" and not root.get("descendant_ids"):
        return "DATA_SOURCE_ROWS_REQUIRED"
    if rt == "NOTION_DATA_SOURCE" and root.get("page_mode") == "PAGE_ONLY":
        return "DATA_SOURCE_PAGE_MODE_INVALID"
    # A source module's own rule for what its roots may name (the website scan's URL paths), before a run fails on it.
    hook = getattr(BY_RESOURCE_TYPE.get(rt), "scope_problem", None)
    return hook(root) if callable(hook) else None


def _plan_root(root: dict, item: dict) -> dict:
    return {**root, "resource_type": item["resource_type"], "provider_resource_id": item["provider_resource_id"],
            "canonical_reference": item.get("canonical_reference", ""), "account_id": item.get("account_id", ""),
            "region": item.get("region", ""), "default_branch": item.get("default_branch")}


def policy_digest(profile: ScopeProfile, catalog_snapshot_id: str, auth: str, extra: dict | None = None) -> str:
    content = {"kind": profile.kind, "connection_id": str(profile.connection_id), "profile_id": str(profile.id),
               "version": profile.version, "catalog_snapshot_id": catalog_snapshot_id, "auth_revision": auth,
               "selection": exact_selection(profile.selected_roots, profile.excluded_ids, profile.budgets,
                                            profile.schedule_minutes, profile.event_mode, profile.catalog_snapshot_id,
                                            profile.full_scan_minutes),
               **(extra or {})}
    return hashlib.sha256(json.dumps(content, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def build_plan(profile: ScopeProfile, catalog: ScopeCatalog | None, *, auth: str, enabled: bool,
               now: _dt.datetime | None = None, configured_triggers: set[str] | None = None) -> ScopePlan:
    """Resolve a profile against the current catalog into a fixed, expiring plan."""

    now = now or _now()
    items = {i["id"]: i for i in (catalog.items if catalog else [])}
    warnings: list[str] = []
    blocking = False
    if not enabled:
        warnings.append("CONNECTION_PAUSED")
        blocking = True
    if profile.auth_revision != auth:
        warnings.append("NEEDS_SCOPE_REVIEW")
        blocking = True
    if catalog and catalog.snapshot_id and profile.catalog_snapshot_id != catalog.snapshot_id:
        warnings.append("CATALOG_REFRESHED_SINCE_SAVE")
    known, roots, unresolved = [], [], 0
    for root in effective_roots(profile):
        item = items.get(root["resource_id"])
        if item is None or not selectable(item):
            unresolved += 1
            continue
        problem = _root_problem(root, item)
        if problem:
            warnings.append(problem)
            blocking = True
        known.append(item)
        roots.append(_plan_root(root, item))
    if unresolved:
        warnings.append("UNRESOLVED_ROOTS_SKIPPED")
        blocking = True
    if not known:
        warnings.append("NO_TARGETS_SELECTED")
        blocking = True
    if (profile.schedule_minutes or profile.full_scan_minutes) and "SCHEDULE" not in (configured_triggers or set()):
        warnings.append("SCHEDULE_NOT_CONFIGURED")
    if profile.event_mode == "ENABLED" and "EVENT" not in (configured_triggers or set()):
        warnings.append("EVENTS_NOT_CONFIGURED")
    return ScopePlan(
        kind=profile.kind, connection_id=profile.connection_id, profile_id=profile.id, profile_version=profile.version,
        catalog_snapshot_id=profile.catalog_snapshot_id, auth_revision=profile.auth_revision,
        policy_digest=policy_digest(profile, catalog.snapshot_id if catalog else "", auth),
        resources=known, roots=roots, known_count=len(known), unresolved_count=unresolved,
        warnings=list(dict.fromkeys(warnings)), executable=not blocking, trigger="BASELINE", expires_at=now + PLAN_TTL,
    )


def plan_public(plan: ScopePlan, profile: dict) -> dict:
    out = {"kind": plan.kind, "connection_id": str(plan.connection_id), "plan_id": str(plan.id),
           "profile_id": str(plan.profile_id), "profile_version": plan.profile_version,
           "catalog_snapshot_id": plan.catalog_snapshot_id, "auth_revision": plan.auth_revision, "profile": profile,
           "resources": plan.resources, "policy_digest": plan.policy_digest, "known_count": plan.known_count,
           "unresolved_count": plan.unresolved_count, "warnings": plan.warnings,
           "expires_at": _iso(plan.expires_at) or NOT_RECORDED, "executable": bool(plan.executable)}
    if plan.rescan_target:
        out["rescan_target"] = plan.rescan_target
    return out


# --- rescan of one exact location -------------------------------------------


_NOTION_ID = re.compile(r"([0-9a-f]{32})(?:[?#].*)?$")


def path_allowed(module, location: str, root: dict) -> bool:
    """Whether an approved root's ``paths`` and ``excluded_paths`` admit a location (a rescan's, an event's): slash-
    delimited prefixes of the location itself, or the test of a source module that keeps full URLs (``scope_allows``,
    the website scan's)."""
    paths, excluded = root.get("paths") or [], root.get("excluded_paths") or []
    hook = getattr(module, "scope_allows", None)
    if callable(hook):
        return hook(location, paths, excluded)
    return not path_under(location, excluded) and (not paths or path_under(location, paths))


def _notion_id(location: str) -> str:
    m = _NOTION_ID.search(location.replace("-", "")) if location else None
    return m.group(1) if m else location.replace("-", "")


def rescan_target(finding, exposure, profile: ScopeProfile, catalog: ScopeCatalog | None) -> tuple[dict, dict]:
    """(plan root, rescan_target) for one exposure, or ScopeError when the
    location is outside the profile's approved scope."""

    source_type = exposure.source_type
    if source_type not in BY_SOURCE:
        raise ScopeError("RESCAN_UNSUPPORTED_SOURCE", f"{source_type} locations cannot be rescanned exactly")
    items = catalog.items if catalog else []
    if source_type == "notion":
        wanted = _notion_id(exposure.location)
        item = next((i for i in items if i["resource_type"] == "NOTION_PAGE"
                     and i["provider_resource_id"].replace("-", "") == wanted), None)
    else:
        from cremore.source_config import RESOURCE_SOURCE
        rt = next(key for key, source in RESOURCE_SOURCE.items() if source == source_type)
        item = next((i for i in items if i["resource_type"] == rt and i["provider_resource_id"] == exposure.resource_name), None)
    if item is None:
        raise ScopeError("RESCAN_RESOURCE_NOT_IN_CATALOG", "the exposure's resource is not in the connection catalog")
    root = next((r for r in effective_roots(profile) if r["resource_id"] == item["id"]), None)
    if source_type == "notion" and root is None:
        # A page approved as a descendant or a data-source row of another root.
        page_id = item["provider_resource_id"]
        root = next((r for r in effective_roots(profile)
                     if r.get("page_mode") != "PAGE_ONLY" and page_id in (r.get("descendant_ids") or [])), None)
    if root is None:
        raise ScopeError("RESCAN_OUT_OF_SCOPE", "this location is not inside the selected profile's approved scope")
    location = exposure.location
    exact = _plan_root(root, item)
    target = {"finding_id": str(finding.id), "exposure_id": str(exposure.id),
              "evidence_digest": hashlib.sha256(f"{exposure.id}|{finding.id}|{source_type}|{exposure.resource_name}|"
                                                f"{location}|{exposure.object_version}".encode()).hexdigest(),
              "source_type": source_type, "resource_id": item["id"], "resource": exposure.resource_name, "path": location}
    if BY_SOURCE[source_type].SCOPE_KIND == "object":
        if root.get("excluded_prefixes") and any(location.startswith(p) for p in root["excluded_prefixes"]):
            raise ScopeError("RESCAN_OUT_OF_SCOPE", "the object key is under an excluded prefix")
        if not root.get("all_current_objects") and not any(location.startswith(p) for p in root.get("prefixes") or []):
            raise ScopeError("RESCAN_OUT_OF_SCOPE", "the object key is not under an approved prefix")
        exact["exact_keys"] = [location]
    elif BY_SOURCE[source_type].SCOPE_KIND == "path":
        hook = getattr(BY_SOURCE[source_type], "scope_problem", None)
        problem = hook(root) if callable(hook) else None
        if problem:  # the approved scope itself cannot bound a read: say that, not that the location is outside it
            raise ScopeError(problem, "the approved scope names a path that is not one")
        if not path_allowed(BY_SOURCE[source_type], location, root):
            raise ScopeError("RESCAN_OUT_OF_SCOPE", "the path is outside the approved paths")
        ref = root.get("ref") or (f"refs/heads/{item['default_branch']}" if item.get("default_branch") else "HEAD")
        exact["ref"] = ref
        exact["exact_paths"] = [location]
        target["ref"] = ref
    else:
        exact["exact_page_ids"] = [item["provider_resource_id"]]
    return exact, target


# --- runs --------------------------------------------------------------------


def run_payload(plan: ScopePlan, profile: ScopeProfile, base: dict, source_type: str) -> dict:
    return {**base, "source_type": source_type, "connection_kind": plan.kind, "connection_id": str(plan.connection_id),
            "plan_id": str(plan.id), "profile_id": str(profile.id), "profile_version": profile.version,
            "auth_revision": plan.auth_revision, "policy_digest": plan.policy_digest,
            "trigger": plan.trigger, "verify": plan.verify, "budgets": profile.budgets, "roots": plan.roots}


def split_roots(roots):
    """One derivation of approved shards, shared by validation and execution."""
    out = []
    for root in roots:
        rt = root["resource_type"]
        if rt in ("NOTION_PAGE", "NOTION_DATA_SOURCE"):
            if "exact_page_ids" in root:
                ids = root["exact_page_ids"]
            else:
                ids = [root["provider_resource_id"]] if rt == "NOTION_PAGE" else []
                if root.get("page_mode") != "PAGE_ONLY":
                    ids += root.get("descendant_ids") or []
            for page_id in sorted(set(ids)):
                out.append({**root, "resource_type": "NOTION_PAGE", "provider_resource_id": page_id,
                            "page_mode": "PAGE_ONLY", "descendant_ids": [], "exact_page_ids": [page_id]})
        elif rt == "S3_BUCKET" and not root.get("all_current_objects") and not root.get("exact_keys"):
            prefixes = []
            for prefix in sorted(set(root.get("prefixes") or [])):
                if not any(prefix.startswith(p) for p in prefixes):
                    prefixes.append(prefix)
            out.extend({**root, "prefixes": [prefix]} for prefix in prefixes)
        else:
            out.append(copy.deepcopy(root))
    return out


def _execution_identity(root):
    return {**_root(root), **{key: root.get(key) for key in (
        "resource_type", "provider_resource_id", "account_id", "region", "default_branch",
        "exact_keys", "exact_paths", "exact_page_ids")}}


def _exact_within(root, approved):
    rt = approved["resource_type"]
    field = EXACT_FIELDS[rt]
    if any(k in root for k in {"exact_keys", "exact_paths", "exact_page_ids"} - {field}):
        return False
    values = root.get(field)
    if values is None:
        return True
    if not isinstance(values, list) or not values or any(not isinstance(v, str) or not v or _CONTROL.search(v) for v in values):
        return False
    for value in values:
        if BY_RESOURCE_TYPE[rt].SCOPE_KIND == "object":
            if (len(value.encode()) > 1024 or any(value.startswith(p) for p in approved.get("excluded_prefixes") or [])
                    or (not approved.get("all_current_objects") and not any(value.startswith(p) for p in approved.get("prefixes") or []))):
                return False
        elif BY_RESOURCE_TYPE[rt].SCOPE_KIND == "path":
            if not path_allowed(BY_RESOURCE_TYPE[rt], value, approved):
                return False
        else:
            pages = [approved["provider_resource_id"]] if rt == "NOTION_PAGE" else []
            if approved.get("page_mode") != "PAGE_ONLY":
                pages += approved.get("descendant_ids") or []
            if value.replace("-", "").lower() not in {p.replace("-", "").lower() for p in pages}:
                return False
    return True


def _approved_execution_root(plan, current, observed, items, split_cache):
    """Bind provider identity to its catalog ID, then permit only narrowing."""
    item = items.get(current["resource_id"])
    if item is None and plan.trigger == "RESCAN" and observed.get("resource_type") == "NOTION_PAGE":
        # An exact finding rescan may carry only the separately catalogued child.
        child = str(observed.get("provider_resource_id", "")).replace("-", "").lower()
        children = {p.replace("-", "").lower() for p in current.get("descendant_ids") or []}
        if current.get("page_mode") != "PAGE_ONLY" and child in children:
            item = next((i for i in plan.resources if i.get("resource_type") == "NOTION_PAGE"
                         and str(i.get("provider_resource_id", "")).replace("-", "").lower() == child), None)
    if (item is None or item.get("resource_type") not in RESOURCE_TYPES
            or item.get("id") != resource_id(plan.kind, plan.connection_id, item["resource_type"], item.get("provider_resource_id", ""))):
        return False
    expected = _plan_root(current, item)
    if plan.trigger == "POLICY_SWEEP":
        if _execution_identity(observed) == _execution_identity(expected):
            return True  # The trigger first validates its full approved input.
        rid = current["resource_id"]
        if rid not in split_cache:
            split_cache[rid] = {json.dumps(_execution_identity(r), sort_keys=True) for r in split_roots([expected])}
        return json.dumps(_execution_identity(observed), sort_keys=True) in split_cache[rid]
    # A rescan names the ref rescan_target chose for every path source, not only the Git hosts.
    if plan.trigger == "RESCAN" and BY_RESOURCE_TYPE[expected["resource_type"]].SCOPE_KIND == "path" and not current.get("ref"):
        expected["ref"] = f"refs/heads/{item['default_branch']}" if item.get("default_branch") else "HEAD"
    hints = {k: observed[k] for k in ("exact_keys", "exact_paths", "exact_page_ids") if k in observed}
    if hints:
        if plan.trigger not in {"EVENT", "RESCAN"} or not _exact_within(observed, expected):
            return False
        expected.update(hints)
    elif plan.trigger == "RESCAN":
        return False
    return _execution_identity(observed) == _execution_identity(expected)


def validate_execution(plan: ScopePlan, profile: ScopeProfile, target, *, now=None,
                       require_unexpired: bool = False) -> None:
    """Recheck the approved identity and authorization when queued work executes."""
    if (plan.profile_id != profile.id or plan.kind != profile.kind
            or plan.connection_id != profile.connection_id or target.id != plan.connection_id
            or plan.profile_version != profile.version):
        raise ScopeError("SCOPE_PLAN_STALE", "the approved profile changed", http_status=409)
    if not plan.executable or plan.unresolved_count:
        raise ScopeError("SCOPE_PLAN_NOT_EXECUTABLE", ", ".join(plan.warnings), http_status=409)
    approved = {root["resource_id"]: root for root in effective_roots(profile)}
    items = {item.get("id"): item for item in plan.resources}
    split_cache = {}
    if not plan.roots:
        raise ScopeError("SCOPE_PLAN_NOT_EXECUTABLE", "no approved roots remain", http_status=409)
    if plan.trigger not in {"RESCAN", "EVENT", "POLICY_SWEEP"} and {root.get("resource_id") for root in plan.roots} != set(approved):
        raise ScopeError("SCOPE_PLAN_STALE", "the approved root selection changed", http_status=409)
    for root in plan.roots:
        current = approved.get(root.get("resource_id"))
        if current is None or not _approved_execution_root(plan, current, root, items, split_cache):
            raise ScopeError("SCOPE_PLAN_STALE", "the approved root policy changed", http_status=409)
    enabled = bool(target.enabled) if plan.kind == "aws" else (
        target.status != "DISABLED" and not (target.credential_evidence or {}).get("revoked_at"))
    auth = auth_revision(plan.kind, target)
    if not enabled or plan.auth_revision != auth or profile.auth_revision != auth:
        raise ScopeError("NEEDS_SCOPE_REVIEW", "the connection authorization changed", http_status=409)
    if require_unexpired and plan.expires_at:
        expiry = plan.expires_at if plan.expires_at.tzinfo else plan.expires_at.replace(tzinfo=_dt.UTC)
        if expiry <= (now or _now()):
            raise ScopeError("SCOPE_PLAN_EXPIRED", "prepare a new preview", http_status=410)


_JOB_STATUS = {"QUEUED": "QUEUED", "RUNNING": "RUNNING", "SUCCEEDED": "COMPLETED", "FAILED": "FAILED",
               "CANCELLING": "CANCELLING", "CANCELLED": "CANCELLED"}


def active_scan_public(job) -> dict | None:
    """The scan holding the installation's content-scan slot, as the dashboard shows it."""
    if job is None:
        return None
    return {"id": str(job.id), "kind": job.kind, "status": job.status,
            "connection_id": str(job.connection_id) if job.connection_id else None,
            "mode": (job.payload or {}).get("mode", "BASELINE"),
            "created_at": _iso(job.created_at), "started_at": _iso(job.started_at)}


# Coverage written with this marker counts format skips (archives, PDFs, images)
# apart from `failed`. Older coverage folded unsupported formats into `failed`
# and images into `skipped_unsupported`, so it is read as recorded, never re-split.
FAILURE_BASIS = "EXCLUDES_FORMAT_SKIPS"


def rule_basis(coverage: dict, current_digest: str) -> str:
    """How a finished run's own detection policy compares with the current one."""
    recorded = (coverage or {}).get("detection_policy_digest")
    if not recorded:
        return "UNRECORDED"
    return "CURRENT" if recorded == current_digest else "PREVIOUS"


def job_is_partial(job) -> bool:
    cov = job.coverage or {}
    return bool(
        int(cov.get("failed", job.objects_failed or 0) or 0)
        or int(cov.get("skipped", 0) or 0)
        or int(cov.get("skipped_unsupported", 0) or 0)
        or int(cov.get("skipped_media", 0) or 0)
        or int(cov.get("roots_failed", 0) or 0)
        or cov.get("root_coverage_complete") is False
        or cov.get("stopped_reason")
    )


def job_error_code(job) -> str | None:
    """Expose the stored machine code, never an exception's message or body."""
    if not job.error:
        return None
    code = job.error.split(":", 1)[0].strip()
    return code if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,95}", code) else "SCAN_FAILED"


def run_public(job, kind: str, connection_id) -> dict:
    """The dashboard's ScopeRun for one scoped job."""

    from cremore.scanning.extraction.contract import public_reasons

    p = job.payload or {}
    cov = job.coverage or {}
    failed = int(cov.get("failed", job.objects_failed or 0) or 0)
    skipped = int(cov.get("skipped", 0) or 0)
    partial = job_is_partial(job)
    status = _JOB_STATUS.get(job.status, job.status)
    if job.status == "SUCCEEDED" and partial:
        status = "PARTIAL"
    out = {"kind": kind, "connection_id": str(connection_id), "id": str(job.id), "profile_id": str(p.get("profile_id", "")),
           "profile_version": int(p.get("profile_version", 0) or 0), "scope_snapshot_id": str(p.get("plan_id", "")),
           "trigger": p.get("trigger", "BASELINE"), "mode": p.get("mode", "BASELINE"), "status": status,
           "attempted": int(cov.get("attempted", job.objects + failed) or 0), "succeeded": int(cov.get("succeeded", job.objects) or 0),
           "failed": failed, "skipped": skipped, "bytes": int(cov.get("bytes", 0) or 0), "requests": int(cov.get("requests", 0) or 0),
           "engine_name": cov.get("engine_name") or NOT_RECORDED,
           "engine_version": cov.get("engine_version") or NOT_RECORDED,
           "created_at": _iso(job.created_at) or NOT_RECORDED}
    out["extraction_reasons"] = public_reasons(cov.get("extraction_reasons"))
    if job.finished_at:
        out["completed_at"] = _iso(job.finished_at)
    if "root_coverage_complete" in cov:
        out["root_coverage_complete"] = bool(cov["root_coverage_complete"])
    if cov.get("coverage_basis"):
        out["coverage_basis"] = cov["coverage_basis"]
    if cov.get("policy_held"):
        # Roots an upgrade's change run did not read whole under the current policy: its next full scan does.
        out["policy_held_roots"] = int(cov["policy_held"])
        if cov.get("policy_held_only"):
            out["policy_held_only"] = True  # nothing else leaves the run partial
    for key in ("count_basis", "timings", "reused", "skipped_archived", "skipped_submodules", "skipped_unchanged",
                "skipped_unsupported", "skipped_media", "failure_basis"):
        if key in cov:
            out[key] = cov[key]
    if job.status == "SUCCEEDED" and not partial:
        out["result_status"] = "SCANNED"
    if job.status == "SUCCEEDED":
        out["count_status"] = "OBSERVED_OBJECTS_ONLY"
        out["content_bytes"] = out["bytes"]
    reason = job_error_code(job) if job.error else (cov.get("stopped_reason") or None)
    if reason:
        out["reason_code"] = reason
    return out
