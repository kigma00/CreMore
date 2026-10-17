"""Authenticate, list metadata and approve a selection before creating collections.

The API seals credentials and queues work. Only the worker authenticates or lists
provider resources. An actor/browser-bound draft owns the envelope until one
atomic completion transfers it to a provider connection.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import re
import time
import uuid
from contextlib import ExitStack, nullcontext

from cremore.onboarding import catalog, check, permissions, service, targets
from cremore.onboarding.session_store import SessionStore
from cremore.onboarding.store import (
    ProviderConnectionConflict,
    ProviderConnectionStore,
    active_plans,
    atomic,
)

TTL = dt.timedelta(minutes=30)
TERMINAL = {"CANCELLED", "EXPIRED", "COMPLETED"}
_BROWSER = re.compile(r"[A-Za-z0-9_-]{43,128}")


def _now():
    return dt.datetime.now(dt.UTC)


def _binding(key):
    if not isinstance(key, str) or not _BROWSER.fullmatch(key):
        raise service.OnboardingError("ONBOARDING_BROWSER_REQUIRED")
    return hashlib.sha256(key.encode()).hexdigest()


def _get(repo, sid, actor, body, *, terminal=False, lock=False):
    try:
        row = SessionStore(repo).get(sid, lock=lock)
    except (ValueError, TypeError):
        row = None
    binding = _binding(body.get("browser_key"))
    if row is None or row["actor"] != actor or not hmac.compare_digest(row["binding_hash"], binding):
        raise service.OnboardingError("ONBOARDING_SESSION_NOT_FOUND", 404)
    if row["expires_at"] <= _now() and row["data"]["state"] not in TERMINAL:
        _end(repo, row, "EXPIRED")
        if not terminal:
            raise service.OnboardingError("ONBOARDING_SESSION_EXPIRED", 409)
        row = SessionStore(repo).get(row["id"])
    if not terminal and row["data"]["state"] in TERMINAL:
        raise service.OnboardingError("ONBOARDING_SESSION_CLOSED", 409)
    return row


def _expected(row, body):
    if type(body.get("expected_revision")) is not int or body["expected_revision"] != row["revision"]:
        raise service.OnboardingError("ONBOARDING_SESSION_CHANGED", 409)


def public(row):
    data = row["data"]
    return {"id": str(row["id"]), "revision": row["revision"], "expires_at": row["expires_at"].isoformat(),
            **{k: data[k] for k in ("provider", "edition", "auth_method", "state", "authentication", "roots",
                                   "completeness", "plans", "selected_targets", "resources", "selected_resources",
                                   "error", "connection_id", "job_id", "snapshot_id", "purposes",
                                   "selected_roots", "editing", "name", "previous_plans", "previous_target_ids", "discovery_notice",
                                   "held_purposes") if k in data},
            "context": {k: v for k, v in data.get("target", {}).items() if k not in {"auth", "generated"}},
            "checks": {k: v for k, v in data.get("checks", {}).items() if k in {"results", "requested_plans", "checked_at", "stale"}},
            "public_auth": {k: v for k, v in data.get("target", {}).get("auth", {}).items()
                            if k in {"client_id", "email", "role", "mount", "token_file"}},
            "blockers": permissions.blockers(_candidate(data), data["plans"]) if data.get("checks") else [],
            "generated": data.get("target", {}).get("generated"),
            "feature_enabled": {purpose: purpose not in (data.get("disabled_purposes") or [])
                                for purpose in dict.fromkeys([*data.get("purposes", []), *data.get("disabled_purposes", [])])},
            "has_more": bool(data.get("discovery_cursor")),
            # Targets the edited integration collects from that this listing lacks: inspect refuses until they are listed.
            "previous_unlisted": max(0, len(data.get("previous_targets") or []) - len(data["previous_target_ids"]))
            if data.get("editing") and "previous_target_ids" in data else 0}


def read(repo, sid, body, actor):
    return public(_get(repo, sid, actor, body, terminal=True))


def _audit(repo, row, event, note=None):
    from cremore.domain.models import FindingEvent

    repo.record_finding_event(FindingEvent(target_type="onboarding_session", target_id=row["id"],
                                         actor=row["actor"], event_type=event, note=note))


def create(repo, settings, body, actor):
    descriptor = catalog.descriptor(body.get("provider"))
    edition = body.get("edition") or descriptor["editions"][0]["id"]
    if edition not in {item["id"] for item in descriptor["editions"]}:
        raise service.OnboardingError("EDITION_UNKNOWN")
    method = service._method(descriptor["provider"], [], body.get("auth_method"), edition, new_setup=True)
    support = method.get("auth_first")
    if not isinstance(support, dict):
        raise service.OnboardingError("AUTH_FIRST_NOT_SUPPORTED", 409)
    fields = [f for f in descriptor.get("target") or [] if f["name"] in support.get("context", [])]
    context = service._fields(fields, body.get("context") or {}, edition)
    normalize = getattr(catalog.module(descriptor["provider"]), "auth_context", None)
    if callable(normalize):
        context = normalize(descriptor["provider"], edition, context)
    intent = body.get("credential_purpose", "collector")
    if intent not in {"collector", "remediator"} or (intent == "remediator" and "remediation" not in method["purposes"]):
        raise service.OnboardingError("CREDENTIAL_PURPOSE_INVALID")
    refs = service._credential(settings, descriptor["provider"], method, body.get("credential"), context,
                               purposes=["remediation"] if intent == "remediator" else [])
    context.update({"auth": service._public_fields(method, body.get("credential"))})
    binding = _binding(body.get("browser_key"))
    with atomic(repo) as bound:
        row = SessionStore(bound).create(actor, binding,
            {"provider": descriptor["provider"], "edition": edition, "auth_method": method["id"], "target": context,
             "secret_refs": refs, "credential_purpose": intent,
             "purposes": [], "plans": {}, "state": "NEW"}, _now() + TTL)
        row = _queue(bound, row, "authenticate")
        _audit(bound, row, "ONBOARDING_AUTHENTICATION_REQUESTED")
    return public(row)


def authenticate(repo, sid, body, actor):
    with atomic(repo) as bound:
        row = _get(bound, sid, actor, body)
        _expected(row, body)
        if row["data"]["state"] not in {"SETUP_REQUIRED", "AUTH_FAILED", "FAILED", "AUTHENTICATED"}:
            raise service.OnboardingError("ONBOARDING_AUTHENTICATION_UNAVAILABLE", 409)
        row = SessionStore(bound).save(row, {**row["data"], "authentication": {}, "plans": {}, "purposes": [], "held_purposes": [],
            "checks": {}, "roots": [], "resources": [], "selected_targets": [], "selected_resources": [], "snapshot_id": None})
        return public(_queue(bound, row, "authenticate"))


def edit(repo, settings, connection_id, body, actor):
    """Reuse one owner's envelope; the API never opens it or creates another owner."""
    with atomic(repo) as bound:
        record = service.get(bound, connection_id)
        if body.get("expected_revision") != record["revision"]:
            raise service.OnboardingError("PROVIDER_CONNECTION_CHANGED", 409)
        method = service._method(record["provider"], record["purposes"], record["auth_method"], record["edition"])
        authentication_only = record.get("checks", {}).get("authentication_only") is True and not record["plans"]
        if ((record["provider"] == "aws" or record["status"] != "ACTIVE") and not authentication_only
                or record["status"] == "DISABLED" or not method.get("auth_first")):
            raise service.OnboardingError("TARGET_EDIT_NOT_SUPPORTED", 409)
        plans = active_plans(record)
        if not plans and not authentication_only:
            raise service.OnboardingError("TARGET_EDIT_NO_ACTIVE_FEATURES", 409)
        fields = set(method["auth_first"]["context"]) | {"auth", "generated"}
        context = {k: v for k, v in targets.records_of(record)[0]["target"].items() if k in fields}
        profiles = {}
        for link in ProviderConnectionStore(bound).children(record["id"]):
            if link["kind"] == "content":
                profiles[link["child_id"]] = {str(p.id): p.version for p in bound.list_scope_profiles("source", uuid.UUID(link["child_id"]))}
        row = SessionStore(bound).create(actor, _binding(body.get("browser_key")), {
            **{k: record[k] for k in ("provider", "edition", "auth_method", "secret_refs", "name")},
            "target": context, "purposes": list(plans), "plans": {}, "state": "NEW",
            "credential_purpose": "remediator" if record["purposes"] == ["remediation"] else "collector",
            "disabled_purposes": list(record.get("disabled_purposes") or []),
            "editing": str(record["id"]), "owner_revision": record["revision"], "profile_versions": profiles,
            "previous_plans": plans, "previous_targets": [{k: v for k, v in root["target"].items()
                if k not in {"auth", "generated"}} for root in targets.records_of(record)
                if set(root["purposes"]) & set(plans)], "previous_scopes": _previous_scopes(record, plans)}, _now() + TTL)
        row = _queue(bound, row, "authenticate")
        _audit(bound, row, "ONBOARDING_TARGET_EDIT_REQUESTED")
        return public(row)


def _previous_scopes(record, plans):
    """The targets a record keeps to some of its running features (a scan location a content card added), so a listing
    that shows them plain again does not widen the other running features to them."""
    out = []
    for root in targets.records_of(record):
        served = [p for p in root["purposes"] if p in plans]
        if served and set(plans) - set(served):
            out.append({"target": {k: v for k, v in root["target"].items() if k not in {"auth", "generated"}}, "purposes": served})
    return out


def _rescoped(data, roots):
    """A relisted target keeps the running features it served, and only those; a feature the integration does not run
    yet reaches it as it reaches any listed target. A target left with no feature is not offered."""
    scopes = data.get("previous_scopes") or []
    running = set(data.get("previous_plans") or {})
    out = []
    for root in roots:
        served = next((s["purposes"] for s in scopes if s["target"] == root["target"]), None)
        if served is not None:
            keep = [p for p in root.get("purposes", data["purposes"]) if p in served or p not in running]
            if not keep:
                continue
            root = {**root, "purposes": keep}
        out.append(root)
    return out


def _queue(repo, row, action):
    from cremore.domain.models import ScanJob

    row = SessionStore(repo).save(row, {**row["data"], "state": "WORKING", "error": None})
    job = repo.enqueue_job(ScanJob(kind=service.CHECK_JOB,
        payload={"onboarding_session_id": str(row["id"]), "revision": row["revision"] + 1, "action": action}))
    return SessionStore(repo).save(row, {**row["data"], "job_id": str(job.id)})


def discover(repo, sid, body, actor):
    with atomic(repo) as bound:
        row = _get(bound, sid, actor, body)
        _expected(row, body)
        if row["data"].get("authentication", {}).get("status") != "GRANTED":
            raise service.OnboardingError("AUTHENTICATION_REQUIRED", 409)
        if body.get("more") is True:
            if row["data"]["state"] not in {"LISTED", "CHECKED", "SELECTED"} or not row["data"].get("discovery_cursor"):
                raise service.OnboardingError("ONBOARDING_PAGE_UNAVAILABLE", 409)
            row = SessionStore(bound).save(row, {**row["data"], "checks": {}, "resources": [],
                "selected_targets": [], "selected_resources": [], "selected_roots": [], "snapshot_id": None})
            return public(_queue(bound, row, "discover"))
        purposes = _checked_purposes(row["data"], body.get("purposes"))
        data = {**row["data"], "purposes": purposes, "held_purposes": [], "plans": {}, "checks": {}, "resources": [],
                "selected_targets": [], "selected_resources": [], "snapshot_id": None,
                "roots": [], "discovery_cursor": None}
        row = SessionStore(bound).save(row, data)
        if data["auth_method"] == "google_oauth" and not data["target"].get("auth", {}).get("oauth_cloud_access"):
            return public(SessionStore(bound).save(row, {**data, "state": "AWAITING_OAUTH"}))
        return public(_queue(bound, row, "discover"))


def _checked_purposes(data, given):
    """The rules a draft's feature set meets when discovery sets it and when inspect narrows it."""
    purposes = service._purposes(catalog.descriptor(data["provider"]), given)
    # A v3 credential cannot change execution domains after authentication.
    # The console starts a separate acting connection for remediation.
    if any(str(ref).startswith("sealed:v3:") for ref in data["secret_refs"].values()):
        intent = "remediator" if purposes == ["remediation"] else "collector"
        if intent != data.get("credential_purpose", "collector"):
            raise service.OnboardingError("CREDENTIAL_PURPOSE_REAUTHENTICATION_REQUIRED", 409)
    if set(purposes) & set(data.get("disabled_purposes") or []):
        raise service.OnboardingError("TARGET_EDIT_PAUSED_FEATURE", 409)
    if data.get("editing") and set(data["previous_plans"]) - set(purposes):
        raise service.OnboardingError("TARGET_EDIT_KEEP_FEATURES", 409)
    service._method(data["provider"], purposes, data["auth_method"], data["edition"])
    return purposes


def inspect(repo, sid, body, actor):
    with atomic(repo) as bound:
        row = _get(bound, sid, actor, body)
        _expected(row, body)
        data = row["data"]
        if (data["state"] not in {"LISTED", "CHECKED", "SELECTED", "FAILED"}
                or data.get("authentication", {}).get("status") != "GRANTED"):
            raise service.OnboardingError("ONBOARDING_TARGETS_REQUIRED", 409)
        ids = body.get("target_ids")
        roots = {root["id"]: root for root in data.get("roots", [])}
        if (not isinstance(ids, list) or not ids or len(ids) > 100 or any(not isinstance(i, str) or i not in roots for i in ids)
                or len(set(ids)) != len(ids)):
            raise service.OnboardingError("ONBOARDING_TARGETS_INVALID")
        # A target the integration collects from that this listing lacks (a later page, a suspended installation) is not
        # evidence it is gone, but completion would replace it away: it must be listed, or removed explicitly.
        if data.get("editing") and len(data.get("previous_target_ids") or []) < len(data.get("previous_targets") or []):
            raise service.OnboardingError("ONBOARDING_EXISTING_TARGET_NOT_LISTED", 409)
        given = body.get("plans")
        if not isinstance(given, dict) or not given or set(given) - set(data["purposes"]):
            raise service.OnboardingError("PURPOSES_INVALID")
        dropped = sorted(set(data["purposes"]) - set(given))
        if dropped:
            # Continuing with the features whose access passed only removes features: the narrowed set meets every
            # discovery rule, each target keeps only remaining features, and select/complete require them all again.
            narrowed = _checked_purposes(data, sorted(given))
            kept = {}
            for key, root in roots.items():
                if "purposes" in root:
                    root = {**root, "purposes": [p for p in root["purposes"] if p in narrowed]}
                    if not root["purposes"]:
                        continue
                kept[key] = root
            if any(i not in kept for i in ids):
                raise service.OnboardingError("ONBOARDING_TARGETS_INVALID")
            roots = kept
            data = {**data, "purposes": narrowed, "roots": list(kept.values()),
                    "held_purposes": sorted({*(data.get("held_purposes") or []), *dropped})}
        if "target_purposes" in body:
            roots, data = _scoped(data, roots, ids, body["target_purposes"])
        candidate = _candidate({**data, "selected_targets": sorted(ids)})
        plans = {p: targets.normalize_plan(candidate, p, v) for p, v in given.items()}
        for purpose, plan in plans.items():
            allowed_options = {}
            for root in (roots[i] for i in ids if purpose in roots[i].get("purposes", data["purposes"])):
                for name, allowed in root.get("plan_options", {}).items():
                    allowed_options.setdefault(name, set()).update(allowed)
            for name, allowed in allowed_options.items():
                if set(plan.get(name) or []) - allowed:
                    raise service.OnboardingError("ONBOARDING_OPTION_NOT_LISTED")
        data = {**data, "selected_targets": sorted(ids), "plans": plans, "checks": {},
                "resources": [], "selected_resources": [], "snapshot_id": None}
        row = SessionStore(bound).save(row, data)
        if dropped:
            _audit(bound, row, "ONBOARDING_PURPOSES_NARROWED", note="held:" + ",".join(dropped))
        return public(_queue(bound, row, "inspect"))


def _scoped(data, roots, ids, given):
    """Selected roots limited to some of their features, as a content card adds a scan location to an account without
    widening the account's other features to it. A root an edited integration already uses keeps every running
    feature it served, and every feature keeps a selected root."""
    if not isinstance(given, dict) or set(given) - set(ids):
        raise service.OnboardingError("ONBOARDING_TARGETS_INVALID")
    previous = set(data.get("previous_target_ids") or [])
    running = set(data.get("previous_plans") or {})
    roots = dict(roots)
    for key, chosen in given.items():
        serves = roots[key].get("purposes", data["purposes"])
        if (not isinstance(chosen, list) or not chosen or not all(isinstance(p, str) for p in chosen)
                or len(set(chosen)) != len(chosen) or set(chosen) - set(serves)
                or (key in previous and set(serves) & running - set(chosen))):
            raise service.OnboardingError("ONBOARDING_TARGETS_INVALID")
        roots[key] = {**roots[key], "purposes": [p for p in serves if p in chosen]}
    if any(not any(p in roots[i].get("purposes", data["purposes"]) for i in ids) for p in data["purposes"]):
        raise service.OnboardingError("ONBOARDING_TARGETS_INVALID")
    return roots, {**data, "roots": list(roots.values())}


def select(repo, sid, body, actor):
    with atomic(repo) as bound:
        row = _get(bound, sid, actor, body)
        _expected(row, body)
        if row["data"]["state"] not in {"CHECKED", "SELECTED"}:
            raise service.OnboardingError("PERMISSION_CHECK_REQUIRED", 409)
        candidate = _candidate(row["data"])
        permissions.require(candidate, row["data"]["plans"])
        ids = body.get("resource_ids", [])
        from cremore.scanning import scope

        listed = row["data"].get("resources", [])
        known = {r["id"]: r for r in listed if scope.selectable(r)}
        if (not isinstance(ids, list) or len(ids) > 10000 or any(not isinstance(i, str) or i not in known for i in ids)
                or len(set(ids)) != len(ids) or ("exposure" in candidate["purposes"] and not ids)):
            raise service.OnboardingError("ONBOARDING_RESOURCES_INVALID")
        if body.get("snapshot_id") != row["data"].get("snapshot_id"):
            raise service.OnboardingError("ONBOARDING_SNAPSHOT_CHANGED", 409)
        roots = body.get("selected_roots", [
            {"resource_id": i, "all_current_objects": known[i]["resource_type"] in {"S3_BUCKET"},
             **({"page_mode": "PAGE_ONLY"} if known[i]["resource_type"] == "NOTION_PAGE" else {})} for i in ids])
        roots = scope.validate_profile_input({"name": "Onboarding", "change_reason": "ONBOARDING_SELECTION",
            "budgets": {"bytes": 104857600, "requests": 1000, "seconds": 600}, "selected_roots": roots})["selected_roots"]
        if {r["resource_id"] for r in roots} != set(ids):
            raise service.OnboardingError("ONBOARDING_RESOURCES_INVALID")
        for root in roots:
            item = known[root["resource_id"]]
            problem = scope._root_problem(root, item)
            if problem:
                raise service.OnboardingError(problem)
            if root.get("descendant_ids"):
                children = {r["provider_resource_id"] for r in listed if r["source_key"] == item["source_key"]
                            and r.get("parent_id") == item["provider_resource_id"] and scope.selectable(r)
                            and r["resource_type"] == "NOTION_PAGE"}
                if set(root["descendant_ids"]) - children:
                    raise service.OnboardingError("ONBOARDING_RESOURCES_INVALID")
        if "exposure" in candidate["purposes"] and {r["source_key"] for r in known.values()} - {known[i]["source_key"] for i in ids}:
            raise service.OnboardingError("ONBOARDING_EACH_TARGET_NEEDS_RESOURCES")
        return public(SessionStore(bound).save(row, {**row["data"], "selected_resources": sorted(ids),
            "selected_roots": roots, "state": "SELECTED"}))


def _candidate(data):
    chosen = [root for root in data.get("roots", []) if root["id"] in data.get("selected_targets", [])]
    context = data["target"]
    target = {**context, **chosen[0]["target"]} if len(chosen) == 1 and set(chosen[0].get("purposes", data["purposes"])) == set(data["purposes"]) else {
        **context, "version": 2, "roots": [{k: r[k] for k in ("id", "target", "purposes") if k in r} for r in chosen]}
    return {k: data[k] for k in ("provider", "edition", "auth_method", "secret_refs", "purposes")} | {
        "target": target, "plans": {}, "checks": data.get("checks") or {}, "status": "CHECKED",
        "disabled_purposes": list(data.get("disabled_purposes") or [])}


def complete(repo, settings, sid, body, actor):
    with atomic(repo) as bound:
        row = _get(bound, sid, actor, body, terminal=True, lock=True)
        if row["data"]["state"] == "COMPLETED":
            return service.view(bound, service.get(bound, row["data"]["connection_id"]))
        _expected(row, body)
        if body.get("authentication_only") is True:
            data = row["data"]
            if data.get("credential_purpose") == "remediator":
                raise service.OnboardingError("REMEDIATION_FEATURE_REQUIRED", 409)
            if (data["state"] != "AUTHENTICATED" or data.get("authentication", {}).get("status") != "GRANTED"
                    or data.get("editing") or data.get("purposes") or data.get("plans")):
                raise service.OnboardingError("ONBOARDING_AUTHENTICATION_ONLY_UNAVAILABLE", 409)
            if set(body) - {"browser_key", "expected_revision", "name", "authentication_only"}:
                raise service.OnboardingError("ONBOARDING_AUTHENTICATION_ONLY_INVALID")
            name = body.get("name")
            if not isinstance(name, str) or not service._TEXT.fullmatch(name.strip()):
                raise service.OnboardingError("NAME_INVALID")
            # An authenticated credential owner has no approved collection target,
            # child, scope, schedule or permission receipt. Activation still requires
            # a new bound session and the normal target/access checks below.
            candidate = {k: data[k] for k in ("provider", "edition", "auth_method", "secret_refs", "target")}
            candidate.update(name=name.strip(), purposes=[], plans={}, status="CHECKED",
                             checks={"authentication_only": True, "checked_at": _now().isoformat()})
            record = ProviderConnectionStore(bound).create(candidate, actor)
            service._audit(bound, record["id"], actor, "PROVIDER_CONNECTION_AUTHENTICATED", record["provider"])
            SessionStore(bound).save(row, {"state": "COMPLETED", "connection_id": str(record["id"])})
            _audit(bound, row, "ONBOARDING_COMPLETED")
            return service.view(bound, record)
        if row["data"]["state"] != "SELECTED":
            raise service.OnboardingError("ONBOARDING_REVIEW_REQUIRED", 409)
        schedules = body.get("schedules", {})
        if not isinstance(schedules, dict) or set(schedules) - set(row["data"]["purposes"]):
            raise service.OnboardingError("ONBOARDING_SCHEDULE_INVALID")
        # Whether a new scope scans what changed when its provider says so (absent: yes, where a provider can).
        if not isinstance(body.get("change_scans", True), bool):
            raise service.OnboardingError("ONBOARDING_CHANGE_SCANS_INVALID")
        plans = {p: dict(plan) for p, plan in row["data"]["plans"].items()}
        descriptor = catalog.descriptor(row["data"]["provider"])
        for purpose, selected in schedules.items():
            # The original scalar remains the primary interval. A map lets a
            # provider expose independent cadences in the same final review.
            chosen = selected if isinstance(selected, dict) else {"schedule_minutes": selected}
            fields = {f["name"]: f for f in catalog.schedule_fields(descriptor["provider"], purpose)}
            for name, minutes in chosen.items():
                field = fields.get(name)
                exposure = purpose == "exposure" and name in {"schedule_minutes", "full_scan_minutes"}
                full = exposure and name == "full_scan_minutes"
                if full and minutes is None:
                    continue  # the installation default, whatever it is when the scan comes due
                if (not exposure and (field is None or name not in plans[purpose]) or type(minutes) is not int
                        or minutes != 0 and not (60 if full else 5) <= minutes <= (1440 if full else 43200 if exposure else field.get("max", 10080))):
                    raise service.OnboardingError("ONBOARDING_SCHEDULE_INVALID")
                if minutes and not settings.scan_schedules_allowed:
                    raise service.OnboardingError("SCAN_SCHEDULES_DISABLED", 409)
                if exposure and minutes:
                    from cremore.scanning import trigger_settings

                    if not trigger_settings.schedules_on(settings, bound):
                        raise service.OnboardingError("EXPOSURE_SCHEDULES_DISABLED", 409)
                if field is not None:
                    plans[purpose][name] = service._field_value(field, minutes)
        # Schedule edits do not change provider access. The existing permission
        # gate ignores only declared cadences; all target/value-read choices stay pinned.
        row = {**row, "data": {**row["data"], "plans": plans}}
        candidate = _candidate(row["data"])
        permissions.require(candidate, row["data"]["plans"])
        name = body.get("name")
        if not isinstance(name, str) or not service._TEXT.fullmatch(name.strip()):
            raise service.OnboardingError("NAME_INVALID")
        candidate["name"] = name.strip()
        module = catalog.module(candidate["provider"])
        for root in targets.records_of(candidate):
            refused = service.sign_in.problem(settings, root["provider"], root["target"], root["purposes"], repo=bound,
                                              excluding=row["data"].get("editing"))
            if refused:
                raise service.OnboardingError(refused, 409)
            ready = getattr(module, "ready", None)
            if callable(ready):
                ready(bound, settings, root)
        if "aws_investigations" in body:
            from cremore_aws_provider.investigation import investigation_switches

            options = body["aws_investigations"]
            if (candidate["provider"] != "aws" or not isinstance(options, dict)
                    or set(options) != {"changes", "expected"} or not isinstance(options["changes"], dict)
                    or not isinstance(options["expected"], dict)
                    or set(options["changes"]) - set(investigation_switches.onboarding_keys(candidate["purposes"]))):
                raise service.OnboardingError("AWS_INVESTIGATIONS_INVALID")
            try:
                investigation_switches.save(bound, settings, options["changes"], actor, expected=options["expected"])
            except investigation_switches.SettingsError as exc:
                raise service.OnboardingError(str(exc), exc.status) from None
        if row["data"].get("editing"):
            record = service.get(bound, row["data"]["editing"])
            if record["revision"] != row["data"]["owner_revision"]:
                raise service.OnboardingError("PROVIDER_CONNECTION_CHANGED", 409)
            if record.get("checks", {}).get("authentication_only") is True and not record["plans"]:
                record = ProviderConnectionStore(bound).update(record["id"], record["revision"], actor,
                    **{k: candidate[k] for k in ("target", "name", "purposes", "plans", "checks", "status")})
            else:
                result = service.replace_targets(bound, settings, record, candidate, row["data"]["plans"], actor)
                _save_scopes(bound, row, result, actor, schedules=schedules, change_scans=body.get("change_scans", True))
                SessionStore(bound).save(row, {"state": "COMPLETED", "connection_id": result["id"]})
                _audit(bound, row, "ONBOARDING_COMPLETED")
                return result
        else:
            record = ProviderConnectionStore(bound).create(candidate, actor)
            service._audit(bound, record["id"], actor, "PROVIDER_CONNECTION_CREATED", record["provider"])
        prepare = getattr(module, "prepare", None)
        if callable(prepare):
            from cremore.onboarding import children

            for root in targets.records_of(record):
                for purpose, child in service._children_of(prepare(root)):
                    children.create(bound, settings, record, purpose, child, actor)
        result = service.activate(bound, settings, record["id"], {"purposes": row["data"]["plans"]}, actor)
        _save_scopes(bound, row, result, actor, schedules=schedules, change_scans=body.get("change_scans", True))
        SessionStore(bound).save(row, {"state": "COMPLETED", "connection_id": result["id"]})
        _audit(bound, row, "ONBOARDING_COMPLETED")
        return result


def _save_scopes(repo, row, result, actor, *, schedules=None, change_scans=True):
    """Approve each exposure child's selection as its scope profile. A new profile scans what changed whenever its
    provider can say so (``change_scans`` turns that off); an existing one keeps its name, budgets and run settings."""
    from cremore.db.catalog_store import CatalogStore
    from cremore.domain.models import ScopeCatalog, ScopeProfile
    from cremore.scanning import scope, triggers

    data = row["data"]
    selected = set(data.get("selected_resources", []))
    selections = {r["resource_id"]: r for r in data.get("selected_roots", [])}
    for link in ProviderConnectionStore(repo).children(result["id"]):
        if link["kind"] not in {"content", "aws_account"} or "exposure" not in data["purposes"]:
            continue
        kind = "aws" if link["kind"] == "aws_account" else "source"
        source = (repo.get_aws_account if kind == "aws" else repo.get_connection)(uuid.UUID(link["child_id"]))
        if kind == "source" and source.status == "DISABLED":
            continue
        # The draft's description key identifies the child; labels never identify a target.
        from cremore.sources.registry import PROVIDERS

        key = "aws:" + source.account_id if kind == "aws" else _content_key({
            "source_type": PROVIDERS[source.provider].SOURCE_TYPE, "config": source.config})
        if kind == "source":
            evidence = data.get("source_evidence", {}).get(key)
            if not evidence or evidence.get("status") != "ACTIVE":
                raise service.OnboardingError("AUTHENTICATION_REQUIRED", 409)
            source = repo.update_connection(source.id, credential_evidence=evidence, status="ACTIVE", last_verified_at=_now())
        listed = [r for r in data.get("resources", []) if r["source_key"] == key]
        remap = {r["id"]: scope.resource_id(kind, source.id, r["resource_type"], r["provider_resource_id"]) for r in listed}
        resources, roots = [], []
        for item in listed:
            projected = {k: v for k, v in item.items() if k != "source_key"}
            projected["id"] = remap[item["id"]]
            if "parent_id" in projected:
                projected["parent_id"] = remap.get(projected["parent_id"], projected["parent_id"])
            if "known_root_ids" in projected:
                projected["known_root_ids"] = [remap.get(i, i) for i in projected["known_root_ids"]]
            resources.append(projected)
            if item["id"] in selected:
                roots.append({**selections[item["id"]], "resource_id": projected["id"]})
        if not roots:
            raise service.OnboardingError("ONBOARDING_RESOURCES_INVALID")
        snapshot = str(uuid.uuid4())
        auth = scope.auth_revision(kind, source)
        CatalogStore(repo).refresh(ScopeCatalog(kind=kind, connection_id=source.id, snapshot_id=snapshot,
            auth_revision=auth, completeness=data["completeness"], refreshed_at=_now()), resources)
        existing = repo.list_scope_profiles(kind, source.id)
        if len(existing) > 1:
            raise service.OnboardingError("ONBOARDING_MULTIPLE_SCOPES_USE_EDITOR", 409)
        preserved = {key: getattr(existing[0], key) for key in
            ("name", "budgets", "excluded_ids", "schedule_minutes", "full_scan_minutes", "event_mode")} if existing else {}
        cadence = (schedules or {}).get("exposure", {})
        cadence = cadence if isinstance(cadence, dict) else {"schedule_minutes": cadence}
        chosen = {r["resource_id"] for r in roots}
        events = change_scans and any(triggers.change_triggered(r["resource_type"]) for r in resources if r["id"] in chosen)
        fields = scope.validate_profile_input({"name": result["name"], "change_reason": "ONBOARDING_SELECTION",
            "selected_roots": roots, "catalog_snapshot_id": snapshot,
            "budgets": dict(scope.DEFAULT_BUDGET), "event_mode": "ENABLED" if events else "DISABLED",
            "schedule_minutes": data["plans"]["exposure"].get("schedule_minutes", 0), **preserved,
            **cadence})
        fields.pop("expected_version")
        if row["data"].get("editing") and {str(p.id): p.version for p in existing} != row["data"]["profile_versions"].get(str(source.id), {}):
            raise service.OnboardingError("SCOPE_VERSION_CONFLICT", 409)
        if existing:
            current = existing[0]
            saved = repo.update_scope_profile(current.id, expected_version=current.version, version=current.version + 1,
                state="PAUSED" if current.state == "PAUSED" else "READY", auth_revision=auth, approved_by=actor, approved_at=_now(), **fields)
            if saved is None:
                raise service.OnboardingError("SCOPE_VERSION_CONFLICT", 409)
        else:
            repo.create_scope_profile(ScopeProfile(kind=kind, connection_id=source.id, state="READY",
                auth_revision=auth, approved_by=actor, approved_at=_now(), **fields))
        service._audit(repo, result["id"], actor, "ONBOARDING_SCOPE_APPROVED", str(source.id))


def _content_key(child):
    from cremore.onboarding.children import content_coordinate
    from cremore.sources.registry import BY_SOURCE

    return targets.target_id({"source_type": child["source_type"],
        "config": content_coordinate(BY_SOURCE[child["source_type"]], child.get("config") or {})})


def _existing_selection(repo, data):
    """Translate existing approved selections to this draft's resource IDs."""
    from cremore.scanning import scope
    from cremore.sources.registry import PROVIDERS

    selected = []
    for link in ProviderConnectionStore(repo).children(data["editing"]):
        if link["kind"] != "content":
            continue
        source = repo.get_connection(uuid.UUID(link["child_id"]))
        if source is None:
            continue
        key = _content_key({"source_type": PROVIDERS[source.provider].SOURCE_TYPE, "config": source.config})
        listed = [r for r in data["resources"] if r["source_key"] == key]
        if not listed:
            continue
        profiles = repo.list_scope_profiles("source", source.id)
        if len(profiles) > 1:
            raise service.OnboardingError("ONBOARDING_MULTIPLE_SCOPES_USE_EDITOR", 409)
        remap = {scope.resource_id("source", source.id, r["resource_type"], r["provider_resource_id"]): r["id"] for r in listed}
        for profile in profiles:
            for root in profile.selected_roots:
                if root["resource_id"] not in remap:
                    raise service.OnboardingError("ONBOARDING_EXISTING_SCOPE_NOT_LISTED", 409)
                selected.append({**root, "resource_id": remap[root["resource_id"]]})
    data.update(selected_roots=selected, selected_resources=[r["resource_id"] for r in selected])


def _end(repo, row, state):
    row = SessionStore(repo).save(row, {"state": state})
    _audit(repo, row, "ONBOARDING_" + state)
    return public(row)


def cancel(repo, sid, body, actor):
    with atomic(repo) as bound:
        row = _get(bound, sid, actor, body, terminal=True)
        if row["data"]["state"] in TERMINAL:
            return public(row)
        return _end(bound, row, "CANCELLED")


def expire(repo, now):
    for row in SessionStore(repo).expired(now):
        try:
            with atomic(repo) as bound:
                _end(bound, row, "EXPIRED")
        except ProviderConnectionConflict:
            continue


def run(worker, job, *, write_context=None):
    """Bounded, fenced metadata work; no provider calls while a DB lock is held."""
    payload = job.payload
    row = SessionStore(worker.repo).get(payload["onboarding_session_id"])
    write = write_context or (lambda: nullcontext(worker.repo))
    if row is None or row["revision"] != payload["revision"] or row["data"]["state"] != "WORKING":
        with write() as repo:
            repo.complete_job(job.id, objects=0, findings=0)
        return
    data = dict(row["data"])
    started, requests = time.monotonic(), 0

    def alive():
        with write() as repo:
            current = SessionStore(repo).get(row["id"])
            if (current is None or current["revision"] != row["revision"] or current["expires_at"] <= _now()
                    or (repo.get_job(job.id) and repo.get_job(job.id).status == "CANCELLED")):
                raise service.OnboardingError("ONBOARDING_SESSION_CHANGED", 409)
        if time.monotonic() - started > 120:
            raise service.OnboardingError("ONBOARDING_TIME_LIMIT")

    def before_request():
        nonlocal requests
        alive()
        requests += 1
        if requests > 100:
            raise service.OnboardingError("ONBOARDING_REQUEST_LIMIT")

    secrets = {}
    try:
        alive()
        secrets = check.open_secrets(worker, data)
        module = catalog.module(data["provider"])
        with ExitStack() as stack:
            # The existing bounded_request calls this client's stream/request;
            # charge/check *every* request, including pagination and retries.
            def client_factory(**kwargs):
                client = worker.http_client_factory(**kwargs)
                stack.callback(client.close)
                return _Client(client, before_request)

            context = check.CheckContext(worker.repo, worker.settings, client_factory,
                getattr(worker, "aws_role_checker", None), getattr(worker, "aws_sessions", None), write=write,
                before_request=before_request)
            action = payload["action"]
            if action == "authenticate":
                answer = module.authenticate(data, secrets, context)
                data["authentication"] = check.clean([{"permission": "authentication", **answer}], [{"id": "authentication"}])[0]
                data["state"] = "AUTHENTICATED" if data["authentication"]["status"] == "GRANTED" else "AUTH_FAILED"
            elif action == "discover":
                answer = module.discover(data, secrets, context)
                roots, completeness = answer[:2]
                found = {r["id"]: r for r in data.get("roots", [])}
                found.update({r["id"]: r for r in _roots(data, roots)})
                if len(found) > 10000:
                    raise service.OnboardingError("ONBOARDING_TARGET_LIMIT")
                data["roots"] = _rescoped(data, list(found.values()))
                data["previous_target_ids"] = [r["id"] for r in data["roots"] if r["target"] in data.get("previous_targets", [])]
                data["discovery_cursor"] = answer[2] if len(answer) == 3 else None
                data["completeness"] = completeness if completeness in {"COMPLETE", "PARTIAL"} else "PARTIAL"
                data["state"] = "LISTED"
            elif action == "inspect":
                candidate = _candidate(data)
                candidate["checks"] = {"requested_plans": data["plans"]}
                results = check.evaluate(candidate, secrets, context)
                data["checks"] = {"requested_plans": data["plans"], "results": results,
                    "checked_at": _now().isoformat(), "digest": service.check_digest(candidate), "stale": False}
                marks = check.credential_marks(worker.settings, targets.records_of(candidate)[0], secrets, module, context)
                data["checks"].update(credential_marks=marks or [], credential_marks_unknown=marks is None)
                candidate["checks"] = data["checks"]
                if not permissions.blockers(candidate, data["plans"]) and "exposure" in data["purposes"]:
                    data["resources"], data["completeness"], data["source_evidence"] = _resources(worker, candidate, row["id"], context)
                    if data.get("editing"):
                        _existing_selection(worker.repo, data)
                data["snapshot_id"] = str(uuid.uuid4())
                data["state"] = "CHECKED"
            else:
                raise service.OnboardingError("ONBOARDING_ACTION_INVALID")
        alive()
    except Exception as exc:  # noqa: BLE001 -- retain a fixed code, never a response or token
        data.update(state="FAILED", error=check._code(exc))
    finally:
        for envelope in secrets.values():
            envelope.clear()
    with write() as repo:
        current = SessionStore(repo).get(row["id"])
        if current and current["revision"] == row["revision"]:
            if current["expires_at"] <= _now():
                _end(repo, current, "EXPIRED")
            else:
                SessionStore(repo).save(row, data)
        repo.complete_job(job.id, objects=0, findings=0)


class _Client:
    def __init__(self, client, before):
        self.client, self._before = client, before

    def request(self, *args, **kwargs):
        self._before()
        return self.client.request(*args, **kwargs)

    def stream(self, *args, **kwargs):
        self._before()
        return self.client.stream(*args, **kwargs)

    def close(self):
        pass  # ExitStack owns the underlying client's lifetime.

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def _roots(data, roots):
    descriptor = catalog.descriptor(data["provider"])
    module = catalog.module(data["provider"])
    if not isinstance(roots, list) or len(roots) > 10000:
        raise service.OnboardingError("ONBOARDING_TARGETS_INVALID")
    out = {}
    for root in roots:
        values = service._fields(descriptor.get("target") or [], root["target"], data["edition"])
        values = module.target(data["provider"], data["edition"], values) if hasattr(module, "target") else values
        key = targets.target_id(values)
        # Display names are bounded metadata; they never select a target or endpoint.
        label = str(root.get("label") or key)[:200]
        if any(ord(c) < 32 for c in label):
            label = key
        out[key] = {"id": key, "target": values, "label": label}
        if "purposes" in root:
            supported = root["purposes"]
            if (not isinstance(supported, list) or not supported or any(p not in data["purposes"] for p in supported)):
                raise service.OnboardingError("ONBOARDING_TARGETS_INVALID")
            out[key]["purposes"] = sorted(set(supported))
        options = root.get("plan_options")
        if options:
            fields = {f["name"] for spec in descriptor["purposes"].values() for f in spec.get("plan") or []
                      if f["kind"] in {"list", "choices"}}
            if (not isinstance(options, dict) or set(options) - fields
                    or any(not isinstance(items, list) or len(items) > 500
                           or any(not isinstance(i, str) or not service._LIST_ITEM.fullmatch(i) for i in items)
                           for items in options.values())):
                raise service.OnboardingError("ONBOARDING_OPTIONS_INVALID")
            out[key]["plan_options"] = options
    return list(out.values())


def _resources(worker, record, sid, context):
    from cremore.collectors.base import RequestBudget
    from cremore.domain.connections import job_payload_for, validate_connection
    from cremore.domain.models import Connection
    from cremore.scanning.catalog import list_resources
    from cremore.secretstore.resolver import inject_secret
    from cremore.sources.registry import BY_SOURCE

    listed, complete, evidence = [], "COMPLETE", {}
    module = catalog.module(record["provider"])
    resolver = worker.metadata_secret_resolver
    if (getattr(worker.settings, "isolated_deployment", False)
            or any(str(ref).startswith("sealed:v3:") for ref in record["secret_refs"].values())):
        from cremore.secretstore.isolation import binding_for_record

        # These sources are generated from the checked draft above; no persisted
        # child exists yet. Bind to that owner, never to a job/envelope header.
        resolver = resolver.bound(binding_for_record(record))
    budget = RequestBudget(limit=100)
    list_scope = getattr(module, "list_onboarding_scope", None)
    if callable(list_scope):
        return list_scope(record, sid, context, budget)
    for child in targets.described(module, record, "exposure", record["checks"]["requested_plans"]["exposure"]):
        if child["kind"] != "content":
            raise service.OnboardingError("AUTH_FIRST_SCOPE_NOT_SUPPORTED")
        source_module = BY_SOURCE[child["source_type"]]
        source = Connection(provider=source_module.PROVIDER, name=child["name"],
                            config=child.get("config") or {}, secret_ref=record["secret_refs"].get("credential"))
        validate_connection(source)
        key = _content_key({**child, "config": source.config})
        payload = {**job_payload_for(source), "provider": source.provider, "connection_kind": "source",
                   "connection_id": str(uuid.uuid5(sid, key)), "secret_ref": source.secret_ref}
        payload = inject_secret("catalog-refresh", payload, resolver,
                                github_client_factory=context.http_client, http_client_factory=context.http_client)
        try:
            identity = source_module.check_credential(payload, http_client_factory=context.http_client)
            if identity.status != "ACTIVE":
                raise service.OnboardingError("AUTHENTICATION_REQUIRED", 409)
            evidence[key] = identity.as_evidence(_now().isoformat())
            items, completeness = list_resources(payload, http_client=context.http_client, request_budget=budget)
            listed.extend({**i, "source_key": key} for i in items)
            if len(listed) > 10000:
                raise service.OnboardingError("ONBOARDING_RESOURCE_LIMIT")
            if completeness != "COMPLETE":
                complete = "PARTIAL"
        finally:
            payload.pop("token", None)
    return listed, complete, evidence
