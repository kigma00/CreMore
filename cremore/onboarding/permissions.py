"""Required access for the exact choices an administrator is about to activate.

A completed worker job is not a successful permission check. The catalog owns
which reads are required; only explicit GRANTED answers satisfy those reads.
"""

from datetime import UTC, datetime, timedelta

from cremore.onboarding import catalog, targets

CHECK_MAX_AGE = timedelta(minutes=30)


def required(record, purpose, plan):
    effective = getattr(catalog.module(record["provider"]), "permission_plan", None)
    plan = effective(record, purpose, plan) if callable(effective) else plan
    return [p for p in catalog.permissions_for(record["provider"], purpose, record["auth_method"], record["target"])
            if p.get("required", True) and not (p.get("option") and plan.get(p["option"]) is not True)
            and not (p.get("nonempty") and not plan.get(p["nonempty"]))
            and not (p.get("unless") and plan.get(p["unless"]) is True)]


def access_plan(plan, *, record=None, purpose=None):
    schedules = {f["name"] for f in catalog.schedule_fields(record["provider"], purpose)} if record else {"schedule_minutes"}
    return {key: value for key, value in plan.items() if key not in schedules}


def reductions_only(before, after, *, record=None, purpose=None):
    """Only descriptor-backed removal of optional reads needs no new access."""
    optional = set()
    schedules = {"schedule_minutes"}
    if record is not None:
        schedules.update(f["name"] for f in catalog.schedule_fields(record["provider"], purpose))
        declared = catalog.descriptor(record["provider"])["purposes"][purpose].get("permissions") or []
        optional = {p["option"] for p in declared if p.get("option")} - {p["unless"] for p in declared if p.get("unless")}
    for name in set(before) | set(after):
        if name in schedules or before.get(name) == after.get(name):
            continue
        if name in optional and before.get(name) is True and after.get(name) is False:
            continue
        # An empty list may mean "all", and false may disable a restriction
        # (for example creation-only events). Do not infer a scope reduction.
        return False
    return True


def blockers(record, plans, *, now=None):
    """Safe, displayable failures; credentials and provider responses never leave here."""
    from cremore.onboarding.service import check_digest

    checks = record.get("checks") or {}
    now = now or datetime.now(UTC)
    try:
        at = datetime.fromisoformat(checks["checked_at"])
        fresh = at.tzinfo is not None and now - CHECK_MAX_AGE <= at <= now
    except (KeyError, TypeError, ValueError):
        fresh = False
    if (not fresh or checks.get("stale") or checks.get("digest") != check_digest(record)
            or any(purpose not in checks.get("requested_plans", {}) or
                   access_plan(checks["requested_plans"][purpose], record=record, purpose=purpose)
                   != access_plan(plan, record=record, purpose=purpose) for purpose, plan in plans.items())):
        return [{"status": "NOT_REPORTED", "detail": "PERMISSION_CHECK_REQUIRED"}]
    out = []
    for purpose, plan in plans.items():
        answers = (checks.get("results", {}).get(purpose) or {}).get("items") or []
        roots = targets.records_of(record, purpose)
        if not roots:
            out.append({"purpose": purpose, "status": "MISSING", "detail": "ONBOARDING_EACH_FEATURE_NEEDS_TARGET"})
        for root in roots:
            for permission in required(root, purpose, plan):
                found = [item for item in answers if item.get("permission") == permission["id"]
                         and item.get("target_id") == root.get("target_id")]
                subjects_for = getattr(catalog.module(root["provider"]), "permission_subjects", None)
                subjects = subjects_for(root, purpose, permission["id"], plan) if callable(subjects_for) else []
                found.extend({"permission": permission["id"], "subject": subject, "status": "NOT_REPORTED",
                              "detail": "NOT_CHECKED"} for subject in subjects
                             if not any(item.get("subject") == subject for item in found))
                if not found:
                    found = [{"permission": permission["id"], "status": "NOT_REPORTED", "detail": "NOT_CHECKED"}]
                # A grant for one target does not cancel a refusal for another.
                out.extend({"purpose": purpose, **item} for item in found if item.get("status") != "GRANTED")
    return out


def require(record, plans, *, now=None):
    from cremore.onboarding.service import OnboardingError

    missing = blockers(record, plans, now=now)
    if missing:
        code = "PERMISSION_CHECK_REQUIRED" if missing[0].get("detail") == "PERMISSION_CHECK_REQUIRED" else "REQUIRED_PERMISSIONS_NOT_GRANTED"
        raise OnboardingError(code, 409)


def scope_reduction(existing, fields):
    """Removing whole roots/excluding IDs does not acquire any new access."""
    if existing is None:
        return not fields["selected_roots"]
    old = {r["resource_id"]: r for r in existing.selected_roots}
    return (all(old.get(r["resource_id"]) == r for r in fields["selected_roots"])
            and set(existing.excluded_ids) <= set(fields["excluded_ids"]))


def require_scope(repo, kind, cid, fields, existing=None):
    """The same gate covers the existing scope API as the initial wizard."""
    from cremore.db.catalog_store import CatalogStore
    from cremore.onboarding import service
    from cremore.onboarding.store import ProviderConnectionStore, active_plans
    from cremore.scanning import scope

    if scope_reduction(existing, fields):
        return
    owner = ProviderConnectionStore(repo).parent_of("aws_account" if kind == "aws" else "content", cid)
    if owner:
        record = service.get(repo, owner)
        if record["status"] != "ACTIVE" or "exposure" not in active_plans(record):
            raise service.OnboardingError("PROVIDER_CONNECTION_NOT_ACTIVE", 409)
        require(record, {"exposure": record["plans"]["exposure"]})
    ids = [r["resource_id"] for r in fields["selected_roots"]]
    listed = CatalogStore(repo).selected(kind, cid, ids)
    now = datetime.now(UTC)
    if (listed is None or listed.snapshot_id != fields["catalog_snapshot_id"]
            or listed.refreshed_at is None or listed.refreshed_at.tzinfo is None
            or not now - CHECK_MAX_AGE <= listed.refreshed_at <= now):
        raise service.OnboardingError("SCOPE_CATALOG_RECHECK_REQUIRED", 409)
    current = (repo.get_aws_account if kind == "aws" else repo.get_connection)(cid)
    if current is None or listed.auth_revision != scope.auth_revision(kind, current):
        raise service.OnboardingError("SCOPE_CATALOG_RECHECK_REQUIRED", 409)
    by_id = {r["id"]: r for r in listed.items}
    if any(i not in by_id or not scope.selectable(by_id[i]) for i in ids):
        raise service.OnboardingError("ONBOARDING_RESOURCES_INVALID", 409)
