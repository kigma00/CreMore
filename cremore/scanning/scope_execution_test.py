import datetime as dt
import uuid
from types import SimpleNamespace

import pytest

from cremore.domain.models import ScopeCatalog, ScopeProfile
from cremore.scanning import scope


def test_execution_rechecks_profile_options_authorization_and_only_preview_expiry():
    cid = uuid.uuid4()
    target = SimpleNamespace(id=cid, provider="github", status="ACTIVE", secret_ref="vault://github/org", credential_evidence={})
    item = scope.resource("source", cid, "GITHUB_REPOSITORY", "org/repo", "org/repo", "https://github.com/org/repo", "github.com")
    root = {"resource_id": item["id"], "all_current_objects": False, "include_future_descendants": False, "paths": ["src/"]}
    profile = ScopeProfile(id=uuid.uuid4(), kind="source", connection_id=cid, name="approved", selected_roots=[root],
                           auth_revision=scope.auth_revision("source", target), catalog_snapshot_id="s")
    catalog = ScopeCatalog(kind="source", connection_id=cid, snapshot_id="s", items=[item])
    plan = scope.build_plan(profile, catalog, auth=profile.auth_revision, enabled=True)
    scope.validate_execution(plan, profile, target, require_unexpired=True)
    plan.expires_at = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)
    scope.validate_execution(plan, profile, target)  # An already queued approval does not expire mid-run.
    with pytest.raises(scope.ScopeError, match="prepare a new preview"):
        scope.validate_execution(plan, profile, target, require_unexpired=True)
    profile.selected_roots[0]["paths"] = ["elsewhere/"]
    with pytest.raises(scope.ScopeError, match="root policy changed"):
        scope.validate_execution(plan, profile, target)
    profile.selected_roots[0]["paths"] = ["src/"]
    target.secret_ref = "vault://github/another"
    with pytest.raises(scope.ScopeError, match="authorization changed"):
        scope.validate_execution(plan, profile, target)


def test_priority_exclusions_and_configured_trigger_warnings_are_explicit():
    cid = uuid.uuid4()
    resources = [scope.resource("aws", cid, "S3_BUCKET", name, name, name, "aws") for name in ("low", "high", "excluded")]
    roots = [{"resource_id": i["id"], "priority": n, "all_current_objects": True, "include_future_descendants": False}
             for i, n in zip(resources, [0, 50, 100], strict=True)]
    profile = ScopeProfile(id=uuid.uuid4(), kind="aws", connection_id=cid, name="p", selected_roots=roots,
                           excluded_ids=[resources[-1]["id"]], schedule_minutes=5, event_mode="ENABLED")
    assert [r["priority"] for r in scope.effective_roots(profile)] == [50, 0]
    catalog = ScopeCatalog(kind="aws", connection_id=cid, items=resources)
    ordinary = scope.build_plan(profile, catalog, auth="", enabled=True)
    configured = scope.build_plan(profile, catalog, auth="", enabled=True, configured_triggers={"SCHEDULE", "EVENT"})
    assert "SCHEDULE_NOT_CONFIGURED" in ordinary.warnings and "EVENTS_NOT_CONFIGURED" in ordinary.warnings
    assert "SCHEDULE_NOT_CONFIGURED" not in configured.warnings and "EVENTS_NOT_CONFIGURED" not in configured.warnings


def _approved(provider, resource_type, references, options):
    cid = uuid.uuid4()
    target = SimpleNamespace(id=cid, provider=provider, status="ACTIVE", secret_ref="", credential_evidence={})
    items = [scope.resource("source", cid, resource_type, ref, ref, ref, provider) for ref in references]
    roots = [scope._root({"resource_id": item["id"], **options}) for item in items]
    profile = ScopeProfile(id=uuid.uuid4(), kind="source", connection_id=cid, name="approved", selected_roots=roots,
                           auth_revision=scope.auth_revision("source", target))
    catalog = ScopeCatalog(kind="source", connection_id=cid, items=items)
    plan = scope.build_plan(profile, catalog, auth=profile.auth_revision, enabled=True)
    return target, profile, plan


def test_event_subset_must_retain_provider_identity_and_exact_approved_paths():
    target, profile, plan = _approved("github", "GITHUB_REPOSITORY", ["org/one", "org/two"],
        {"paths": ["src/"], "excluded_paths": ["src/private/"]})
    plan.trigger = "EVENT"
    plan.roots = [{**plan.roots[0], "exact_paths": ["src/settings.py"]}]
    scope.validate_execution(plan, profile, target)
    plan.roots[0]["exact_paths"] = ["src/private/settings.py"]
    with pytest.raises(scope.ScopeError, match="root policy changed"):
        scope.validate_execution(plan, profile, target)
    plan.roots[0]["exact_paths"] = ["src/settings.py"]
    plan.roots[0]["provider_resource_id"] = "org/unapproved"
    with pytest.raises(scope.ScopeError, match="root policy changed"):
        scope.validate_execution(plan, profile, target)
    plan.roots[0]["provider_resource_id"] = "org/one"
    plan.trigger = "BASELINE"
    with pytest.raises(scope.ScopeError, match="root selection changed"):
        scope.validate_execution(plan, profile, target)


def test_policy_sweep_only_accepts_derived_s3_prefix_shards():
    target, profile, plan = _approved("aws", "S3_BUCKET", ["bucket"],
        {"prefixes": ["approved/", "another/"], "excluded_prefixes": ["approved/private/"]})
    plan.trigger = "POLICY_SWEEP"
    plan.roots = [scope.split_roots(plan.roots)[0]]
    scope.validate_execution(plan, profile, target)
    plan.roots[0]["prefixes"] = ["unapproved/"]
    with pytest.raises(scope.ScopeError, match="root policy changed"):
        scope.validate_execution(plan, profile, target)


def test_policy_sweep_notion_child_is_separate_but_never_outside_explicit_approval():
    parent, child = "a" * 32, "b" * 32
    target, profile, plan = _approved("notion", "NOTION_PAGE", [parent],
        {"page_mode": "PAGE_WITH_DESCENDANTS", "descendant_ids": [child]})
    plan.trigger = "POLICY_SWEEP"
    plan.roots = [r for r in scope.split_roots(plan.roots) if r["provider_resource_id"] == child]
    scope.validate_execution(plan, profile, target)
    plan.roots[0].update(provider_resource_id="c" * 32, exact_page_ids=["c" * 32])
    with pytest.raises(scope.ScopeError, match="root policy changed"):
        scope.validate_execution(plan, profile, target)


def test_exact_rescan_of_independently_catalogued_approved_child():
    parent, child = "a" * 32, "b" * 32
    target, profile, plan = _approved("notion", "NOTION_PAGE", [parent],
        {"page_mode": "PAGE_WITH_DESCENDANTS", "descendant_ids": [child]})
    item = scope.resource("source", profile.connection_id, "NOTION_PAGE", child, child, child, "notion")
    plan.trigger = "RESCAN"
    plan.resources = [item]
    plan.roots = [{**scope._plan_root(profile.selected_roots[0], item), "exact_page_ids": [child]}]
    scope.validate_execution(plan, profile, target)
    profile.selected_roots[0]["page_mode"] = "PAGE_ONLY"
    with pytest.raises(scope.ScopeError, match="root policy changed"):
        scope.validate_execution(plan, profile, target)


def test_inventory_report_coverage_is_not_reported_as_full_root_scan():
    from cremore.domain.models import ScanJob

    cid = uuid.uuid4()
    job = ScanJob(id=uuid.uuid4(), kind="scope", status="SUCCEEDED", connection_id=cid, payload={"mode": "INVENTORY"},
        coverage={"root_coverage_complete": False, "coverage_basis": "INVENTORY_REPORT_ONLY", "succeeded": 5})
    public = scope.run_public(job, "source", cid)
    assert public["status"] == "PARTIAL" and public.get("result_status") != "SCANNED"
    assert public["root_coverage_complete"] is False and public["coverage_basis"] == "INVENTORY_REPORT_ONLY"
