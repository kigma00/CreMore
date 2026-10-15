"""Scan-scope logic: catalog queries, profile validation, plans, rescan targets."""

import datetime as _dt
import uuid

import pytest

from cremore.domain.models import Exposure, Finding, ScanJob, ScopeCatalog, ScopePlan, ScopeProfile
from cremore.scanning import scope

CID = uuid.uuid4()
NOW = _dt.datetime(2026, 9, 14, tzinfo=_dt.UTC)


def bucket(name, **extra):
    return scope.resource("aws", CID, "S3_BUCKET", name, name, f"arn:aws:s3:::{name}", "aws", now=NOW, **extra)


def repo_item(full, **extra):
    return scope.resource("source", CID, "GITHUB_REPOSITORY", full, full, f"https://github.com/{full}", "github.com",
                          now=NOW, **extra)


def catalog(items, kind="aws"):
    return ScopeCatalog(kind=kind, connection_id=CID, snapshot_id="snap1", auth_revision="auth1", items=items,
                        completeness="COMPLETE", refreshed_at=NOW)


def test_resource_ids_are_stable_and_metadata_only():
    a, b = bucket("logs"), bucket("logs")
    assert a["id"] == b["id"] and a["content_readiness"] == "NOT_PROBED" and a["list_visibility"] == "VISIBLE"
    assert scope.selectable(a) and not scope.selectable({**a, "list_visibility": "DENIED"})


def test_catalog_query_filters_sorts_and_pages_with_snapshot_bound_cursor():
    items = [bucket("logs", region="us-east-1"), bucket("archive", region="eu-west-1"), bucket("logs-old")]
    cat = catalog(items)
    page = scope.catalog_page(cat, "aws", CID, "aws", "auth1", scope.normalize_query({"q": "logs", "page_size": "1"}))
    assert page["known_count"] == 2 and [i["display_name"] for i in page["items"]] == ["logs"] and page["has_more"]
    assert page["next_cursor"] == "snap1:1" and page["count_accuracy"] == "EXACT" and "region" in page["available_filters"]
    nxt = scope.catalog_page(cat, "aws", CID, "aws", "auth1", scope.normalize_query({"q": "logs", "page_size": "1", "cursor": "snap1:1"}))
    assert [i["display_name"] for i in nxt["items"]] == ["logs-old"] and not nxt["has_more"]
    with pytest.raises(scope.ScopeError) as exc:
        scope.catalog_page(cat, "aws", CID, "aws", "auth1", scope.normalize_query({"cursor": "old:1"}))
    assert exc.value.http_status == 410
    # exact metadata filters; UNKNOWN matches missing metadata; date bounds exclude unknown dates
    q = scope.normalize_query({"region": "UNKNOWN"})
    assert [i["display_name"] for i in scope.filter_items(items, q)] == ["logs-old"]
    q = scope.normalize_query({"synced_after": "2026-09-14T00:00:00Z", "synced_before": "2026-09-14T23:59:59.999999999Z"})
    assert len(scope.filter_items(items, q)) == 3
    q = scope.normalize_query({"selected": "true", "selected_ids": [items[1]["id"]]})
    assert [i["display_name"] for i in scope.filter_items(items, q)] == ["archive"]
    # an empty (never collected) catalog is reported as such, never as a clean empty listing
    empty = scope.catalog_page(None, "aws", CID, "aws", "auth1", scope.normalize_query({}))
    assert empty["catalog_snapshot_id"] == "" and empty["reason_code"] == "NOT_COLLECTED" and empty["last_refreshed_at"].startswith("0001-")
    with pytest.raises(scope.ScopeError):
        scope.normalize_query({"sort": "random"})


def test_profile_input_is_validated_and_normalised():
    fields = scope.validate_profile_input({
        "name": "prod buckets", "change_reason": "baseline", "expected_version": 0,
        "selected_roots": [{"resource_id": "r1", "all_current_objects": True, "prefixes": ["a/", "a/"], "excluded_prefixes": [],
                            "paths": [], "excluded_paths": [], "descendant_ids": [], "include_future_descendants": False}],
        "excluded_ids": [], "budgets": {"bytes": 1024, "requests": 10, "seconds": 60}, "schedule_minutes": 0,
        "event_mode": "DISABLED", "catalog_snapshot_id": "snap1"})
    assert fields["selected_roots"][0]["prefixes"] == ["a/"] and "ref" not in fields["selected_roots"][0]
    for bad in ({"name": "", "change_reason": "x"}, {"name": "x", "change_reason": "x", "budgets": {"bytes": 0, "requests": 1, "seconds": 1}},
                {"name": "x", "change_reason": "x", "budgets": {"bytes": 1, "requests": 1, "seconds": 1}, "schedule_minutes": 3},
                {"name": "x", "change_reason": "x", "budgets": {"bytes": 1, "requests": 1, "seconds": 1},
                 "selected_roots": [{"resource_id": "a"}, {"resource_id": "a"}]}):
        with pytest.raises(scope.ScopeError):
            scope.validate_profile_input(bad)


def profile(roots, **kw):
    base = {"id": uuid.uuid4(), "kind": "aws", "connection_id": CID, "name": "p", "version": 1, "selected_roots": roots, "excluded_ids": [],
                "budgets": {"bytes": 10, "requests": 10, "seconds": 10}, "catalog_snapshot_id": "snap1", "auth_revision": "auth1"}
    base.update(kw)
    return ScopeProfile(**base)


@pytest.mark.parametrize("field", ["all_current_objects", "include_future_descendants"])
@pytest.mark.parametrize("value", ["false", "true", 0, 1, None, [], {}])
def test_scope_approval_flags_require_actual_booleans(field, value):
    with pytest.raises(scope.ScopeError, match="must be a boolean"):
        scope.validate_profile_input({
            "name": "approved", "change_reason": "operator choice",
            "budgets": {"bytes": 10, "requests": 10, "seconds": 10},
            "selected_roots": [{"resource_id": "r1", field: value}],
        })


@pytest.mark.parametrize("field", ["name", "change_reason"])
def test_required_scope_text_cannot_be_only_whitespace(field):
    body = {"name": "approved", "change_reason": "operator choice",
            "budgets": {"bytes": 10, "requests": 10, "seconds": 10}, field: " \u2003 "}
    with pytest.raises(scope.ScopeError):
        scope.validate_profile_input(body)


@pytest.mark.parametrize("value", [None, False, "", {}])
def test_malformed_root_collection_does_not_silently_clear_approval(value):
    with pytest.raises(scope.ScopeError):
        scope.validate_profile_input({
            "name": "approved", "change_reason": "operator choice", "selected_roots": value,
            "budgets": {"bytes": 10, "requests": 10, "seconds": 10},
        })


def test_plan_resolves_known_roots_and_blocks_unsafe_selections():
    logs = bucket("logs")
    cat = catalog([logs])
    root = {"resource_id": logs["id"], "all_current_objects": True, "prefixes": [], "excluded_prefixes": [], "paths": [],
            "excluded_paths": [], "descendant_ids": [], "include_future_descendants": False}
    plan = scope.build_plan(profile([root, {**root, "resource_id": "ghost"}]), cat, auth="auth1", enabled=True, now=NOW)
    assert not plan.executable and plan.known_count == 1 and plan.unresolved_count == 1
    assert plan.warnings == ["UNRESOLVED_ROOTS_SKIPPED"] and len(plan.policy_digest) == 64
    assert plan.roots[0]["provider_resource_id"] == "logs" and plan.expires_at == NOW + scope.PLAN_TTL
    # a bucket without an explicit object selection is not executable
    blocked = scope.build_plan(profile([{**root, "all_current_objects": False}]), cat, auth="auth1", enabled=True, now=NOW)
    assert not blocked.executable and "BUCKET_OBJECT_SELECTION_REQUIRED" in blocked.warnings
    # authorization changed / connection paused / nothing selected
    assert "NEEDS_SCOPE_REVIEW" in scope.build_plan(profile([root]), cat, auth="auth2", enabled=True).warnings
    assert "CONNECTION_PAUSED" in scope.build_plan(profile([root]), cat, auth="auth1", enabled=False).warnings
    none = scope.build_plan(profile([root], excluded_ids=[logs["id"]]), cat, auth="auth1", enabled=True)
    assert not none.executable and "NO_TARGETS_SELECTED" in none.warnings
    assert scope.profile_state(profile([root]), auth="auth1", enabled=True) == "READY"
    assert scope.profile_state(profile([root]), auth="x", enabled=True) == "NEEDS_SCOPE_REVIEW"
    assert scope.connection_state(["NO_TARGETS_SELECTED", "READY"], enabled=True) == "READY"
    # future descendants and schedules are declared, never silently executed
    future = scope.build_plan(profile([{**root, "include_future_descendants": True}], schedule_minutes=30, event_mode="ENABLED"),
                              cat, auth="auth1", enabled=True)
    assert not future.executable and {"FUTURE_DESCENDANTS_NOT_SUPPORTED", "SCHEDULE_NOT_CONFIGURED", "EVENTS_NOT_CONFIGURED"} <= set(future.warnings)


def test_rescan_target_is_one_exact_location_inside_the_approved_scope():
    repo = repo_item("example-org/app", default_branch="main")
    cat = catalog([repo], kind="source")
    root = {"resource_id": repo["id"], "all_current_objects": False, "prefixes": [], "excluded_prefixes": [],
            "paths": ["src/"], "excluded_paths": ["src/vendor/"], "descendant_ids": [], "include_future_descendants": False}
    prof = profile([root], kind="source")
    finding = Finding(id=uuid.uuid4(), credential_id=uuid.uuid4(), primary_exposure_id=uuid.uuid4(), severity="HIGH")
    exposure = Exposure(id=uuid.uuid4(), credential_id=finding.credential_id, source_type="github",
                        resource_name="example-org/app", location="src/config.py", source_connection_id=CID)
    exact, target = scope.rescan_target(finding, exposure, prof, cat)
    assert exact["exact_paths"] == ["src/config.py"] and exact["ref"] == "refs/heads/main" and target["ref"] == "refs/heads/main"
    assert target["resource_id"] == repo["id"] and len(target["evidence_digest"]) == 64 and target["source_type"] == "github"
    with pytest.raises(scope.ScopeError) as exc:
        scope.rescan_target(finding, exposure.model_copy(update={"location": "src/vendor/x.py"}), prof, cat)
    assert exc.value.code == "RESCAN_OUT_OF_SCOPE"
    with pytest.raises(scope.ScopeError) as exc:
        scope.rescan_target(finding, exposure.model_copy(update={"resource_name": "example-org/other"}), prof, cat)
    assert exc.value.code == "RESCAN_RESOURCE_NOT_IN_CATALOG"


@pytest.mark.parametrize("resource_type, source_type, name, location", [
    ("GITHUB_REPOSITORY", "github", "example-org/app", "src/config.py"),
    ("GITLAB_REPOSITORY", "gitlab", "group/app", "src/config.py"),
    ("BITBUCKET_REPOSITORY", "bitbucket", "workspace/app", "src/config.py"),
    ("AZURE_DEVOPS_REPOSITORY", "azure_devops", "org/project/app", "src/config.py"),
    ("CONFLUENCE_PAGE", "confluence", "123456", "123456/body"),
    ("WEBSITE", "website", "acme.test", "https://acme.test/app.js.map!/webpack://app/src/config.ts"),
])
def test_an_exact_rescan_of_every_path_source_is_confirmed_as_planned(resource_type, source_type, name, location):
    # Confirming a rescan rechecks its plan against the approved root with the ref rescan_target chose.
    from types import SimpleNamespace

    item = scope.resource("source", CID, resource_type, name, name, name, "host", now=NOW)
    connection = SimpleNamespace(id=CID, status="ACTIVE", secret_ref=None, credential_evidence={})
    auth = scope.auth_revision("source", connection)
    root = {"resource_id": item["id"], "all_current_objects": False, "prefixes": [], "excluded_prefixes": [],
            "paths": [], "excluded_paths": [], "descendant_ids": [], "include_future_descendants": False}
    prof = profile([root], kind="source", auth_revision=auth)
    finding = Finding(id=uuid.uuid4(), credential_id=uuid.uuid4(), primary_exposure_id=uuid.uuid4(), severity="HIGH")
    exposure = Exposure(id=uuid.uuid4(), credential_id=finding.credential_id, source_type=source_type,
                        resource_name=name, location=location, source_connection_id=CID)
    exact, target = scope.rescan_target(finding, exposure, prof, catalog([item], kind="source"))
    plan = ScopePlan(kind="source", connection_id=CID, profile_id=prof.id, profile_version=prof.version,
                     auth_revision=auth, resources=[item], roots=[exact], known_count=1, executable=True,
                     trigger="RESCAN", rescan_target=target)
    scope.validate_execution(plan, prof, connection)


def test_a_rescan_says_when_the_approved_scope_itself_cannot_bound_a_read():
    item = scope.resource("source", CID, "WEBSITE", "acme.test", "acme.test", "https://acme.test/", "host", now=NOW)
    root = {"resource_id": item["id"], "all_current_objects": False, "prefixes": [], "excluded_prefixes": [],
            "paths": [], "excluded_paths": ["admin/"], "descendant_ids": [], "include_future_descendants": False}
    finding = Finding(id=uuid.uuid4(), credential_id=uuid.uuid4(), primary_exposure_id=uuid.uuid4(), severity="HIGH")
    exposure = Exposure(id=uuid.uuid4(), credential_id=finding.credential_id, source_type="website",
                        resource_name="acme.test", location="https://acme.test/app.js", source_connection_id=CID)
    with pytest.raises(scope.ScopeError) as exc:
        scope.rescan_target(finding, exposure, profile([root], kind="source"), catalog([item], kind="source"))
    assert exc.value.code == "WEBSITE_SCOPE_PATH_INVALID"


def test_run_projection_reports_partial_coverage_honestly():
    job = ScanJob(id=uuid.uuid4(), kind="scope", status="SUCCEEDED", objects=3, objects_failed=1,
                  payload={"profile_id": "p", "profile_version": 2, "plan_id": "plan", "trigger": "BASELINE"},
                  coverage={"attempted": 5, "succeeded": 3, "failed": 1, "skipped": 1, "bytes": 120, "requests": 9,
                            "roots_failed": 0, "stopped_reason": "BUDGET_BYTES"}, created_at=NOW, finished_at=NOW)
    run = scope.run_public(job, "aws", CID)
    assert run["status"] == "PARTIAL" and run["skipped"] == 1 and run["reason_code"] == "BUDGET_BYTES"
    assert run["scope_snapshot_id"] == "plan" and run["count_status"] == "OBSERVED_OBJECTS_ONLY" and run["content_bytes"] == 120
    clean = scope.run_public(job.model_copy(update={"objects_failed": 0, "coverage": None}), "aws", CID)
    assert clean["status"] == "COMPLETED" and clean["attempted"] == 3 and "reason_code" not in clean
    assert clean["engine_name"] == clean["engine_version"] == scope.NOT_RECORDED
    recorded = scope.run_public(job.model_copy(update={"coverage": {
        "engine_name": "saved-engine", "engine_version": "saved-version"}}), "aws", CID)
    assert (recorded["engine_name"], recorded["engine_version"]) == ("saved-engine", "saved-version")
