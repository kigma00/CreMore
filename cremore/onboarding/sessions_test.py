"""Auth-first onboarding with fake Notion, including the transaction boundary."""

import datetime as dt
import json
import uuid
from types import SimpleNamespace

import httpx
import pytest

from cremore.config import Settings
from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414 -- opt-in isolated DB fixture
from cremore.db.repository import InMemoryRepository
from cremore.onboarding import check, service, sessions
from cremore.onboarding.session_store import SessionStore
from cremore.onboarding.store import ProviderConnectionStore
from cremore.secretstore.resolver import SecretResolver

SETTINGS = Settings(FINGERPRINT_KEY="ab" * 32)
KEY = "a" * 43
TOKEN = "synthetic-notion-token-never-real"
PAGE = "b3adca1f-3017-45b2-82d0-cbb25c3e9f24"



@pytest.fixture(params=["memory", "sqlite"])
def repo(request, tmp_path):
    if request.param == "memory":
        yield InMemoryRepository()
        return
    from cremore.db.sql import SqlRepository, create_all, make_engine

    engine = make_engine("sqlite:///" + str(tmp_path / "onboarding.sqlite"))
    create_all(engine)
    yield SqlRepository(engine)
    engine.dispose()


def start(repo):
    return sessions.create(repo, SETTINGS, {"browser_key": KEY, "provider": "notion", "edition": "standard",
        "auth_method": "integration", "credential": {"token": TOKEN}}, "admin")


def body(view, **extra):
    return {"browser_key": KEY, "expected_revision": view["revision"], **extra}


def finish_job(repo, view, *, denied=False, hook=None):
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path))
        if hook:
            hook()
        if request.url.path == "/v1/users/me":
            return httpx.Response(200, json={"object": "user", "id": "bot-id", "name": "Test bot",
                                            "bot": {"workspace_name": "Test workspace"}})
        assert request.url.path == "/v1/search", "no content or secret values may be read"
        if denied:
            return httpx.Response(403, json={"message": TOKEN})
        return httpx.Response(200, json={"results": [{"object": "page", "id": PAGE, "properties": {
            "Name": {"type": "title", "title": [{"plain_text": "PoC"}]}}, "parent": {"type": "workspace"}}],
            "has_more": False})

    worker = SimpleNamespace(repo=repo, settings=SETTINGS,
        metadata_secret_resolver=SecretResolver(sealing_key=SETTINGS.sealing_keys),
        http_client_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    check.run(worker, repo.get_job(uuid.UUID(view["job_id"])))
    return sessions.read(repo, view["id"], body(view), "admin"), calls


def inspect(repo):
    view = start(repo)
    assert not ProviderConnectionStore(repo).list()
    view, calls = finish_job(repo, view)
    assert calls == [("GET", "/v1/users/me")]
    assert view["state"] == "AUTHENTICATED" and not view.get("plans")
    view = sessions.discover(repo, view["id"], body(view, purposes=["exposure"]), "admin")
    view, calls = finish_job(repo, view)
    assert not calls
    view = sessions.inspect(repo, view["id"], body(view, target_ids=[view["roots"][0]["id"]],
                                                  plans={"exposure": {}}), "admin")
    return view


def selected(repo):
    view, _ = finish_job(repo, inspect(repo))
    assert view["state"] == "CHECKED", view
    assert view["resources"][0]["provider_resource_id"] == PAGE
    return sessions.select(repo, view["id"], body(view, snapshot_id=view["snapshot_id"],
                            resource_ids=[view["resources"][0]["id"]]), "admin")


def test_auth_then_metadata_then_one_atomic_completion(repo):
    view = selected(repo)
    assert not repo.list_connections()
    result = sessions.complete(repo, SETTINGS, view["id"], body(view, name="Test integration"), "admin")
    source = repo.list_connections()[0]
    profile = repo.list_scope_profiles("source", source.id)[0]
    from cremore.scanning import scope

    assert profile.auth_revision == scope.auth_revision("source", source)
    assert profile.selected_roots[0]["resource_id"] == scope.resource_id("source", source.id, "NOTION_PAGE", PAGE)
    assert profile.state == "READY" and profile.schedule_minutes == 0
    assert not any(job.kind == "scope" for job in repo.list_jobs(100))
    assert SessionStore(repo).get(view["id"])["data"] == {"state": "COMPLETED", "connection_id": result["id"]}
    again = sessions.complete(repo, SETTINGS, view["id"], body(view, name="ignored retry"), "admin")
    assert again["id"] == result["id"] and len(repo.list_connections()) == 1
    assert TOKEN not in json.dumps(result)


def test_account_authentication_creates_no_scan_and_content_reuses_the_credential_owner(repo):
    view, calls = finish_job(repo, start(repo))
    assert calls == [("GET", "/v1/users/me")]
    result = sessions.complete(repo, SETTINGS, view["id"], body(view, name="Notion account", authentication_only=True), "admin")
    assert result["checks"]["authentication_only"] and result["purposes"] == [] and not result["plans"]
    assert not result["children"] and not repo.list_connections()
    assert all(job.kind == service.CHECK_JOB for job in repo.list_jobs(100))
    original = ProviderConnectionStore(repo).get(result["id"])
    jobs = len(repo.list_jobs(100))
    with pytest.raises(service.OnboardingError, match="PURPOSES_INVALID"):
        service.request_check(repo, result["id"], "admin")
    assert len(repo.list_jobs(100)) == jobs
    assert sessions.complete(repo, SETTINGS, view["id"], body(view, name="retry", authentication_only=True), "admin")["id"] == result["id"]
    service.set_enabled(repo, result["id"], False, "admin")
    with pytest.raises(service.OnboardingError, match="TARGET_EDIT_NOT_SUPPORTED"):
        disabled = ProviderConnectionStore(repo).get(result["id"])
        sessions.edit(repo, SETTINGS, result["id"], {"browser_key": KEY, "expected_revision": disabled["revision"]}, "admin")
    result = service.set_enabled(repo, result["id"], True, "admin")
    assert result["status"] == "CHECKED" and not result["children"]
    view = sessions.edit(repo, SETTINGS, result["id"], {"browser_key": KEY, "expected_revision": result["revision"]}, "admin")
    view, _ = finish_job(repo, view)
    view = sessions.discover(repo, view["id"], body(view, purposes=["exposure"]), "admin")
    view, _ = finish_job(repo, view)
    view = sessions.inspect(repo, view["id"], body(view, target_ids=[view["roots"][0]["id"]], plans={"exposure": {}}), "admin")
    view, _ = finish_job(repo, view)
    view = sessions.select(repo, view["id"], body(view, snapshot_id=view["snapshot_id"], resource_ids=[view["resources"][0]["id"]]), "admin")
    updated = sessions.complete(repo, SETTINGS, view["id"], body(view, name="Notion account"), "admin")
    assert updated["id"] == result["id"] and updated["status"] == "ACTIVE"
    assert not updated["checks"]["authentication_only"] and len(repo.list_connections()) == 1
    assert ProviderConnectionStore(repo).get(result["id"])["secret_refs"] == original["secret_refs"]
    assert len(ProviderConnectionStore(repo).list()) == 1


def test_authentication_only_cannot_skip_authentication_or_create_a_schedule(repo):
    view = start(repo)
    with pytest.raises(service.OnboardingError, match="AUTHENTICATION_ONLY_UNAVAILABLE"):
        sessions.complete(repo, SETTINGS, view["id"], body(view, name="Notion", authentication_only=True), "admin")
    view, _ = finish_job(repo, view)
    with pytest.raises(service.OnboardingError, match="AUTHENTICATION_ONLY_INVALID"):
        sessions.complete(repo, SETTINGS, view["id"], body(view, name="Notion", authentication_only=True, schedules={"exposure": 5}), "admin")
    assert not ProviderConnectionStore(repo).list()


def test_postgres_account_lifecycle_and_content_activation(pg):
    test_account_authentication_creates_no_scan_and_content_reuses_the_credential_owner(pg[1])


def test_other_provider_cannot_change_aws_investigations(repo):
    view = selected(repo)
    with pytest.raises(service.OnboardingError, match="AWS_INVESTIGATIONS_INVALID"):
        sessions.complete(repo, SETTINGS, view["id"], body(view, name="Notion", aws_investigations={
            "changes": {"usage_lookup": True}, "expected": {"usage_lookup": False}}), "admin")
    assert not repo.list_connections()


def test_review_can_set_an_exposure_schedule_without_repeating_access_checks(repo):
    view = selected(repo)
    settings = SETTINGS.model_copy(update={"scan_schedules_mode": "enabled"})
    # Scheduled scans run by default; an Admin who switched them off (in this version) is asked to switch them on first.
    repo.put_setting("scan_triggers", {"schedules_enabled": False, "full_scan_default_minutes": 1440}, "admin")
    with pytest.raises(service.OnboardingError, match="EXPOSURE_SCHEDULES_DISABLED"):
        sessions.complete(repo, settings, view["id"], body(view, name="Scheduled", schedules={"exposure": 15}), "admin")
    repo.put_setting("scan_triggers", {"schedules_enabled": True}, "admin")
    result = sessions.complete(repo, settings, view["id"], body(view, name="Scheduled", schedules={"exposure": 15}), "admin")
    [source] = repo.list_connections()
    [profile] = repo.list_scope_profiles("source", source.id)
    assert profile.schedule_minutes == 15 and profile.state == "READY"
    assert result["status"] == "ACTIVE"
    again = sessions.complete(repo, settings, view["id"], body(view, name="Retry", schedules={"exposure": 0}), "admin")
    assert again["id"] == result["id"]
    assert repo.list_scope_profiles("source", source.id)[0].schedule_minutes == 15


@pytest.mark.parametrize("full,delta", [(1440, 15), (720, 0), (0, 5), (0, 0)])
def test_onboarding_saves_independent_full_and_incremental_cadences(repo, full, delta):
    view = selected(repo)
    repo.put_setting("scan_triggers", {"schedules_enabled": True}, "admin")
    sessions.complete(repo, SETTINGS, view["id"], body(view, name="Dual schedules", schedules={
        "exposure": {"full_scan_minutes": full, "schedule_minutes": delta}}), "admin")
    [source] = repo.list_connections()
    [profile] = repo.list_scope_profiles("source", source.id)
    assert (profile.full_scan_minutes, profile.schedule_minutes) == (full, delta)
    # Enough shared budget for hundreds of selected Notion pages, as in the scope editor.
    from cremore.scanning.scope import DEFAULT_BUDGET
    assert profile.budgets == DEFAULT_BUDGET


def test_a_new_scope_scans_what_changed_by_default_follows_the_installation_full_scan_and_can_opt_out(repo):
    """Notion has a change feed and a webhook: a new integration's scope scans what changed unless the final step's
    toggle is off, and with no full-scan choice (or the installation default, null) it follows the installation."""
    view = selected(repo)
    for value in ("yes", None, 1):
        with pytest.raises(service.OnboardingError, match="ONBOARDING_CHANGE_SCANS_INVALID"):
            sessions.complete(repo, SETTINGS, view["id"], body(view, name="Bad", change_scans=value), "admin")
    assert not repo.list_connections()
    sessions.complete(repo, SETTINGS, view["id"], body(view, name="Defaults", schedules={
        "exposure": {"full_scan_minutes": None, "schedule_minutes": 0}}), "admin")
    [profile] = repo.list_scope_profiles("source", repo.list_connections()[0].id)
    assert (profile.event_mode, profile.full_scan_minutes, profile.schedule_minutes) == ("ENABLED", None, 0)


@pytest.mark.parametrize("change_scans", [True, False])
def test_the_final_step_s_change_scan_toggle_sets_a_new_scope_and_never_an_existing_one(repo, change_scans):
    view = selected(repo)
    result = sessions.complete(repo, SETTINGS, view["id"], body(view, name="Toggle", change_scans=change_scans), "admin")
    source = repo.list_connections()[0]
    [profile] = repo.list_scope_profiles("source", source.id)
    chosen = "ENABLED" if change_scans else "DISABLED"
    assert profile.event_mode == chosen and profile.full_scan_minutes is None
    # Editing the integration later keeps the scope's own choice, whatever the toggle says.
    editing = sessions.edit(repo, SETTINGS, result["id"], {"browser_key": KEY, "expected_revision": result["revision"]}, "admin")
    editing, _ = finish_job(repo, editing)
    editing = sessions.discover(repo, editing["id"], body(editing, purposes=["exposure"]), "admin")
    editing, _ = finish_job(repo, editing)
    editing = sessions.inspect(repo, editing["id"], body(editing, target_ids=[editing["roots"][0]["id"]], plans={"exposure": {}}), "admin")
    editing, _ = finish_job(repo, editing)
    editing = sessions.select(repo, editing["id"], body(editing, snapshot_id=editing["snapshot_id"],
        resource_ids=editing["selected_resources"], selected_roots=editing["selected_roots"]), "admin")
    sessions.complete(repo, SETTINGS, editing["id"], body(editing, name="Toggle", change_scans=not change_scans,
                                                          schedules={"exposure": {"full_scan_minutes": 720}}), "admin")
    saved = repo.get_scope_profile(profile.id)
    assert saved.event_mode == chosen and saved.full_scan_minutes == 720


@pytest.mark.parametrize("value", [True, -1, 1, 59, 1441, "1440"])
def test_invalid_full_scan_cadence_never_creates_connection(repo, value):
    view = selected(repo)
    with pytest.raises(service.OnboardingError, match="ONBOARDING_SCHEDULE_INVALID"):
        sessions.complete(repo, SETTINGS, view["id"], body(view, name="Invalid", schedules={
            "exposure": {"full_scan_minutes": value}}), "admin")
    assert repo.list_connections() == []


@pytest.mark.parametrize("schedule", [True, -1, 1, "15", 43201])
def test_invalid_review_schedule_does_not_create_any_connection(repo, schedule):
    view = selected(repo)
    with pytest.raises(service.OnboardingError, match="ONBOARDING_SCHEDULE_INVALID"):
        sessions.complete(repo, SETTINGS, view["id"], body(view, name="Bad", schedules={"exposure": schedule}), "admin")
    assert not repo.list_connections()


def test_installation_schedule_lock_is_enforced_at_completion(repo):
    view = selected(repo)
    settings = SETTINGS.model_copy(update={"scan_schedules_mode": "disabled"})
    with pytest.raises(service.OnboardingError, match="SCAN_SCHEDULES_DISABLED"):
        sessions.complete(repo, settings, view["id"], body(view, name="Locked", schedules={"exposure": 5}), "admin")
    assert not repo.list_connections()


@pytest.mark.parametrize("override,expected_error", [
    ({"schedule_minutes": 15, "enterprise_schedule_minutes": 2880, "audit_schedule_minutes": 5}, None),
    ({"audit_schedule_minutes": True}, "ONBOARDING_SCHEDULE_INVALID"),
    ({"audit_schedule_minutes": 1}, "ONBOARDING_SCHEDULE_INVALID"),
    ({"enterprise_inventory": 0}, "ONBOARDING_SCHEDULE_INVALID"),
])
def test_final_review_changes_only_declared_github_cadences_atomically(repo, override, expected_error):
    from cremore_github_provider.onboarding_export_test import connection, plan

    from cremore.coverage.metadata_store import MetadataStore

    selected_plan = plan(audit_events=True, enterprise_audit=True)
    conn = connection()
    data = {k: conn[k] for k in ("provider", "edition", "auth_method", "secret_refs")}
    data.update(state="SELECTED", target={}, purposes=["inventory"], plans={"inventory": selected_plan},
        roots=[{"id": "r", "target": conn["target"]}], selected_targets=["r"], selected_resources=[],
        checks={"checked_at": sessions._now().isoformat(), "requested_plans": {"inventory": selected_plan},
                "results": {"inventory": {"items": [{"permission": p["id"], "status": "GRANTED"}
                    for p in service.catalog.permissions_for("github", "inventory", "github_app", conn["target"])]}}})
    data["checks"]["digest"] = service.check_digest(sessions._candidate(data))
    row = SessionStore(repo).create("admin", sessions._binding(KEY), data, sessions._now() + sessions.TTL)
    view = sessions.public(row)
    settings = SETTINGS.model_copy(update={"scan_schedules_mode": "enabled"})
    request = body(view, name="GitHub", schedules={"inventory": override})
    if expected_error:
        with pytest.raises(service.OnboardingError, match=expected_error):
            sessions.complete(repo, settings, view["id"], request, "admin")
        assert not ProviderConnectionStore(repo).list()
        assert not MetadataStore(repo).list_connections()
        return
    result = sessions.complete(repo, settings, view["id"], request, "admin")
    assert result["plans"]["inventory"] == {**selected_plan, **override}
    rows = MetadataStore(repo).list_connections()
    assert len(rows) == 4
    assert sorted(r["spec"]["schedule_minutes"] for r in rows) == [5, 5, 15, 2880]


def test_required_access_unknown_selection_and_foreign_browser_cannot_commit(repo):
    view, _ = finish_job(repo, inspect(repo), denied=True)
    assert TOKEN not in json.dumps(view)
    assert not view["resources"]
    with pytest.raises(service.OnboardingError, match="REQUIRED_PERMISSIONS_NOT_GRANTED"):
        sessions.select(repo, view["id"], body(view, snapshot_id=view["snapshot_id"]), "admin")
    with pytest.raises(service.OnboardingError, match="NOT_FOUND"):
        sessions.read(repo, view["id"], {"browser_key": "b" * 43}, "admin")
    with pytest.raises(service.OnboardingError, match="NOT_FOUND"):
        sessions.read(repo, view["id"], body(view), "other-admin")
    assert not repo.list_connections()


def test_failed_completion_rolls_back_and_cancel_or_expiry_drops_the_envelope(repo, monkeypatch):
    view = selected(repo)
    with monkeypatch.context() as patch:
        def fail(*_args, **_kwargs):
            raise ValueError("scope write failed")
        patch.setattr(sessions, "_save_scopes", fail)
        with pytest.raises(ValueError, match="scope write failed"):
            sessions.complete(repo, SETTINGS, view["id"], body(view, name="Rollback"), "admin")
    assert not repo.list_connections() and not ProviderConnectionStore(repo).list()
    assert sessions.cancel(repo, view["id"], body(view), "admin")["state"] == "CANCELLED"
    assert "secret_refs" not in SessionStore(repo).get(view["id"])["data"]
    other = start(repo)
    sessions.expire(repo, dt.datetime.now(dt.UTC) + dt.timedelta(hours=1))
    assert SessionStore(repo).get(other["id"])["data"] == {"state": "EXPIRED"}


def test_cancelled_or_changed_draft_cannot_receive_inflight_results(repo):
    view = start(repo)
    current, _ = finish_job(repo, view, hook=lambda: sessions.cancel(repo, view["id"], body(view), "admin"))
    assert current["state"] == "CANCELLED"
    assert "authentication" not in current


def test_scope_updates_reject_a_lost_revision(repo):
    from cremore.domain.models import ScopeProfile

    profile = repo.create_scope_profile(ScopeProfile(kind="source", connection_id=uuid.uuid4(), name="Synthetic"))
    assert repo.update_scope_profile(profile.id, expected_version=1, version=2, name="First").version == 2
    assert repo.update_scope_profile(profile.id, expected_version=1, version=2, name="Overwritten") is None
    assert repo.get_scope_profile(profile.id).name == "First"


def test_editing_reuses_auth_but_does_not_overwrite_another_edit(repo):
    view = selected(repo)
    result = sessions.complete(repo, SETTINGS, view["id"], body(view, name="Original"), "admin")
    editing = sessions.edit(repo, SETTINGS, result["id"], {"browser_key": KEY, "expected_revision": result["revision"]}, "admin")
    editing, _ = finish_job(repo, editing)
    editing = sessions.discover(repo, editing["id"], body(editing, purposes=["exposure"]), "admin")
    editing, _ = finish_job(repo, editing)
    editing = sessions.inspect(repo, editing["id"], body(editing, target_ids=[editing["roots"][0]["id"]], plans={"exposure": {}}), "admin")
    editing, _ = finish_job(repo, editing)
    editing = sessions.select(repo, editing["id"], body(editing, snapshot_id=editing["snapshot_id"],
        resource_ids=[editing["resources"][0]["id"]]), "admin")
    service.rename(repo, result["id"], {"name": "Other edit"}, "admin")
    with pytest.raises(service.OnboardingError, match="PROVIDER_CONNECTION_CHANGED"):
        sessions.complete(repo, SETTINGS, editing["id"], body(editing, name="Overwrite"), "admin")
    assert len(repo.list_connections()) == 1 and service.get(repo, result["id"])["name"] == "Other edit"


@pytest.mark.parametrize("missing", [False, True])
def test_editing_preserves_scope_details_exclusions_and_run_settings(repo, missing):
    view = selected(repo)
    result = sessions.complete(repo, SETTINGS, view["id"], body(view, name="Original"), "admin")
    source = repo.list_connections()[0]
    profile = repo.list_scope_profiles("source", source.id)[0]
    root = {**profile.selected_roots[0], "priority": 7}
    if missing:
        root["resource_id"] = "previously-approved-but-not-listed"
    version = profile.version
    settings = {"excluded_ids": ["previously-excluded"], "budgets": {"bytes": 123456, "requests": 500, "seconds": 120},
                "schedule_minutes": 60, "event_mode": "DISABLED", "state": "PAUSED"}
    repo.update_scope_profile(profile.id, selected_roots=[root], **settings)
    editing = sessions.edit(repo, SETTINGS, result["id"], {"browser_key": KEY, "expected_revision": result["revision"]}, "admin")
    editing, _ = finish_job(repo, editing)
    editing = sessions.discover(repo, editing["id"], body(editing, purposes=["exposure"]), "admin")
    editing, _ = finish_job(repo, editing)
    editing = sessions.inspect(repo, editing["id"], body(editing, target_ids=[editing["roots"][0]["id"]], plans={"exposure": {}}), "admin")
    editing, _ = finish_job(repo, editing)
    if missing:
        assert editing["state"] == "FAILED" and editing["error"] == "ONBOARDING_EXISTING_SCOPE_NOT_LISTED"
        assert repo.get_scope_profile(profile.id).selected_roots == [root]
        return
    assert editing["selected_roots"][0]["priority"] == 7 and editing["selected_resources"]
    editing = sessions.select(repo, editing["id"], body(editing, snapshot_id=editing["snapshot_id"],
        resource_ids=editing["selected_resources"], selected_roots=editing["selected_roots"]), "admin")
    sessions.complete(repo, SETTINGS, editing["id"], body(editing, name="Renamed"), "admin")
    saved = repo.get_scope_profile(profile.id)
    assert saved.selected_roots == [root] and saved.version == version + 1
    assert {key: getattr(saved, key) for key in settings} == settings


def test_database_rows_are_explicit_and_bound_to_their_parent(repo):
    from cremore.scanning import scope

    view, _ = finish_job(repo, inspect(repo))
    row = SessionStore(repo).get(view["id"])
    page = row["data"]["resources"][0]
    database = {**page, "id": "db-draft", "resource_type": "NOTION_DATA_SOURCE", "provider_resource_id": "db-provider"}
    page["parent_id"] = "db-provider"
    row = SessionStore(repo).save(row, {**row["data"], "resources": [database, page]})
    view = sessions.public(row)
    fields = body(view, snapshot_id=view["snapshot_id"], resource_ids=[database["id"]], selected_roots=[
        {"resource_id": database["id"], "page_mode": "DATA_SOURCE_SELECTED_PAGES", "descendant_ids": ["other-database-row"]}])
    with pytest.raises(service.OnboardingError, match="ONBOARDING_RESOURCES_INVALID"):
        sessions.select(repo, view["id"], fields, "admin")
    fields["selected_roots"][0]["descendant_ids"] = [PAGE]
    view = sessions.select(repo, view["id"], fields, "admin")
    sessions.complete(repo, SETTINGS, view["id"], body(view, name="Selected database rows"), "admin")
    source = repo.list_connections()[0]
    profile = repo.list_scope_profiles("source", source.id)[0]
    root = profile.selected_roots[0]
    assert root["resource_id"] == scope.resource_id("source", source.id, "NOTION_DATA_SOURCE", "db-provider")
    assert root["descendant_ids"] == [PAGE] and scope._root_problem(root, database) is None


def test_postgres_concurrent_completion_has_one_connection_and_scope(pg):
    from concurrent.futures import ThreadPoolExecutor

    repo = pg[1]
    view = selected(repo)
    with ThreadPoolExecutor(4) as pool:
        results = list(pool.map(lambda _: sessions.complete(repo, SETTINGS, view["id"],
            body(view, name="Concurrent completion"), "admin"), range(4)))
    assert len({result["id"] for result in results}) == 1
    assert len(ProviderConnectionStore(repo).list()) == 1
    assert len(repo.list_connections()) == 1
    assert len(repo.list_scope_profiles("source", repo.list_connections()[0].id)) == 1


def test_removed_normalized_sources_remain_off_without_provider_access(repo):
    from cremore.onboarding import targets
    from cremore.onboarding.fixtures_test import grant_access

    made = service.create(repo, SETTINGS, {"provider": "gitlab", "purposes": ["exposure"], "auth_method": "token",
        "target": {"scope": "group", "id": "1"}, "credential": {"token": "synthetic-gitlab-token"}}, "admin")
    store = ProviderConnectionStore(repo)
    current = store.get(made["id"])
    first = {k: v for k, v in current["target"].items() if k != "auth"}
    second = {**first, "id": "2"}
    roots = [{"id": targets.target_id(t), "target": t} for t in (first, second)]
    current = store.update(current["id"], current["revision"], "admin", target={"version": 2, "roots": roots})
    grant_access(repo, current["id"], {"exposure": {}})
    service.activate(repo, SETTINGS, current["id"], {"purposes": {"exposure": {}}}, "admin")
    current = store.get(current["id"])
    current = store.update(current["id"], current["revision"], "worker", checks={})
    reduced = service.remove_targets(repo, SETTINGS, current["id"], {"expected_revision": current["revision"],
        "target_ids": [roots[1]["id"]]}, "admin")
    assert len(repo.list_connections()) == 2
    assert sum(s.status == "DISABLED" for s in repo.list_connections()) == 1
    service.set_enabled(repo, reduced["id"], False, "admin")
    service.set_enabled(repo, reduced["id"], True, "admin")
    assert sum(s.status == "DISABLED" for s in repo.list_connections()) == 1
    disabled = next(s for s in repo.list_connections() if s.status == "DISABLED")
    before = len(repo.list_check_events(disabled.id))
    service.set_credential(repo, SETTINGS, reduced["id"], {"credential": {"token": "synthetic-replacement-token"}}, "admin")
    assert repo.get_connection(disabled.id).status == "DISABLED"
    assert len(repo.list_check_events(disabled.id)) == before
    owner_ref = store.get(reduced["id"])["secret_refs"]["credential"]
    assert all(s.secret_ref == owner_ref for s in repo.list_connections())
    with pytest.raises(service.OnboardingError, match="TARGETS_INVALID"):
        service.remove_targets(repo, SETTINGS, current["id"], {"target_ids": [roots[0]["id"]]}, "admin")


def test_postgres_scope_compare_and_swap_has_one_winner(pg):
    from concurrent.futures import ThreadPoolExecutor

    from cremore.domain.models import ScopeProfile

    repo = pg[1]
    profile = repo.create_scope_profile(ScopeProfile(kind="source", connection_id=uuid.uuid4(), name="Synthetic"))
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda name: repo.update_scope_profile(profile.id, expected_version=1,
                            version=2, name=name), ["First", "Second"]))
    assert sum(result is not None for result in results) == 1
    assert repo.get_scope_profile(profile.id).version == 2


def test_target_removal_stops_independently_reconfigured_collections(repo):
    from cremore.coverage.metadata_models import MetadataConnectionSpec
    from cremore.coverage.metadata_store import MetadataStore
    from cremore.onboarding import targets
    from cremore.onboarding.fixtures_test import grant_access

    made = service.create(repo, SETTINGS, {"provider": "gcp", "purposes": ["inventory"], "auth_method": "adc",
        "target": {"project": "synthetic-project-one"}}, "admin")
    store = ProviderConnectionStore(repo)
    current = store.get(made["id"])
    first = {k: v for k, v in current["target"].items() if k != "auth"}
    roots = [{"id": targets.target_id(t), "target": t} for t in (first, {**first, "project": "synthetic-project-two"})]
    current = store.update(current["id"], current["revision"], "admin", target={"version": 2, "roots": roots})
    grant_access(repo, current["id"], {"inventory": {}})
    service.activate(repo, SETTINGS, current["id"], {"purposes": {"inventory": {}}}, "admin")
    collections = MetadataStore(repo)
    row = next(r for r in collections.list_connections() if r["spec"]["scopes"][0]["id"] == first["project"])
    # This is an edit the existing metadata connection API allows.
    changed = MetadataConnectionSpec.model_validate({**row["spec"], "scopes": [{"kind": "project", "id": "synthetic-project-other"}]})
    collections.change(row["id"], row["revision"], "admin", spec=changed)
    current = store.get(current["id"])
    service.remove_targets(repo, SETTINGS, current["id"], {"expected_revision": current["revision"],
        "target_ids": [roots[1]["id"]]}, "admin")
    assert len(collections.list_connections()) == 2
    assert collections.get(row["id"])["enabled"] is False
    service.set_enabled(repo, current["id"], False, "admin")
    service.set_enabled(repo, current["id"], True, "admin")
    assert collections.get(row["id"])["enabled"] is False
    assert sum(r["enabled"] for r in collections.list_connections()) == 1


def test_plan_options_are_the_union_of_selected_roots_for_the_feature(repo):
    tenant = "11111111-1111-1111-1111-111111111111"
    subs = [f"{i:08d}-1111-1111-1111-111111111111" for i in range(1, 4)]
    accounts = [f"/subscriptions/{sub}/resourceGroups/synthetic/providers/Microsoft.Storage/storageAccounts/test{i}"
                for i, sub in enumerate(subs)]
    data = {"provider": "azure", "edition": "cloud", "auth_method": "workload_identity", "secret_refs": {},
            "target": {"tenant": tenant}, "purposes": ["inventory", "identity"], "plans": {}, "state": "LISTED",
            "authentication": {"status": "GRANTED"}}
    data["roots"] = sessions._roots(data, [
        {"target": {"tenant": tenant, "subscription": sub}, "purposes": ["inventory"],
         "plan_options": {"storage_key_accounts": [account]}} for sub, account in zip(subs, accounts, strict=True)] + [
        {"target": {"tenant": tenant}, "purposes": ["identity"], "plan_options": {"storage_key_accounts": ["unrelated"]}}])
    view = sessions.public(SessionStore(repo).create("admin", sessions._binding(KEY), data, sessions._now() + sessions.TTL))
    chosen = [data["roots"][i]["id"] for i in (0, 1, 3)]
    for rejected in (accounts[2], "unrelated"):
        with pytest.raises(service.OnboardingError, match="ONBOARDING_OPTION_NOT_LISTED"):
            sessions.inspect(repo, view["id"], body(view, target_ids=chosen,
                plans={"inventory": {"storage_key_accounts": [rejected]}, "identity": {}}), "admin")
    accepted = sessions.inspect(repo, view["id"], body(view, target_ids=chosen,
        plans={"inventory": {"storage_key_accounts": accounts[:2]}, "identity": {}}), "admin")
    assert accepted["state"] == "WORKING"
    assert accepted["plans"]["inventory"]["storage_key_accounts"] == accounts[:2]


TENANT = "11111111-1111-4111-8111-111111111111"
SUBSCRIPTION = "22222222-2222-4222-8222-222222222222"


def listed(repo, purposes, roots, **extra):
    """A Microsoft draft whose targets are listed, written directly: inspect reads only the draft."""
    data = {"provider": "azure", "edition": "cloud", "auth_method": "workload_identity", "secret_refs": {},
            "target": {"tenant": TENANT}, "purposes": purposes, "plans": {}, "state": "LISTED",
            "authentication": {"status": "GRANTED"}, **extra}
    data["roots"] = sessions._roots(data, roots)
    return sessions.public(SessionStore(repo).create("admin", sessions._binding(KEY), data, sessions._now() + sessions.TTL))


def test_inspect_narrows_to_a_subset_of_features_and_rejects_anything_else(repo):
    view = listed(repo, ["inventory", "identity"], [{"target": {"tenant": TENANT}, "purposes": ["identity", "inventory"]},
        {"target": {"tenant": TENANT, "subscription": SUBSCRIPTION}, "purposes": ["inventory"]}])
    shared, inventory_only = (r["id"] for r in view["roots"])
    for plans in ({}, {"inventory": {}, "identity": {}, "vault": {}}, {"billing": {}}, {"exposure": {}}, ["inventory"]):
        with pytest.raises(service.OnboardingError, match="PURPOSES_INVALID"):
            sessions.inspect(repo, view["id"], body(view, target_ids=[shared], plans=plans), "admin")
    # A target that served only the held feature cannot stay selected.
    with pytest.raises(service.OnboardingError, match="ONBOARDING_TARGETS_INVALID"):
        sessions.inspect(repo, view["id"], body(view, target_ids=[shared, inventory_only], plans={"identity": {}}), "admin")
    assert SessionStore(repo).get(view["id"])["data"]["purposes"] == ["inventory", "identity"]
    narrowed = sessions.inspect(repo, view["id"], body(view, target_ids=[shared], plans={"identity": {}}), "admin")
    assert narrowed["state"] == "WORKING" and set(narrowed["plans"]) == {"identity"}
    assert narrowed["purposes"] == ["identity"] and narrowed["held_purposes"] == ["inventory"]
    assert narrowed["roots"] == [{**view["roots"][0], "purposes": ["identity"]}]
    saved = SessionStore(repo).get(view["id"])["data"]
    assert (saved["purposes"], saved["held_purposes"]) == (["identity"], ["inventory"])
    events = [e for e in repo.list_events() if e.event_type == "ONBOARDING_PURPOSES_NARROWED"]
    assert [(e.target_id, e.note) for e in events] == [(uuid.UUID(view["id"]), "held:inventory")]
    # The held feature needs a new discovery; discovery clears what was held.
    row = SessionStore(repo).save(SessionStore(repo).get(view["id"]), {**saved, "state": "CHECKED"})
    with pytest.raises(service.OnboardingError, match="PURPOSES_INVALID"):
        sessions.inspect(repo, view["id"], body(sessions.public(row), target_ids=[shared], plans={"inventory": {}}), "admin")


def test_an_editing_session_cannot_hold_a_feature_it_already_runs(repo):
    view = listed(repo, ["inventory", "identity"], [{"target": {"tenant": TENANT}, "purposes": ["identity", "inventory"]}],
                  editing=str(uuid.uuid4()), previous_plans={"inventory": {}})
    target = [view["roots"][0]["id"]]
    with pytest.raises(service.OnboardingError, match="TARGET_EDIT_KEEP_FEATURES"):
        sessions.inspect(repo, view["id"], body(view, target_ids=target, plans={"identity": {}}), "admin")
    assert sessions.inspect(repo, view["id"], body(view, target_ids=target, plans={"inventory": {}}), "admin")["held_purposes"] == ["identity"]


def test_a_scan_location_added_to_an_account_leaves_its_running_features_where_they_were(repo):
    from cremore.onboarding import targets

    other = "33333333-3333-4333-8333-333333333333"
    view = listed(repo, ["exposure", "inventory"], [{"target": {"tenant": TENANT, "subscription": s}} for s in (SUBSCRIPTION, other)],
                  editing=str(uuid.uuid4()), previous_plans={"inventory": {}})
    a, b = (r["id"] for r in view["roots"])
    store = SessionStore(repo)
    view = sessions.public(store.save(store.get(view["id"]), {**store.get(view["id"])["data"], "previous_target_ids": [a]}))
    plans = {"exposure": {}, "inventory": {}}
    # The root the inventory already reads keeps it; a scope is a subset of the root's features; every feature keeps a root.
    for ids, scoped in (([a, b], {a: ["exposure"]}), ([a, b], {b: []}), ([a, b], {b: ["vault"]}), ([a, b], {b: ["exposure"] * 2}),
                        ([a, b], {"elsewhere": ["exposure"]}), ([a, b], {b: "exposure"}), ([a, b], [b]), ([a, b], {b: [1]}),
                        ([b], {b: ["exposure"]})):
        with pytest.raises(service.OnboardingError, match="ONBOARDING_TARGETS_INVALID"):
            sessions.inspect(repo, view["id"], body(view, target_ids=ids, plans=plans, target_purposes=scoped), "admin")
    # Without a scope a plain root serves every feature, as an account card's edit does.
    unscoped = sessions._candidate({**store.get(view["id"])["data"], "selected_targets": [a, b]})
    assert [r["target_id"] for r in targets.records_of(unscoped, "inventory")] == [a, b]
    view = sessions.inspect(repo, view["id"], body(view, target_ids=[a, b], plans=plans, target_purposes={b: ["exposure"]}), "admin")
    assert [r.get("purposes") for r in view["roots"]] == [None, ["exposure"]]
    # Completion replaces the targets with this candidate and reconciles each feature's records over records_of.
    candidate = sessions._candidate(store.get(view["id"])["data"])
    assert [r["target_id"] for r in targets.records_of(candidate, "inventory")] == [a]
    assert [r["target_id"] for r in targets.records_of(candidate, "exposure")] == [a, b]


def test_a_scan_only_target_stays_scan_only_when_the_integration_is_edited_again(repo):
    from cremore.onboarding import targets

    other = "33333333-3333-4333-8333-333333333333"
    plain = sessions._roots({"provider": "azure", "edition": "cloud", "purposes": ["exposure", "inventory"]},
                            [{"target": {"tenant": TENANT, "subscription": s}} for s in (SUBSCRIPTION, other)])
    record = {"purposes": ["exposure", "inventory"], "target": {"tenant": TENANT, "version": 2, "roots": [
        {"id": plain[0]["id"], "target": plain[0]["target"]},
        {"id": plain[1]["id"], "target": plain[1]["target"], "purposes": ["exposure"]}]}}
    running = {"exposure": {}, "inventory": {}}
    # What an edit keeps: only the target held to some of the running features.
    scopes = sessions._previous_scopes(record, running)
    assert scopes == [{"target": plain[1]["target"], "purposes": ["exposure"]}]
    # The provider lists both plain again: the scan location stays the scan's, a feature not running yet reaches it,
    # and a target left with nothing it may serve is not offered.
    data = {"purposes": ["exposure", "inventory", "vault"], "previous_plans": running, "previous_scopes": scopes}
    assert [r.get("purposes") for r in sessions._rescoped(data, plain)] == [None, ["exposure", "vault"]]
    only_inventory = {**data, "previous_scopes": [{**scopes[0], "purposes": ["inventory"]}]}
    assert [r["id"] for r in sessions._rescoped(only_inventory, [{**plain[1], "purposes": ["exposure"]}])] == []
    # The next draft keeps the inventory on A, and the scan location can stay scan-only.
    a, b = (r["id"] for r in plain)
    view = listed(repo, ["exposure", "inventory"], [{"target": r["target"]} for r in plain],
                  editing=str(uuid.uuid4()), previous_plans=running, previous_scopes=scopes)
    store = SessionStore(repo)
    saved = store.get(view["id"])["data"]
    view = sessions.public(store.save(store.get(view["id"]), {**saved, "roots": sessions._rescoped(saved, saved["roots"]),
                                                              "previous_target_ids": [a, b]}))
    view = sessions.inspect(repo, view["id"], body(view, target_ids=[a, b], plans=running, target_purposes={b: ["exposure"]}), "admin")
    candidate = sessions._candidate(store.get(view["id"])["data"])
    assert [r["target_id"] for r in targets.records_of(candidate, "inventory")] == [a]


def test_an_edit_whose_listing_lacks_a_running_target_cannot_replace_it_away(repo):
    from cremore.onboarding import targets

    other = "33333333-3333-4333-8333-333333333333"
    both = sessions._roots({"provider": "azure", "edition": "cloud", "purposes": ["exposure", "inventory"]},
                           [{"target": {"tenant": TENANT, "subscription": s}} for s in (SUBSCRIPTION, other)])
    a, c = (r["id"] for r in both)
    running = {"inventory": {}}
    # The inventory runs on A and C; this listing (a first page, a suspended installation) shows A only.
    view = listed(repo, ["exposure", "inventory"], [{"target": both[0]["target"]}], editing=str(uuid.uuid4()),
                  previous_plans=running, previous_targets=[r["target"] for r in both], previous_target_ids=[a])
    plans = {"exposure": {}, "inventory": {}}
    assert view["previous_unlisted"] == 1
    with pytest.raises(service.OnboardingError, match="ONBOARDING_EXISTING_TARGET_NOT_LISTED"):
        sessions.inspect(repo, view["id"], body(view, target_ids=[a], plans=plans), "admin")
    assert SessionStore(repo).get(view["id"])["data"]["state"] == "LISTED"
    # Once the next page lists C, both stay the inventory's.
    store = SessionStore(repo)
    saved = store.get(view["id"])["data"]
    view = sessions.public(store.save(store.get(view["id"]), {**saved, "roots": both, "previous_target_ids": [a, c]}))
    assert view["previous_unlisted"] == 0
    sessions.inspect(repo, view["id"], body(view, target_ids=[a, c], plans=plans), "admin")
    candidate = sessions._candidate(store.get(view["id"])["data"])
    assert [r["target_id"] for r in targets.records_of(candidate, "inventory")] == [a, c]


def azure_checked(repo, monkeypatch, denied):
    """A Microsoft draft whose inventory, Key Vault and people features were checked; ``denied`` lack access."""
    from cremore_azure_provider import onboarding

    from cremore.onboarding import catalog

    monkeypatch.setattr(onboarding, "_ambient", lambda *_: "synthetic-azure-token")
    monkeypatch.setattr(onboarding, "check", lambda record, purpose, _secrets, _context: [
        {"permission": p["id"], "status": "MISSING" if purpose in denied else "GRANTED"}
        for p in catalog.permissions_for("azure", purpose, record["auth_method"], record["target"])])
    monkeypatch.setattr(check, "credential_marks", lambda *_: [])

    def handler(request):
        if request.url.path == "/subscriptions":
            return httpx.Response(200, json={"value": [{"subscriptionId": SUBSCRIPTION, "tenantId": TENANT, "state": "Enabled"}]})
        if request.url.path.endswith("storageAccounts"):
            return httpx.Response(200, json={"value": []})
        assert request.url.path.endswith("Microsoft.KeyVault/vaults"), request.url.path
        return httpx.Response(200, json={"value": [{"id": f"/subscriptions/{SUBSCRIPTION}/resourceGroups/test/providers/"
                                                          "Microsoft.KeyVault/vaults/synthetic-vault"}]})

    def run(view):
        worker = SimpleNamespace(repo=repo, settings=SETTINGS,
            metadata_secret_resolver=SecretResolver(sealing_key=SETTINGS.sealing_keys),
            http_client_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
        check.run(worker, repo.get_job(uuid.UUID(view["job_id"])))
        return sessions.read(repo, view["id"], body(view), "admin")

    view = run(sessions.create(repo, SETTINGS, {"provider": "azure", "auth_method": "workload_identity",
        "browser_key": KEY, "context": {"tenant": TENANT}}, "admin"))
    view = run(sessions.discover(repo, view["id"], body(view, purposes=["inventory", "vault", "identity"]), "admin"))
    roots = {r["purposes"][0]: r["id"] for r in view["roots"]}
    view = run(sessions.inspect(repo, view["id"], body(view, target_ids=list(roots.values()), plans={p: {} for p in roots}), "admin"))
    assert view["state"] == "CHECKED", view
    return view, roots, run


def test_continuing_with_the_ready_features_creates_only_those_and_each_is_checked_again(repo, monkeypatch):
    view, roots, run = azure_checked(repo, monkeypatch, denied={"vault"})
    assert {b["purpose"] for b in view["blockers"]} == {"vault"}
    # Without a narrowing inspect the held feature still blocks the whole draft, exactly as before.
    with pytest.raises(service.OnboardingError, match="REQUIRED_PERMISSIONS_NOT_GRANTED"):
        sessions.select(repo, view["id"], body(view, snapshot_id=view["snapshot_id"], resource_ids=[]), "admin")
    with pytest.raises(service.OnboardingError, match="ONBOARDING_REVIEW_REQUIRED"):
        sessions.complete(repo, SETTINGS, view["id"], body(view, name="Synthetic"), "admin")
    view = sessions.inspect(repo, view["id"], body(view, target_ids=[roots["inventory"], roots["identity"]],
                                                   plans={"inventory": {}, "identity": {}}), "admin")
    # The narrowed draft has no evidence until the worker checks every remaining feature again.
    with pytest.raises(service.OnboardingError, match="PERMISSION_CHECK_REQUIRED"):
        sessions.select(repo, view["id"], body(view, snapshot_id=view["snapshot_id"], resource_ids=[]), "admin")
    view = run(view)
    assert view["state"] == "CHECKED" and view["blockers"] == [] and set(view["checks"]["results"]) == {"inventory", "identity"}
    view = sessions.select(repo, view["id"], body(view, snapshot_id=view["snapshot_id"], resource_ids=[]), "admin")
    with pytest.raises(service.OnboardingError, match="ONBOARDING_SCHEDULE_INVALID"):
        sessions.complete(repo, SETTINGS, view["id"], body(view, name="Synthetic", schedules={"vault": 60}), "admin")
    result = sessions.complete(repo, SETTINGS, view["id"], body(view, name="Synthetic"), "admin")
    assert sorted(result["purposes"]) == ["identity", "inventory"] and set(result["plans"]) == {"identity", "inventory"}
    assert {child["purpose"] for child in result["children"]} == {"identity", "inventory"}


def test_a_narrowed_draft_whose_remaining_feature_is_refused_still_cannot_complete(repo, monkeypatch):
    view, roots, run = azure_checked(repo, monkeypatch, denied={"vault", "identity"})
    view = run(sessions.inspect(repo, view["id"], body(view, target_ids=[roots["identity"]], plans={"identity": {}}), "admin"))
    assert view["purposes"] == ["identity"] and view["blockers"]
    with pytest.raises(service.OnboardingError, match="REQUIRED_PERMISSIONS_NOT_GRANTED"):
        sessions.select(repo, view["id"], body(view, snapshot_id=view["snapshot_id"], resource_ids=[]), "admin")
    assert not ProviderConnectionStore(repo).list()


def test_postgres_partial_activation(pg, monkeypatch):
    test_continuing_with_the_ready_features_creates_only_those_and_each_is_checked_again(pg[1], monkeypatch)


@pytest.mark.parametrize("previous", [False, True])
def test_mixed_vault_versions_apply_options_only_where_supported(previous):
    from cremore.onboarding import catalog, targets

    record = {"provider": "vault", "edition": "community", "auth_method": "token", "secret_refs": {},
              "purposes": ["vault"], "plans": {}}
    roots = [{"address": "https://vault.example.test", "namespace": "", "mounts": [f"kv{version}"], "kv_version": str(version)}
             for version in (1, 2)]
    record["target"] = {"version": 2, "roots": [{"id": targets.target_id(root), "target": root} for root in roots]}
    plan = targets.normalize_plan(record, "vault", {"previous_versions": previous})
    children = targets.described(catalog.module("vault"), record, "vault", plan)
    assert [child["spec"]["include_previous_versions"] for child in children] == [False, previous]
    assert len(children) == 2
    with pytest.raises(service.OnboardingError, match="PLAN_FIELD_UNKNOWN"):
        targets.normalize_plan({**record, "target": roots[0]}, "vault", {"previous_versions": True})


@pytest.mark.parametrize("state", ["CHECKED", "SELECTED"])
def test_more_targets_invalidates_the_previous_check_and_selection(repo, state):
    view = selected(repo)
    row = SessionStore(repo).get(view["id"])
    row = SessionStore(repo).save(row, {**row["data"], "state": state, "discovery_cursor": "synthetic-next-page"})
    view = sessions.public(row)
    more = sessions.discover(repo, view["id"], body(view, more=True), "admin")
    assert more["state"] == "WORKING" and more["roots"] == view["roots"]
    assert not more["checks"] and not more["resources"] and not more["selected_resources"] and not more["selected_roots"]
    with pytest.raises(service.OnboardingError, match="PERMISSION_CHECK_REQUIRED"):
        sessions.select(repo, more["id"], body(more, snapshot_id=view["snapshot_id"], resource_ids=view["selected_resources"]), "admin")


def test_expired_draft_can_be_closed_without_blocking_reauthentication(repo):
    view = start(repo)
    row = SessionStore(repo).get(view["id"])
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(sessions, "_now", lambda: row["expires_at"] + dt.timedelta(seconds=1))
        closed = sessions.cancel(repo, view["id"], body(view), "admin")
    assert closed["state"] == "EXPIRED"
    assert SessionStore(repo).get(view["id"])["data"] == {"state": "EXPIRED"}
    replacement = start(repo)
    assert replacement["id"] != view["id"] and replacement["state"] == "WORKING"
