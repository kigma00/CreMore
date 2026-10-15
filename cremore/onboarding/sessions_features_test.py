"""Editing an active feature must never inspect or widen a paused feature."""

import datetime as dt
import uuid
from types import SimpleNamespace

import pytest

from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414 -- isolated PostgreSQL fixture
from cremore.domain.models import ScopeProfile
from cremore.onboarding import catalog, check, permissions, service, sessions, targets
from cremore.onboarding.features_test import connect, switch
from cremore.onboarding.onboarding_test import SETTINGS, github_app
from cremore.onboarding.sessions_test import KEY, body
from cremore.onboarding.sessions_test import repo as repo  # noqa: PLC0414 -- memory/SQLite fixture
from cremore.secretstore.resolver import SecretResolver


def test_active_editor_never_checks_paused_permissions_or_rewrites_its_scope(repo, monkeypatch):
    made = connect(repo, github_app(), {"exposure": {}, "inventory": {}})
    source = repo.list_connections()[0]
    scope = repo.create_scope_profile(ScopeProfile(kind="github", connection_id=source.id,
        name="Approved unchanged scope", state="READY", approved_by="admin", approved_at=dt.datetime.now(dt.UTC),
        selected_roots=[{"resource_id": "retained-root", "paths": ["approved/"]}], schedule_minutes=60))
    original_scope = scope.model_dump()
    old = service.get(repo, made["id"])
    original_exposure_target = targets.records_of(old, "exposure")[0]["target"]
    switch(repo, made["id"], "exposure", False)
    module = catalog.module("github")
    asked = []
    monkeypatch.setattr(module, "authenticate", lambda *_: {"status": "GRANTED", "subject": "synthetic-app"})
    monkeypatch.setattr(check, "credential_marks", lambda *_: [])

    def denied_paused_check(record, purpose, _secrets, _context):
        asked.append(purpose)
        assert purpose == "inventory", "Paused exposure has no permission and must not be checked"
        return [{"permission": p["id"], "status": "GRANTED"} for p in
                catalog.permissions_for("github", purpose, "github_app", record["target"])]

    monkeypatch.setattr(module, "check", denied_paused_check)
    monkeypatch.setattr(sessions, "_resources", lambda *_: pytest.fail("Paused exposure read its resource catalog"))
    worker = SimpleNamespace(repo=repo, settings=SETTINGS,
        metadata_secret_resolver=SecretResolver(sealing_key=SETTINGS.sealing_keys),
        http_client_factory=lambda: pytest.fail("Unexpected network access"))

    def finish(view):
        check.run(worker, repo.get_job(uuid.UUID(view["job_id"])))
        result = sessions.read(repo, view["id"], body(view), "admin")
        assert result["state"] != "FAILED", result
        return result

    # The first change splits a shared v1 target; the second edits the resulting v2 owner. The listing shows the
    # organization the inventory reads now as well; leaving it out of the selection is what removes it.
    for previous, organization in (("acme", "inventory-new"), ("inventory-new", "inventory-next")):
        current = service.get(repo, made["id"])
        monkeypatch.setattr(module, "discover", lambda *_args, org=organization, old=previous:
            ([{"label": name, "target": {"organization": name}} for name in (old, org)], "COMPLETE"))
        view = sessions.edit(repo, SETTINGS, made["id"],
                             {"browser_key": KEY, "expected_revision": current["revision"]}, "admin")
        assert view["purposes"] == ["inventory"] and set(view["previous_plans"]) == {"inventory"}
        assert view["feature_enabled"] == {"inventory": True, "exposure": False}
        view = finish(view)
        with pytest.raises(service.OnboardingError, match="TARGET_EDIT_PAUSED_FEATURE"):
            sessions.discover(repo, view["id"], body(view, purposes=["inventory", "exposure"]), "admin")
        view = finish(sessions.discover(repo, view["id"], body(view, purposes=["inventory"]), "admin"))
        assert len(view["previous_target_ids"]) == 1
        view = finish(sessions.inspect(repo, view["id"], body(view,
            target_ids=[r["id"] for r in view["roots"] if r["label"] == organization],
            plans={"inventory": current["plans"]["inventory"]}), "admin"))
        assert view["state"] == "CHECKED" and view["resources"] == [] and view["blockers"] == []
        view = sessions.select(repo, view["id"], body(view, snapshot_id=view["snapshot_id"], resource_ids=[]), "admin")
        sessions.complete(repo, SETTINGS, view["id"], body(view, name="Edited inventory"), "admin")
        saved = service.get(repo, made["id"])
        assert targets.records_of(saved, "exposure")[0]["target"] == original_exposure_target
        assert targets.records_of(saved, "inventory")[0]["target"]["organization"] == organization
        assert saved["disabled_purposes"] == ["exposure"] and saved["plans"]["exposure"] == old["plans"]["exposure"]
        assert repo.get_connection(source.id).status == "DISABLED"
        assert repo.get_scope_profile(scope.id).model_dump() == original_scope
        assert len(repo.list_connections()) == 1
        permissions.require(saved, {"inventory": saved["plans"]["inventory"]})
        with pytest.raises(service.OnboardingError, match="PERMISSION_CHECK_REQUIRED"):
            switch(repo, made["id"], "exposure", True)
    assert asked == ["inventory", "inventory"]


def test_an_owner_with_all_features_paused_requires_explicit_resume_before_target_edit(repo):
    made = connect(repo, github_app(), {"inventory": {}})
    paused = switch(repo, made["id"], "inventory", False)
    before = [job.id for job in repo.list_jobs()]
    with pytest.raises(service.OnboardingError, match="TARGET_EDIT_NO_ACTIVE_FEATURES"):
        sessions.edit(repo, SETTINGS, made["id"],
                      {"browser_key": KEY, "expected_revision": paused["revision"]}, "admin")
    assert [job.id for job in repo.list_jobs()] == before


def test_postgres_active_editor_preserves_paused_scope(pg, monkeypatch):
    test_active_editor_never_checks_paused_permissions_or_rewrites_its_scope(pg[1], monkeypatch)
