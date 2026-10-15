"""Feature switches retain configuration/evidence and never infer new scope approval."""

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import text

from cremore.coverage.store import CoverageStore
from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414 -- isolated PostgreSQL fixture
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.onboarding import children, service
from cremore.onboarding.fixtures_test import activate_with_access, grant_access
from cremore.onboarding.onboarding_test import SETTINGS, approve_aws, github_app
from cremore.onboarding.store import ProviderConnectionStore, child_feature_enabled


@pytest.fixture(params=["memory", "sqlite"])
def repo(request, tmp_path):
    if request.param == "memory":
        yield InMemoryRepository()
    else:
        engine = make_engine(f"sqlite+pysqlite:///{tmp_path / 'features.sqlite'}")
        create_all(engine)
        yield SqlRepository(engine)
        engine.dispose()


def connect(repo, body, plans):
    made = service.create(repo, SETTINGS, body, "admin")
    return activate_with_access(repo, SETTINGS, made["id"], {"purposes": plans}, "admin")


def switch(repo, cid, purpose, enabled, **extra):
    return service.set_feature(repo, SETTINGS, cid, purpose,
        {"enabled": enabled, "expected_revision": service.get(repo, cid)["revision"], **extra}, "admin")


def test_content_pause_retains_scope_and_resume_requires_current_exact_checks(repo):
    made = connect(repo, github_app(), {"exposure": {}, "inventory": {}})
    source = next(link for link in made["children"] if link["kind"] == "content")
    sid = uuid.UUID(source["id"])
    repo.update_connection(sid, credential_evidence={"owner": "acme"})
    from cremore.scanning.scope import auth_revision

    authorization = auth_revision("source", repo.get_connection(sid))
    before = service.get(repo, made["id"])
    paused = switch(repo, made["id"], "exposure", False)
    assert paused["plans"] == before["plans"] and paused["target"] == before["target"]
    assert paused["feature_enabled"] == {"exposure": False, "inventory": True}
    assert repo.get_connection(sid).status == "DISABLED"
    assert all(row["enabled"] for row in CoverageStore(repo).list_connections())
    with pytest.raises(service.OnboardingError, match="PERMISSION_CHECK_REQUIRED"):
        switch(repo, made["id"], "exposure", True)
    grant_access(repo, made["id"], {"exposure": before["plans"]["exposure"]}, status="MISSING")
    with pytest.raises(service.OnboardingError, match="REQUIRED_PERMISSIONS_NOT_GRANTED"):
        switch(repo, made["id"], "exposure", True)
    grant_access(repo, made["id"], {"exposure": before["plans"]["exposure"]})
    resumed = switch(repo, made["id"], "exposure", True)
    assert resumed["feature_enabled"]["exposure"] and repo.get_connection(sid).status == "PENDING"
    assert auth_revision("source", repo.get_connection(sid)) == authorization
    assert len(repo.list_connections()) == 1
    assert set(resumed["plans"]) == {"exposure", "inventory"}


def test_gcp_shared_collection_preserves_id_and_narrows_capabilities(repo):
    made = connect(repo, {"provider": "gcp", "purposes": ["inventory", "vault"], "auth_method": "adc",
        "target": {"project": "acme-prod"}}, {"inventory": {}, "vault": {}})
    [original] = CoverageStore(repo).list_connections()
    cid = original["id"]
    switch(repo, made["id"], "inventory", False)
    row = CoverageStore(repo).get(cid)
    assert row["enabled"] and "vault_metadata" in row["spec"]["capabilities"]
    assert ProviderConnectionStore(repo).children(made["id"])[0]["purpose"] == "vault"
    assert len(CoverageStore(repo).list_connections()) == 1
    switch(repo, made["id"], "vault", False)
    assert not CoverageStore(repo).get(cid)["enabled"]
    service.set_enabled(repo, made["id"], False, "admin")
    service.set_enabled(repo, made["id"], True, "admin", SETTINGS)
    assert not CoverageStore(repo).get(cid)["enabled"]
    record = service.get(repo, made["id"])
    grant_access(repo, made["id"], {"inventory": record["plans"]["inventory"]})
    switch(repo, made["id"], "inventory", True)
    row = CoverageStore(repo).get(cid)
    assert row["enabled"] and "vault_metadata" not in row["spec"]["capabilities"]
    assert ProviderConnectionStore(repo).children(made["id"])[0]["purpose"] == "inventory"
    assert len(CoverageStore(repo).list_connections()) == 1


def test_pause_survives_credential_refresh_plan_edits_and_whole_resume(repo):
    made = connect(repo, github_app(), {"exposure": {}, "inventory": {}})
    switch(repo, made["id"], "inventory", False)
    record = service.get(repo, made["id"])
    children.repoint(repo, record, "admin")
    service.update_plan(repo, SETTINGS, made["id"], "inventory",
        {"plan": {**record["plans"]["inventory"], "schedule_minutes": 60}}, "admin")
    service.set_enabled(repo, made["id"], False, "admin")
    service.set_enabled(repo, made["id"], True, "admin", SETTINGS)
    assert all(not row["enabled"] for row in CoverageStore(repo).list_connections())
    assert service.view(repo, service.get(repo, made["id"]))["feature_enabled"]["inventory"] is False


def test_pause_is_revision_guarded_idempotent_and_atomic(repo, monkeypatch):
    made = connect(repo, github_app(), {"exposure": {}, "inventory": {}})
    saved = switch(repo, made["id"], "exposure", False)
    assert switch(repo, made["id"], "exposure", False)["revision"] == saved["revision"]
    with pytest.raises(service.OnboardingError, match="PROVIDER_CONNECTION_CHANGED"):
        switch(repo, made["id"], "exposure", False, expected_revision=saved["revision"] - 1)
    def fail(*args):
        raise children.ChildError("SYNTHETIC_FAILURE", 409)
    monkeypatch.setattr(children, "reconcile_features", fail)
    with pytest.raises(service.OnboardingError, match="SYNTHETIC_FAILURE"):
        switch(repo, made["id"], "inventory", False)
    assert service.get(repo, made["id"])["revision"] == saved["revision"]
    assert service.get(repo, made["id"])["disabled_purposes"] == ["exposure"]


def test_aws_exposure_pause_preserves_inventory_access_but_blocks_scans(repo):
    from cremore.collectors.base import CollectorError
    from cremore.domain.models import ScanJob
    from cremore.worker.runtime import ScanRuntime

    approve_aws(repo)
    made = connect(repo, {"provider": "aws", "purposes": ["exposure", "inventory", "vault"], "auth_method": "role",
        "target": {"accounts": ["222222222222"]}},
        {"exposure": {}, "inventory": {}, "vault": {"regions": ["us-east-1"]}})
    [account] = repo.list_aws_accounts()
    switch(repo, made["id"], "exposure", False)
    assert repo.get_aws_account(account.id).enabled
    assert not child_feature_enabled(repo, "aws", account.id, "exposure")
    job = ScanJob(kind="scope", connection_id=account.id, payload={"connection_kind": "aws"})
    with pytest.raises(CollectorError, match="CONNECTION_PAUSED"):
        ScanRuntime(SimpleNamespace(repo=repo)).validate(job)
    with pytest.raises(CollectorError, match="CONNECTION_PAUSED"):
        ScanRuntime(SimpleNamespace(repo=repo)).validate(ScanJob(kind="s3", connection_id=account.id))
    switch(repo, made["id"], "inventory", False)
    rows = CoverageStore(repo).list_connections()
    assert all(row["enabled"] == (row["spec"]["provider"] == "aws_secrets_manager") for row in rows)
    switch(repo, made["id"], "vault", False)
    assert repo.get_aws_account(account.id).enabled  # retained for explicit permission checks
    service.set_enabled(repo, made["id"], False, "admin")
    service.set_enabled(repo, made["id"], True, "admin", SETTINGS)
    assert repo.get_aws_account(account.id).enabled
    assert all(not row["enabled"] for row in CoverageStore(repo).list_connections())


def test_legacy_database_adds_pause_column_without_altering_configuration(tmp_path):
    engine = make_engine(f"sqlite+pysqlite:///{tmp_path / 'legacy.sqlite'}")
    create_all(engine)
    repo = SqlRepository(engine)
    made = connect(repo, github_app(), {"exposure": {}})
    original = service.get(repo, made["id"])
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE provider_connections DROP COLUMN disabled_purposes"))
    create_all(engine)
    create_all(engine)
    restored = service.get(repo, made["id"])
    assert restored["disabled_purposes"] == []
    for key in ("plans", "target", "secret_refs", "purposes", "revision"):
        assert restored[key] == original[key]
    assert switch(repo, made["id"], "exposure", False)["feature_enabled"] == {"exposure": False}
    engine.dispose()


def test_late_check_cannot_restore_evidence_after_a_feature_is_paused(repo):
    from cremore.onboarding.check import _store_results

    made = connect(repo, github_app(), {"inventory": {}})
    old = service.get(repo, made["id"])
    digest = service.check_digest(old)
    switch(repo, made["id"], "inventory", False)
    _store_results(repo, old, digest, old["checks"]["results"], None)
    saved = service.get(repo, made["id"])
    assert saved["checks"]["stale"] and service.check_digest(saved) != digest
    assert saved["disabled_purposes"] == ["inventory"]


def test_paused_remediation_is_ineligible_even_after_a_fresh_check(repo):
    from cremore.onboarding.remediation_purpose_test import gitlab
    from cremore.remediation.provider_actions import _serves

    made = connect(repo, gitlab(), {"remediation": {}})
    switch(repo, made["id"], "remediation", False)
    record = grant_access(repo, made["id"], {"remediation": {}})
    # The scope match would succeed; pausing the no-child feature independently blocks it.
    module = SimpleNamespace(covers=lambda *_: True)
    assert not _serves(module, record, {"provider": "gitlab", "reference": {}})
    switch(repo, made["id"], "remediation", True)
    assert _serves(module, service.get(repo, made["id"]), {"provider": "gitlab", "reference": {}})


def test_target_reconciliation_retains_individual_pauses(repo):
    made = connect(repo, github_app(), {"exposure": {}, "inventory": {}})
    switch(repo, made["id"], "exposure", False)
    record = service.get(repo, made["id"])
    service.replace_targets(repo, SETTINGS, record, {**record, "name": "Retained scope"}, record["plans"], "admin", reduction=True)
    assert all(source.status == "DISABLED" for source in repo.list_connections())
    assert service.get(repo, made["id"])["disabled_purposes"] == ["exposure"]


def test_v2_targets_keep_paused_purposes_while_describing_only_active_capabilities(repo):
    from cremore.onboarding import targets

    made = connect(repo, {"provider": "gcp", "purposes": ["inventory", "vault"], "auth_method": "adc",
        "target": {"project": "acme-prod"}}, {"inventory": {}, "vault": {}})
    stored = service.get(repo, made["id"])
    root = {"project": "acme-prod", "scope": "project"}
    ProviderConnectionStore(repo).update(made["id"], stored["revision"], "fixture",
        target={"version": 2, "roots": [{"id": targets.target_id(root), "target": root,
            "purposes": ["inventory", "vault"]}]})
    switch(repo, made["id"], "inventory", False)
    [row] = CoverageStore(repo).list_connections()
    assert row["enabled"] and "vault_metadata" in row["spec"]["capabilities"]
    assert service.get(repo, made["id"])["target"]["roots"][0]["purposes"] == ["inventory", "vault"]


def test_postgres_pause_race_has_one_winner_and_one_audit(pg):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    repo = pg[1]
    made = connect(repo, github_app(), {"exposure": {}, "inventory": {}})
    revision = service.get(repo, made["id"])["revision"]
    barrier = Barrier(2)
    def pause(purpose):
        barrier.wait(timeout=10)
        try:
            service.set_feature(repo, SETTINGS, made["id"], purpose,
                {"enabled": False, "expected_revision": revision}, "admin")
            return "won"
        except service.OnboardingError as exc:
            return exc.code
    with ThreadPoolExecutor(2) as pool:
        result = list(pool.map(pause, ["exposure", "inventory"]))
    assert sorted(result) == ["PROVIDER_CONNECTION_CHANGED", "won"]
    saved = service.get(repo, made["id"])
    assert saved["revision"] == revision + 1 and len(saved["disabled_purposes"]) == 1
    with pg[0].connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM finding_events WHERE event_type = 'PROVIDER_CONNECTION_FEATURE_DISABLED'")).scalar_one() == 1


def test_postgres_legacy_pause_column_is_added_idempotently(pg):
    engine, repo = pg
    made = connect(repo, github_app(), {"exposure": {}})
    original = service.get(repo, made["id"])
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE provider_connections DROP COLUMN disabled_purposes"))
    create_all(engine)
    create_all(engine)
    assert service.get(repo, made["id"]) == original
