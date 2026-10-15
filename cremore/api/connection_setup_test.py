"""The connection setup API's contract: evidence only, and never a claim it cannot make.

Tests create only the records each scenario needs and assert the API's evidence
and shape directly, without a saved response dataset.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from cremore.api import connection_setup, create_app
from cremore.config import Settings
from cremore.db.repository import InMemoryRepository
from cremore.domain.models import Connection, ScanJob, ScopeCatalog, ScopeProfile

TOKEN = "connection-setup-token-" + "0" * 20
AUTH = {"Authorization": "Bearer " + TOKEN}


@pytest.fixture
def repo():
    return InMemoryRepository()


@pytest.fixture
def client(repo):
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN,
                                                  FINGERPRINT_KEY="ab" * 32))
    with TestClient(app) as value:
        yield value


def connection(repo, **changes):
    fields = {"provider": "github", "name": "app", "status": "ACTIVE",
              "config": {"owner": "acme", "repo": "app"}, **changes}
    return repo.create_connection(Connection(**fields))


def setup(client, conn):
    response = client.get(f"/api/v1/connections/source/{conn.id}/capabilities", headers=AUTH)
    assert response.status_code == 200, response.text
    return response.json()["onboarding"]


def declare(client, conn, **changes):
    body = {"product_type": "GITHUB_CLOUD", "auth_type": "TOKEN", "base_url": "https://github.com",
            "environment": {"deployment_type": "CLOUD"}, "purposes": ["DISCOVERY"], **changes}
    response = client.post(f"/api/v1/connections/source/{conn.id}/profile", headers=AUTH, json=body)
    assert response.status_code == 200, response.text
    return response.json()["onboarding"]


def with_catalog(repo, conn, *, snapshot="snap-1", completeness="PARTIAL"):
    return repo.save_catalog(ScopeCatalog(
        kind="source", connection_id=conn.id, snapshot_id=snapshot, completeness=completeness,
        items=[{"id": "r1", "display_name": "billing", "resource_type": "GITHUB_REPOSITORY"}]))


def with_profile(repo, conn, **changes):
    fields = {"selected_roots": [{"resource_id": "r1", "all_current_objects": True,
                                  "excluded_paths": ["vendor/"], "prefixes": [], "excluded_prefixes": [],
                                  "paths": [], "descendant_ids": [], "include_future_descendants": False}],
              "excluded_ids": ["r2"], "approved_by": "admin", **changes}
    return repo.create_scope_profile(ScopeProfile(kind="source", connection_id=conn.id,
                                                  name="Approved", **fields))


# -- the shape both sides agree on --------------------------------------------


def test_the_payload_reports_scope_counts_and_the_evidence_that_completed_each_step(client, repo):
    conn = connection(repo)
    catalog = with_catalog(repo, conn)
    profile = with_profile(repo, conn)
    declare(client, conn)
    body = setup(client, conn)
    assert set(body) == {"investigation", "probe", "stage", "status", "management_only", "steps", "catalog", "profiles",
                         "profile_count", "selected_roots", "excluded_resources", "excluded_paths", "evidence_digest",
                         "version", "choice", "checkpoint_current"}
    assert (body["investigation"], body["probe"], body["stage"], body["status"], body["management_only"]) == (
        "NOT_AVAILABLE", "AVAILABLE", "AUTHENTICATION", "IN_PROGRESS", False)
    assert (body["version"], body["choice"], body["checkpoint_current"]) == (0, "DRAFT", False)
    assert re.fullmatch(r"[a-f0-9]{64}", body["evidence_digest"])
    assert all(body[field] == 1 for field in ("profile_count", "selected_roots", "excluded_resources", "excluded_paths"))
    assert body["profiles"] == [{"id": str(profile.id), "version": 1, "state": "NEEDS_SCOPE_REVIEW",
                                 "selected_roots": 1, "excluded_resources": 1, "excluded_paths": 1,
                                 "schedule_minutes": 0, "full_scan_minutes": None, "event_mode": "DISABLED", "authorization_current": False}]
    assert datetime.fromisoformat(body["catalog"].pop("updated_at")) == catalog.updated_at
    assert body["catalog"] == {"snapshot_id": "snap-1", "status": "PARTIAL", "known_count": 1,
                               "authorization_current": False, "job_status": "NOT_REQUESTED"}
    assert [(row["code"], row["status"]) for row in body["steps"]] == [
        ("PURPOSE", "COMPLETE"), ("ENVIRONMENT", "COMPLETE"), ("AUTHENTICATION", "PENDING"),
        ("CATALOG", "COMPLETE"), ("SELECTION", "COMPLETE"), ("SCOPE_SAVED", "PENDING"), ("EXECUTION_CHOICE", "PENDING")]
    for row in body["steps"]:
        expected_keys = {"code", "status"}
        if row["status"] == "COMPLETE":
            expected_keys.add("observed_at")
            assert datetime.fromisoformat(row["observed_at"]).tzinfo
        if row["code"] in ("CATALOG", "SELECTION"):
            expected_keys.add("evidence_id")
            assert row["evidence_id"] == (catalog.snapshot_id if row["code"] == "CATALOG" else str(profile.id))
        assert set(row) == expected_keys


def test_an_absent_time_is_absent_rather_than_a_recorded_null(client, repo):
    conn = connection(repo)
    with_profile(repo, conn)
    body = setup(client, conn)
    # A null would read as "recorded: nothing", and the dashboard refuses the
    # whole page rather than render it.
    assert "approved_at" not in body["profiles"][0]
    assert all("observed_at" not in step for step in body["steps"] if step["status"] == "PENDING")
    assert "updated_at" not in body["catalog"]
    assert "saved_at" not in body and "recent_run" not in body


# -- a step is evidence, not a click ------------------------------------------


def test_opening_the_screen_records_nothing(client, repo):
    conn = connection(repo)
    first = setup(client, conn)
    assert first["version"] == 0 and first["checkpoint_current"] is False
    assert [step["status"] for step in setup(client, conn)["steps"]] == [
        step["status"] for step in first["steps"]]
    assert repo.get_setting(connection_setup.checkpoint_key("source", conn.id)) is None


def test_purpose_and_environment_come_from_the_declaration(client, repo):
    conn = connection(repo)
    assert [step["status"] for step in setup(client, conn)["steps"][:2]] == ["PENDING", "PENDING"]
    body = declare(client, conn)
    assert [step["status"] for step in body["steps"][:2]] == ["COMPLETE", "COMPLETE"]
    assert body["steps"][0]["observed_at"]


def test_a_declaration_that_names_no_product_is_not_a_purpose(client, repo):
    conn = connection(repo)
    body = declare(client, conn, product_type="UNKNOWN", environment={})
    assert [step["status"] for step in body["steps"][:2]] == ["PENDING", "PENDING"]


def test_holding_a_secret_is_not_authentication(client, repo):
    conn = connection(repo, secret_ref="vault://github/token")
    body = setup(client, conn)
    step = next(row for row in body["steps"] if row["code"] == "AUTHENTICATION")
    # A stored credential says nothing about whether the provider accepts it.
    assert step["status"] == "PENDING"


@pytest.mark.parametrize("status,expected", [
    ("ACTIVE", "COMPLETE"), ("REJECTED", "PENDING"), ("INDETERMINATE", "PENDING")])
def test_only_a_check_the_provider_accepted_completes_authentication(client, repo, status, expected):
    conn = connection(repo)
    repo.update_connection(conn.id, credential_evidence={
        "status": status, "checked_at": "2026-09-20T00:00:00+00:00", "owner": "", "workspace": "",
        "scopes": [], "error": ""})
    step = next(row for row in setup(client, conn)["steps"] if row["code"] == "AUTHENTICATION")
    assert step["status"] == expected


def test_a_catalog_that_was_never_collected_is_not_an_empty_catalog(client, repo):
    conn = connection(repo)
    assert setup(client, conn)["catalog"] == {
        "snapshot_id": "", "status": "NOT_COLLECTED", "known_count": 0,
        "authorization_current": False, "job_status": "NOT_REQUESTED"}
    with_catalog(repo, conn, completeness="COMPLETE")
    catalog = setup(client, conn)["catalog"]
    assert catalog["status"] == "COMPLETE" and catalog["known_count"] == 1


def test_a_queued_catalog_refresh_is_reported_as_queued(client, repo):
    conn = connection(repo)
    job = repo.enqueue_job(ScanJob(kind="catalog-refresh", payload={}, connection_id=conn.id))
    catalog = with_catalog(repo, conn)
    repo.save_catalog(catalog.model_copy(update={"refresh_job_id": job.id}))
    assert setup(client, conn)["catalog"]["job_status"] == "QUEUED"


def test_a_saved_scope_completes_selection_before_approval_completes_the_scope(client, repo):
    conn = connection(repo)
    with_catalog(repo, conn)
    with_profile(repo, conn)
    steps = {row["code"]: row["status"] for row in setup(client, conn)["steps"]}
    # Targets were chosen; the approval that makes them runnable did not follow.
    assert steps["SELECTION"] == "COMPLETE" and steps["SCOPE_SAVED"] == "PENDING"


def test_a_disabled_connection_is_disconnected_rather_than_in_progress(client, repo):
    conn = connection(repo, status="DISABLED")
    assert setup(client, conn)["status"] == "DISCONNECTED"


# -- the checkpoint is bound to the evidence it describes ----------------------


def save(client, conn, body):
    return client.post(f"/api/v1/connections/source/{conn.id}/onboarding", headers=AUTH, json=body)


def test_a_checkpoint_records_the_choice_and_nothing_else(client, repo):
    conn = connection(repo)
    current = setup(client, conn)
    response = save(client, conn, {"expected_version": 0, "evidence_digest": current["evidence_digest"],
                                   "choice": "DRAFT"})
    assert response.status_code == 200, response.text
    body = response.json()["onboarding"]
    # Recorded against the evidence that was on screen, so it is current now.
    assert body["version"] == 1 and body["choice"] == "DRAFT" and body["checkpoint_current"] is True
    assert body["saved_by"] and body["saved_at"] and body["saved_stage"]
    # Saving a note must not queue anything.
    assert repo.list_jobs(10) == []


def test_a_checkpoint_goes_stale_when_the_evidence_moves(client, repo):
    conn = connection(repo)
    current = setup(client, conn)
    save(client, conn, {"expected_version": 0, "evidence_digest": current["evidence_digest"],
                        "choice": "DRAFT"})
    assert setup(client, conn)["checkpoint_current"] is True
    declare(client, conn)
    # The administrator recorded what they saw. They did not see this.
    assert setup(client, conn)["checkpoint_current"] is False


def test_a_stale_version_or_digest_is_a_conflict_not_an_overwrite(client, repo):
    conn = connection(repo)
    current = setup(client, conn)
    assert save(client, conn, {"expected_version": 0, "evidence_digest": current["evidence_digest"],
                               "choice": "DRAFT"}).status_code == 200
    assert save(client, conn, {"expected_version": 0, "evidence_digest": current["evidence_digest"],
                               "choice": "DRAFT"}).status_code == 409
    fresh = setup(client, conn)
    assert save(client, conn, {"expected_version": fresh["version"], "evidence_digest": "b" * 64,
                               "choice": "DRAFT"}).status_code == 409


def test_a_choice_that_names_a_scope_must_name_one_this_connection_saved(client, repo):
    conn = connection(repo)
    with_catalog(repo, conn)
    profile = with_profile(repo, conn)
    current = setup(client, conn)
    assert save(client, conn, {"expected_version": 0, "evidence_digest": current["evidence_digest"],
                               "choice": "RUN_NOW", "profile_id": str(uuid.uuid4())}).status_code == 409
    accepted = save(client, conn, {"expected_version": 0, "evidence_digest": current["evidence_digest"],
                                   "choice": "RUN_NOW", "profile_id": str(profile.id)})
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["onboarding"]["profile_id"] == str(profile.id)


def test_an_unknown_choice_is_refused(client, repo):
    conn = connection(repo)
    current = setup(client, conn)
    assert save(client, conn, {"expected_version": 0, "evidence_digest": current["evidence_digest"],
                               "choice": "ALL_SCANNED"}).status_code == 422


def test_saving_a_checkpoint_is_an_administrator_action(client, repo):
    from cremore.api.auth import LOCAL_ACTOR

    assert LOCAL_ACTOR
    conn = connection(repo)
    current = setup(client, conn)
    anonymous = client.post(f"/api/v1/connections/source/{conn.id}/onboarding",
                            json={"expected_version": 0, "evidence_digest": current["evidence_digest"],
                                  "choice": "DRAFT"})
    assert anonymous.status_code in (401, 403)


# -- a management-only connection is not a half-finished content connection ----


def test_content_steps_are_not_applicable_where_there_is_no_content(repo):
    rows = connection_setup.steps(
        declaration={"product_type": "AZURE_KEY_VAULT", "environment": {"deployment_type": "CLOUD"},
                     "declared_at": "2026-09-20T00:00:00+00:00"},
        authenticated_at="2026-09-20T00:00:00+00:00", management_only=True, catalog=None,
        profiles=[], checkpoint=None, iso=lambda value: value)
    statuses = {row["code"]: row["status"] for row in rows}
    assert [statuses[code] for code in connection_setup.CONTENT_STEPS] == ["NOT_APPLICABLE"] * 3
    # Nothing is pending, so the connection reads as reviewed once a choice is
    # recorded -- not as a content connection that stopped halfway.
    assert statuses["EXECUTION_CHOICE"] == "PENDING"


def test_a_management_only_connection_cannot_choose_a_content_execution():
    current = {"management_only": True, "version": 0, "evidence_digest": "a" * 64, "stage": "PURPOSE"}
    for choice in ("RUN_NOW", "SCHEDULED", "EVENTS", "SAVE_ONLY"):
        with pytest.raises(ValueError, match="SETUP_CHOICE_NOT_SUPPORTED"):
            connection_setup.validate_checkpoint(
                {"expected_version": 0, "evidence_digest": "a" * 64, "choice": choice}, current, set())
    saved = connection_setup.validate_checkpoint(
        {"expected_version": 0, "evidence_digest": "a" * 64, "choice": "MANAGEMENT_ONLY",
         "profile_id": "ignored"}, current, set())
    assert saved["choice"] == "MANAGEMENT_ONLY" and saved["profile_id"] == ""


# -- the probe ----------------------------------------------------------------


def test_a_probe_asks_who_the_connection_is_and_records_only_that(client, repo):
    conn = connection(repo, secret_ref="vault://github/token")
    response = client.post(f"/api/v1/connections/source/{conn.id}/probe", headers=AUTH)
    assert response.status_code == 200, response.text
    [job] = repo.list_jobs(10)
    assert job.kind == "credential-check" and job.connection_id == conn.id
    # The check is queued; it has not run, so authentication is still pending.
    step = next(row for row in response.json()["onboarding"]["steps"]
                if row["code"] == "AUTHENTICATION")
    assert step["status"] == "PENDING"


def test_a_probe_of_a_disabled_connection_is_refused(client, repo):
    conn = connection(repo, status="DISABLED")
    assert client.post(f"/api/v1/connections/source/{conn.id}/probe", headers=AUTH).status_code == 409


def test_an_unknown_kind_or_connection_is_not_a_blank_setup(client, repo):
    conn = connection(repo)
    assert client.get(f"/api/v1/connections/other/{conn.id}/capabilities",
                      headers=AUTH).status_code == 422
    assert client.get(f"/api/v1/connections/source/{uuid.uuid4()}/capabilities",
                      headers=AUTH).status_code == 404
