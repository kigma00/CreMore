"""Collection history distinguishes content, trigger provenance and safe errors."""

import pytest

from cremore.api.app_test import auth, client
from cremore.api.source_presenters import present_job, present_scan_run
from cremore.domain.models import Connection, ScanJob


@pytest.mark.parametrize("kind", ["catalog-refresh", "aws-role-check", "credential-check", "github-secret-scanning", "metadata-collection"])
def test_metadata_and_authentication_jobs_never_claim_content_was_scanned(kind):
    body = present_job(ScanJob(kind=kind, status="SUCCEEDED"), None)
    assert body["result_status"] is None
    assert "authoritative_listing" not in body and "connection_wide" not in body


@pytest.mark.parametrize("trigger", ["BASELINE", "RESCAN", "SCHEDULE", "EVENT", "POLICY_SWEEP", "RESUME", "INVALID"])
def test_run_history_uses_the_recorded_trigger(trigger):
    body = present_scan_run(ScanJob(kind="scope", payload={"trigger": trigger}))
    expected = "MANUAL" if trigger == "BASELINE" else "UNKNOWN" if trigger == "INVALID" else trigger
    assert body["trigger_type"] == expected


def test_a_finished_metadata_collection_names_the_runs_it_stored():
    rid = "11111111-1111-4111-8111-111111111111"
    body = present_scan_run(ScanJob(kind="provider-metadata-inventory", status="SUCCEEDED",
                                    payload={"coverage_connection_id": "c"}, coverage={"coverage_run_ids": [rid]}))
    assert body["coverage_run_ids"] == [rid] and body["coverage_connection_id"] == "c"
    # A run that stored none, or is no collection, names none.
    assert "coverage_run_ids" not in present_scan_run(ScanJob(kind="provider-metadata-inventory", status="RUNNING"))
    assert "coverage_run_ids" not in present_scan_run(ScanJob(kind="scope", coverage={"objects": 1}))
    # A schema 1 collection records its run as well, but the v2 run routes cannot read it: no ids to follow.
    assert "coverage_run_ids" not in present_scan_run(ScanJob(kind="aws-credential-inventory", status="SUCCEEDED",
                                                              coverage={"coverage_run_ids": [rid]}))


@pytest.mark.parametrize("kind", ["provider-metadata-inventory", "aws-credential-inventory"])
@pytest.mark.parametrize("items", [0, 9])
@pytest.mark.parametrize("coverage_status,status", [("COMPLETE", "SUCCEEDED"), ("PARTIAL", "PARTIAL")])
def test_metadata_record_counts_and_partial_status_are_separate_from_content_counts(kind, items, coverage_status, status):
    # Schema 1 collections (AWS inventory, Vault and secret-store reads) report records the same way.
    body = present_scan_run(ScanJob(kind=kind, status="SUCCEEDED", objects=0,
        coverage={"metadata_items": items, "count_basis": "COMMITTED_METADATA_RECORDS", "coverage_status": coverage_status}))
    assert body["metadata_items"] == items and body["count_basis"] == "COMMITTED_METADATA_RECORDS"
    assert body["resources_succeeded"] == 0 and body["status"] == status


@pytest.mark.parametrize("coverage", [{}, {"metadata_items": 9},
    {"metadata_items": 9, "count_basis": "COMMITTED_OBJECT_ATTEMPTS"},
    *({"metadata_items": count, "count_basis": "COMMITTED_METADATA_RECORDS"} for count in (None, -1, True, "9", 9.5))])
def test_unreported_or_invalid_metadata_count_is_not_presented_as_zero(coverage):
    body = present_scan_run(ScanJob(kind="provider-metadata-inventory", status="SUCCEEDED", coverage=coverage))
    assert "metadata_items" not in body and "count_basis" not in body


def test_content_counts_and_terminal_failure_keep_their_own_meaning():
    coverage = {"metadata_items": 9, "count_basis": "COMMITTED_METADATA_RECORDS", "coverage_status": "PARTIAL"}
    content = present_scan_run(ScanJob(kind="scope", status="SUCCEEDED", objects=4, coverage=coverage))
    assert content["resources_succeeded"] == 4 and content["status"] == "SUCCEEDED"
    assert "metadata_items" not in content and "count_basis" not in content
    for status in ("FAILED", "CANCELLED"):
        body = present_scan_run(ScanJob(kind="provider-metadata-inventory", status=status, coverage=coverage))
        assert body["status"] == status and body["metadata_items"] == 9


@pytest.mark.parametrize("error, expected", [
    ("GITHUB_TREE_UNAVAILABLE: SYNTHETIC_PRIVATE_PROVIDER_BODY", "GITHUB_TREE_UNAVAILABLE"),
    ("unexpected provider body SYNTHETIC_PRIVATE_PROVIDER_BODY", "SCAN_FAILED"),
])
def test_every_job_read_surface_drops_provider_exception_text(error, expected):
    c = client()
    repo = c.app.state.repo
    job = repo.enqueue_job(ScanJob(kind="scope"))
    repo.fail_job(job.id, error)
    paths = ("scan-jobs", f"scan-jobs/{job.id}", "scan-runs", f"scan-runs/{job.id}/coverage", "source-scan-jobs")
    for path in paths:
        response = c.get(f"/api/v1/{path}", headers=auth())
        assert response.status_code == 200
        assert "SYNTHETIC_PRIVATE_PROVIDER_BODY" not in response.text
        assert expected in response.text


def test_a_run_partial_only_for_the_upgrade_hold_says_so_on_both_run_lists():
    c = client()
    repo = c.app.state.repo
    held = {"root_coverage_complete": False, "policy_held": 1}
    runs = {}
    for name, coverage in (("held only", {**held, "policy_held_only": True}),
                           ("held and a gap", {**held, "inspection_gaps": 1}),
                           ("not held", {"root_coverage_complete": False})):
        job = repo.enqueue_job(ScanJob(kind="scope", payload={"mode": "DELTA", "trigger": "SCHEDULE"}))
        repo.complete_job(job.id, objects=1, findings=0, coverage=coverage)
        runs[str(job.id)] = name
    scan_runs = {runs[r["id"]]: r for r in c.get("/api/v1/scan-runs", headers=auth()).json()}
    jobs = {runs[j["id"]]: j for j in c.get("/api/v1/source-scan-jobs", headers=auth()).json()}
    # Still partial on every list: the held roots were not read whole under the new rules.
    assert {r["status"] for r in scan_runs.values()} == {j["status"] for j in jobs.values()} == {"PARTIAL"}
    assert all(j["result_status"] is None for j in jobs.values())
    assert (scan_runs["held only"]["policy_held_roots"], scan_runs["held only"]["policy_held_only"]) == (1, True)
    assert scan_runs["held and a gap"]["policy_held_roots"] == 1 and "policy_held_only" not in scan_runs["held and a gap"]
    assert "policy_held_roots" not in scan_runs["not held"]
    assert {name: j["safe_error_code"] for name, j in jobs.items()} == {
        "held only": "POLICY_HELD", "held and a gap": "SCOPE_INCOMPLETE", "not held": "SCOPE_INCOMPLETE"}


def test_connection_scan_history_excludes_metadata_jobs():
    c = client()
    repo = c.app.state.repo
    connection = repo.create_connection(Connection(provider="github", name="synthetic"))
    job = repo.enqueue_job(ScanJob(kind="catalog-refresh", connection_id=connection.id))
    repo.complete_job(job.id, objects=0, findings=0)
    response = c.get(f"/api/v1/source-connections/{connection.id}/blast-radius", headers=auth())
    assert response.status_code == 200
    assert response.json()["scan_count"] == 0
    assert response.json()["first_scan_at"] is None and response.json()["last_scan_at"] is None
