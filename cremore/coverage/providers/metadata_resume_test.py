"""Real adapter/transport checkpoints across synthetic provider interruptions."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta

import cremore_azure_provider.metadata.adapter as azure
import cremore_gcp_provider.metadata.adapter as gcp
import httpx
import pytest
from cremore_azure_provider.metadata.azure_key_vault_test import ORIGIN, Vault, secret
from cremore_azure_provider.metadata.azure_key_vault_test import spec as azure_spec
from cremore_gcp_provider.metadata.tests.fake import EMAIL, PROJECT
from cremore_gcp_provider.metadata.tests.fake import spec as gcp_spec
from cremore_gcp_provider.metadata.tests.test_adapter import (
    LOGS,
    NOW,
    FakeTransport,
    with_evidence,
)
from cremore_github_provider.metadata.tests.fake import org_responses
from cremore_github_provider.metadata.tests.fake import spec as github_spec
from cremore_github_provider.metadata.tests.test_adapter import drive

from cremore.coverage.metadata_models import checkpoint_json


@pytest.mark.parametrize("provider", ["gcp", "azure"])
@pytest.mark.parametrize("exhausted", [False, True])
def test_waiting_retains_committed_cursor_and_charges_failed_requests(provider, exhausted):
    calls = []
    resuming = False
    account_path = f"/v1/projects/{PROJECT}/serviceAccounts"

    def respond(request):
        calls.append(request)
        if provider == "gcp":
            if "/services/" in request.url.path:
                return httpx.Response(200, json={"state": "ENABLED"})
            if request.url.path != account_path:
                return httpx.Response(200, json={})
            cursor = request.url.params.get("pageToken")
            if not cursor:
                return httpx.Response(200, json={"accounts": [{"email": EMAIL}], "nextPageToken": "next"})
            return httpx.Response(200, json={"accounts": []}) if resuming else httpx.Response(429)
        cursor = request.url.params.get("$skiptoken")
        if not cursor:
            return httpx.Response(200, json={"value": [secret("first")],
                                           "nextLink": f"{ORIGIN}/secrets?$skiptoken=next"})
        return httpx.Response(200, json={"value": [secret("second")]}) if resuming else httpx.Response(429)

    adapter, make_spec = (gcp, gcp_spec) if provider == "gcp" else (azure, azure_spec)
    spent = 5 if provider == "gcp" else 2
    spec = make_spec(max_requests=spent if exhausted else 100, options={"max_retries": 0})
    now = datetime(2026, 9, 21, tzinfo=UTC)
    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        pages = list(adapter.collect_pages(spec, secrets={}, checkpoint={}, check=lambda: None,
                                           client=client, token=lambda: "synthetic", now=now))
        waiting = pages[-1]
        assert waiting.status == "WAITING"
        state = checkpoint_json(waiting.checkpoint)
        assert state["requests"] == spent == len(calls)
        assert state["cursor"] == pages[-2].checkpoint["cursor"] and state["cursor"]
        committed = [r.model_dump() for page in pages for r in page.records]
        resuming = True
        calls.clear()
        resumed = list(adapter.collect_pages(spec, secrets={}, checkpoint=state, check=lambda: None,
                                             client=client, token=lambda: "synthetic", now=now + timedelta(days=1),
                                             read_records=lambda: iter(committed)))
        assert resumed[-1].checkpoint["requests"] == spent + len(calls)
        if exhausted:
            assert not calls and resumed[-1].status == "PARTIAL"
            assert "REQUEST_BUDGET_EXCEEDED" in resumed[-1].reasons
        else:
            assert calls[0].url.params.get("pageToken" if provider == "gcp" else "$skiptoken") == "next"
            assert resumed[-1].status == "COMPLETE"
        if provider == "gcp":
            assert state["window_end"] == resumed[-1].checkpoint["window_end"] == now.isoformat()


def test_github_rejected_page_does_not_advance_tasks_or_claim_emitted_records():
    transport, _, records, state, final = drive(
        github_spec(max_records=3, options={"sources": ["org_sso"]}), org_responses())
    assert final.status == "PARTIAL" and "RECORD_BUDGET_EXCEEDED" in final.reasons
    # Only the App identity page (GET /app) fit; the rejected SSO page claims nothing.
    assert {r["provenance"]["operation"] for r in records} == {"github.app"}
    assert state["emitted"] == len(records)
    assert state["requests"] == transport.requests == 1
    tasks = {item["kind"]: item for item in state["tasks"].values()}
    assert set(tasks) == {"app", "org_sso"} and tasks["app"]["status"] == "complete"
    task = tasks["org_sso"]
    assert task["status"] == "pending" and task["pages"] == task["count"] == 0
    assert task["next_path"]


@pytest.mark.parametrize("rows,next_link,reasons", [
    ([secret()], f"{ORIGIN}/secrets?$skiptoken=next", {"PAGE_LIMIT_REACHED"}),
    ([42, {}, secret()], None, {"INVALID_IDENTIFIERS"}),
])
def test_azure_run_and_saved_counts_reflect_incomplete_listing(rows, next_link, reasons):
    pages = list(azure.collect_pages(azure_spec(max_pages=1), secrets={}, checkpoint={},
                                    check=lambda: None, transport=Vault({"/secrets": {
                                        "value": rows, "nextLink": next_link}})))
    report = next(r for p in pages for r in p.records if r.record_type == "operation_report"
                  and r.provenance.operation == "azure.key_vault.secrets")
    assert report.received_records == len(rows) and report.saved_records == 1
    assert report.status == pages[-1].status == "PARTIAL"
    assert reasons <= set(report.reasons) and reasons <= set(pages[-1].reasons)


def test_azure_exact_page_limit_can_finish_the_last_versions_page():
    pages = list(azure.collect_pages(
        azure_spec(max_pages=1, options={"sources": ["secrets", "versions"]}),
        secrets={}, checkpoint={}, check=lambda: None, transport=Vault({
            "/secrets": {"value": [secret()]},
            "/secrets/db-password/versions": {"value": [secret(version="a1")]}})))
    report = next(r for p in pages for r in p.records if r.record_type == "operation_report"
                  and r.provenance.operation == "azure.key_vault.versions")
    assert report.status == pages[-1].status == "COMPLETE"


def test_azure_partial_listing_never_establishes_absence():
    def read(response):
        return [r.model_dump() for page in azure.collect_pages(
            azure_spec(max_pages=1), secrets={}, checkpoint={}, check=lambda: None,
            transport=Vault({"/secrets": response})) for r in page.records]
    before = read({"value": [secret()]})
    partial = read({"value": [], "nextLink": f"{ORIGIN}/secrets?$skiptoken=next"})
    diff = azure.compare_records(before, partial)
    assert not diff["removed"] and diff["absence_not_evaluated"]
    complete = azure.compare_records(before, read({"value": []}))
    assert complete["removed"] and not complete["absence_not_evaluated"]


@pytest.mark.parametrize("phase", ["relations_secret_access", "relations_api_metrics"])
def test_gcp_resume_retains_relation_issues_and_aggregate_counts(phase):
    connection = gcp_spec(capabilities=["inventory", "vault_metadata", "relations"])
    responses = with_evidence()
    if phase == "relations_secret_access":
        broken = deepcopy(responses[LOGS]["entries"][0])
        broken["insertId"] = None
        responses[LOGS] = [{"entries": [broken], "nextPageToken": "next"}, {"entries": []}]
        operation, reason, expected_pages = "gcp.cloud_logging.secret_access", "INVALID_LOG_EVIDENCE", 2
    else:
        keys = responses[f"https://apikeys.googleapis.com/v2/projects/{PROJECT}/locations/global/keys"]["keys"]
        second = deepcopy(keys[0])
        second.update(uid="2a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d", name=second["name"][:-1] + "2")
        keys.append(second)
        metrics = f"https://monitoring.googleapis.com/v3/projects/{PROJECT}/timeSeries"
        responses[metrics] = [{"timeSeries": [{}], "nextPageToken": "next"}, {"timeSeries": []}]
        operation, reason, expected_pages = "gcp.cloud_monitoring.api_request_count", "INVALID_METRIC_SERIES", 3
    committed = []
    pages = gcp.collect_pages(connection, secrets={}, checkpoint={}, check=lambda: None,
                              transport=FakeTransport(responses), now=NOW)
    for page in pages:
        committed.extend(record.model_dump() for record in page.records)
        state = page.checkpoint
        if state.get("cursor", {}).get("phase") == phase and (
            phase == "relations_secret_access" or state["cursor"].get("index") == 1
        ):
            break
    else:
        pytest.fail("expected a committed page inside the relation phase")
    pages.close()
    remaining = with_evidence()
    remaining[LOGS] = {"entries": []}
    resumed = list(gcp.collect_pages(connection, secrets={}, checkpoint=state, check=lambda: None,
                                     transport=FakeTransport(remaining), now=NOW + timedelta(days=2),
                                     read_records=lambda: iter(committed)))
    report = next(r for p in resumed for r in p.records if r.record_type == "operation_report"
                  and r.provenance.operation == operation)
    assert report.status == "PARTIAL" and reason in report.reasons
    assert report.pages == expected_pages
    if phase == "relations_api_metrics":
        from cremore_gcp_provider.metadata.normalization import record_values
        assert record_values(report.model_dump())["keys_checked"] == 2
