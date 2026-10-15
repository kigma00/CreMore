"""Exercise API -> shared queue -> Google fixture -> SQL -> dashboard reads."""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cremore_gcp_provider.gcp_auth import GcpAuthError
from cremore_gcp_provider.metadata import adapter
from cremore_gcp_provider.metadata.tests.fake import (
    API_KEY_NAME,
    PROJECT,
    SECRET,
    FakeTransport,
    inventory_responses,
    spec,
)
from fastapi.testclient import TestClient
from sqlalchemy import select

from cremore.api import create_app
from cremore.config import Settings
from cremore.coverage.gcp_store import GcpStore
from cremore.coverage.metadata_store import MetadataStore
from cremore.coverage.scheduling import poll_metadata_schedules
from cremore.coverage.store import CoverageError
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.worker.worker import JobWorker

KEY_VALUE = "AIza" + "B" * 35
BINARY = b"\x00\xff\x01synthetic-secret"
TOKEN = "test-gcp-admin-" + "a" * 32


@pytest.fixture(params=["memory", "sqlite"])
def stack(request, monkeypatch):
    if request.param == "memory":
        repo = InMemoryRepository()
    else:
        engine = make_engine("sqlite:///:memory:")
        create_all(engine)
        repo = SqlRepository(engine)
    settings = Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32)
    app = create_app(repo=repo, settings=settings)
    client = TestClient(app, headers={"Authorization": "Bearer " + TOKEN})
    worker = JobWorker(repo, orchestrator=app.state.orchestrator)
    monkeypatch.setattr(adapter, "adc_token", lambda: lambda: "synthetic-adc-token")
    yield repo, settings, client, worker
    client.close()
    if request.param == "sqlite":
        engine.dispose()


def responses():
    data = inventory_responses()
    for body in data.values():
        if "accounts" in body:
            body["accounts"] = [row for row in body["accounts"] if "@" in row["email"]]
        if "keys" in body:
            body["keys"] = [row for row in body["keys"] if row.get("name", "").startswith("projects/")]
        if "versions" in body:
            body["versions"] = [row for row in body["versions"] if row["state"] != "PENDING"]
    data[f"https://apikeys.googleapis.com/v2/{API_KEY_NAME}/keyString"] = {"keyString": KEY_VALUE}
    data[f"https://secretmanager.googleapis.com/v1/{SECRET}/versions/2:access"] = {
        "name": SECRET + "/versions/2", "payload": {"data": base64.b64encode(BINARY).decode()}}
    return data


def create(client, **changes):
    """The value-reading GCP collection a provider connection's step 4 creates."""
    from cremore.onboarding.fixtures_test import collection

    body = spec(capabilities=["inventory", "vault_metadata", "issuer_value", "vault_value"],
                options={"include_values": True, "include_deleted": True}, **changes).model_dump()
    row, _token = collection(client.app.state.repo, body)
    return str(row["id"])


def collect(stack, monkeypatch, cid, data=None, failures=None):
    repo, _, client, worker = stack
    transport = FakeTransport(data if data is not None else responses(), failures=failures)
    monkeypatch.setattr(adapter, "Transport", lambda *_args, **_kwargs: transport)
    queued = client.post(f"/api/v2/coverage/connections/{cid}/collect").json()
    assert "job_id" in queued, queued
    assert worker.process_next()
    return repo.get_job(uuid.UUID(queued["job_id"])), transport


def stored_observations(repo):
    if isinstance(repo, InMemoryRepository):
        return repr(repo.coverage_memory)
    from cremore.db.schema import metadata

    with repo.engine.connect() as conn:
        return repr({name: list(conn.execute(select(table)).mappings()) for name, table in metadata.tables.items()
                     if name.startswith(("coverage_", "gcp_"))})


def test_only_digests_reach_the_database_and_payload_digests_are_private(stack, monkeypatch):
    repo, _, client, _ = stack
    cid = create(client)
    job, transport = collect(stack, monkeypatch, cid)
    assert job.status == "SUCCEEDED", job.error
    view = client.get(f"/api/v2/coverage/connections/{cid}").json()
    assert view["connection_auth"]["state"] == "READY", view
    # The binary Secret was read completely, but cannot be classified as a
    # credential by the detection engine. Keep that uncertainty explicit.
    assert view["latest_run"]["status"] == "PARTIAL"
    assert view["latest_run"]["reasons"] == ["UNRESOLVED_ITEMS"]
    records = list(MetadataStore(repo).iter_records(uuid.UUID(view["latest_run"]["id"])))
    reports = [row for row in records if row["record_type"] == "operation_report"]
    assert reports and all(row["status"] in ("COMPLETE", "NOT_REQUESTED") for row in reports)
    digests = {row["provenance"]["resource_id"]: row["payload_digest"] for row in records if row.get("payload_digest")}
    assert set(digests) == {API_KEY_NAME, SECRET + "/versions/2"}
    assert {value["scheme"] for value in digests.values()} == {"cremore-gcp-payload-v1/hmac-sha256"}
    store = GcpStore(repo)
    with pytest.raises(CoverageError, match="GCP_INVALID_PAGE"):
        store.page(uuid.UUID(cid), "values")
    with store.transaction() as conn:
        assert store.count(conn, "gcp_values", uuid.UUID(cid)) == 0
    persisted = stored_observations(repo)
    assert KEY_VALUE not in persisted and base64.b64encode(BINARY).decode() not in persisted
    assert repr(BINARY) not in persisted and "value_base64" not in persisted
    assert client.get(f"/api/v2/coverage/connections/{cid}/gcp-values").status_code == 404
    for path in ("connections", "inventory", f"connections/{cid}/gcp?kind=objects", f"runs/{view['latest_run']['id']}",
                 f"runs/{view['latest_run']['id']}/export", f"runs/{view['latest_run']['id']}/export?format=native"):
        response = client.get("/api/v2/coverage/" + path)
        assert response.status_code == 200
        text = response.text
        assert KEY_VALUE not in text and base64.b64encode(BINARY).decode() not in text
        assert "payload_digest" not in text and not any(value["fingerprint"] in text for value in digests.values())
    assert not any("/versions/1:access" in url for _, url, _ in transport.calls)
    assert KEY_VALUE not in json.dumps(job.payload)
    assert not any(event.event_type == "GCP_VALUES_READ" for event in repo.list_events())


def test_repeated_polls_only_report_real_changes(stack, monkeypatch):
    _, _, client, _ = stack
    cid = create(client)
    collect(stack, monkeypatch, cid)
    base = f"/api/v2/coverage/connections/{cid}/gcp"
    first = client.get(base).json()["counts"]
    collect(stack, monkeypatch, cid)
    assert client.get(base).json()["counts"] == first
    changed = responses()
    key_list = f"https://apikeys.googleapis.com/v2/projects/{PROJECT}/locations/global/keys"
    changed[key_list]["keys"][0]["deleteTime"] = "2026-09-22T00:00:00Z"
    changed[f"https://secretmanager.googleapis.com/v1/{SECRET}/versions"]["versions"][0]["state"] = "DISABLED"
    collect(stack, monkeypatch, cid, changed, {f"https://apikeys.googleapis.com/v2/{API_KEY_NAME}/keyString": "http_404"})
    events = client.get(base).json()["page"]["items"]
    assert any(row["event_type"] == "state_changed" and row["current_state"] == "deleted" for row in events)
    assert any(row["event_type"] == "state_changed" and row["current_state"] == "disabled" for row in events)
    assert client.get(base + "-values").status_code == 404


def test_binary_empty_and_unclassified_changes_keep_only_hmac_evidence(stack, monkeypatch):
    repo, _, client, _ = stack
    cid = create(client)
    url = f"https://secretmanager.googleapis.com/v1/{SECRET}/versions/2:access"

    def changed_events():
        rows = client.get(f"/api/v2/coverage/connections/{cid}/gcp").json()["page"]["items"]
        return sum(row["source_id"] == SECRET + "/versions/2" and row["event_type"] == "value_changed" for row in rows)

    collect(stack, monkeypatch, cid)
    assert changed_events() == 0
    for expected, payload in ((0, BINARY), (1, b""), (1, b""), (2, b"short")):
        data = responses()
        data[url]["payload"] = {"data": base64.b64encode(payload).decode()}
        collect(stack, monkeypatch, cid, data)
        assert changed_events() == expected
    # A denied read preserves the earlier HMAC as historical evidence, not a complete current observation.
    collect(stack, monkeypatch, cid, failures={url: "http_403"})
    collect(stack, monkeypatch, cid)
    assert changed_events() == 2
    persisted = stored_observations(repo)
    assert base64.b64encode(BINARY).decode() not in persisted and "value_base64" not in persisted


def test_partial_listing_never_marks_credentials_absent(stack, monkeypatch):
    _, _, client, _ = stack
    cid = create(client)
    collect(stack, monkeypatch, cid)
    fail = {f"https://apikeys.googleapis.com/v2/projects/{PROJECT}/locations/global/keys": "permission_denied_or_api_disabled"}
    collect(stack, monkeypatch, cid, failures=fail)
    rows = client.get(f"/api/v2/coverage/connections/{cid}/gcp?kind=objects").json()["page"]["items"]
    assert next(row for row in rows if row["source_id"] == API_KEY_NAME)["lifecycle_state"] == "active"
    empty = responses()
    empty[next(iter(fail))] = {"keys": []}
    collect(stack, monkeypatch, cid, empty)
    rows = client.get(f"/api/v2/coverage/connections/{cid}/gcp?kind=objects").json()["page"]["items"]
    assert next(row for row in rows if row["source_id"] == API_KEY_NAME)["lifecycle_state"] == "no_longer_listed"
    count = client.get(f"/api/v2/coverage/connections/{cid}/gcp").json()["counts"]["events"]
    collect(stack, monkeypatch, cid, empty)
    assert client.get(f"/api/v2/coverage/connections/{cid}/gcp").json()["counts"]["events"] == count


def test_missing_adc_is_a_failed_run_with_a_precise_code(stack, monkeypatch):
    repo, _, client, worker = stack
    def missing():
        raise GcpAuthError("GCP_ADC_NOT_CONFIGURED")
    monkeypatch.setattr(adapter, "adc_token", lambda: missing)
    cid = create(client)
    job = client.post(f"/api/v2/coverage/connections/{cid}/collect").json()
    assert worker.process_next()
    view = client.get(f"/api/v2/coverage/connections/{cid}").json()
    assert repo.get_job(uuid.UUID(job["job_id"])).status == "FAILED"
    assert "GCP_ADC_NOT_CONFIGURED" in view["latest_run"]["reasons"]
    assert view["connection_auth"]["state"] == "FAILED"


def test_schedule_works_without_a_content_scan_switch_and_deduplicates(stack):
    repo, settings, client, _ = stack
    cid = create(client, schedule_minutes=5)
    now = datetime.now(UTC)
    assert poll_metadata_schedules(repo, settings, now=now)["enqueued"] == 1
    assert poll_metadata_schedules(repo, settings, now=now)["enqueued"] == 0
    # A manual click shares the same connection lock and queued job.
    queued = client.post(f"/api/v2/coverage/connections/{cid}/collect").json()
    assert len(repo.list_jobs(100)) == 1
    run = client.get(f"/api/v1/scan-runs/{queued['job_id']}")
    assert run.status_code == 200 and run.json()["status"] == "QUEUED"
    assert run.json()["schedule"]["enabled"] and run.json()["schedule"]["minutes"] == 5
    expected = max(now, repo.get_job(uuid.UUID(queued["job_id"])).created_at) + timedelta(minutes=5)
    assert datetime.fromisoformat(run.json()["schedule"]["next_due_at"]) == expected
    assert client.get(f"/api/v1/scan-runs/{uuid.uuid4()}").status_code == 404
    repo.fail_job(uuid.UUID(queued["job_id"]), "SYNTHETIC_FAILURE")
    assert poll_metadata_schedules(repo, settings, now=now + timedelta(minutes=4))["enqueued"] == 0
    assert poll_metadata_schedules(repo, settings, now=now + timedelta(minutes=6))["enqueued"] == 1
    client.patch(f"/api/v2/coverage/connections/{cid}", json={"revision": 1, "enabled": False})
    assert poll_metadata_schedules(repo, settings, now=now + timedelta(hours=1))["enqueued"] == 0


def gcp_connection(client, purposes=("exposure", "inventory")):
    from cremore.onboarding.fixtures_test import wizard

    return wizard(client, {}, {"provider": "gcp", "purposes": list(purposes), "auth_method": "adc",
                               "target": {"project": PROJECT}},
                  plans={purpose: ({"schedule_minutes": 5} if purpose != "exposure" else {}) for purpose in purposes})


def test_one_gcp_connection_scans_storage_and_collects_its_inventory(stack):
    repo, _, client, _ = stack
    view = gcp_connection(client)
    kinds = {row["kind"]: row for row in view["created"]}
    source = repo.get_connection(uuid.UUID(kinds["content"]["id"]))
    row = MetadataStore(repo).get(uuid.UUID(kinds["metadata"]["id"]))
    assert source.provider == "gcp" and source.config["project"] == PROJECT
    assert row["spec"]["schedule_minutes"] == 5 and row["spec"]["auth_type"] == "adc"


def test_stopping_the_connection_also_stops_scheduled_inventory(stack):
    repo, settings, client, _ = stack
    view = gcp_connection(client)
    inventory = next(row["id"] for row in view["created"] if row["kind"] == "metadata")
    assert client.post(f"/api/v1/provider-connections/{view['id']}/disable").status_code == 200
    assert poll_metadata_schedules(repo, settings)["enqueued"] == 0
    stopped = client.post(f"/api/v2/coverage/connections/{inventory}/collect")
    assert stopped.status_code == 409 and stopped.json()["error"] == "CONNECTION_DISABLED_OR_MISSING"
    assert client.get(f"/api/v2/coverage/connections/{inventory}").json()["enabled"] is False


def test_new_enabled_secret_version_leaves_only_a_digest_on_the_next_poll(stack, monkeypatch):
    repo, _, client, _ = stack
    cid = create(client)
    collect(stack, monkeypatch, cid)
    data = responses()
    data[f"https://secretmanager.googleapis.com/v1/{SECRET}/versions"]["versions"].append(
        {"name": SECRET + "/versions/3", "state": "ENABLED"})
    data[f"https://secretmanager.googleapis.com/v1/{SECRET}/versions/3:access"] = {
        "name": SECRET + "/versions/3", "payload": {"data": base64.b64encode(b"synthetic-v3").decode()}}
    collect(stack, monkeypatch, cid, data)
    objects = client.get(f"/api/v2/coverage/connections/{cid}/gcp?kind=objects").json()["page"]["items"]
    assert any(row["source_id"].endswith("/versions/3") for row in objects)
    events = client.get(f"/api/v2/coverage/connections/{cid}/gcp").json()["page"]["items"]
    assert any(row["source_id"].endswith("/versions/3") and row["event_type"] == "value_collected" for row in events)
    persisted = stored_observations(repo)
    assert "synthetic-v3" not in persisted and base64.b64encode(b"synthetic-v3").decode() not in persisted


def test_disable_during_value_io_cannot_commit_that_digest(stack, monkeypatch):
    repo, _, client, worker = stack
    cid = create(client)
    class DisableDuringRead(FakeTransport):
        def get(self, url, params=None):
            response = super().get(url, params)
            if url.endswith("/keyString"):
                changed = client.patch(f"/api/v2/coverage/connections/{cid}", json={"revision": 1, "enabled": False})
                assert changed.status_code == 200
            return response
    transport = DisableDuringRead(responses())
    monkeypatch.setattr(adapter, "Transport", lambda *_args, **_kwargs: transport)
    queued = client.post(f"/api/v2/coverage/connections/{cid}/collect").json()
    assert worker.process_next()
    assert repo.get_job(uuid.UUID(queued["job_id"])).status == "FAILED"
    assert "cremore-gcp-payload-v1/hmac-sha256" not in stored_observations(repo)


def test_plaintext_read_is_gone_for_every_role_and_registration_still_requires_admin():
    from cremore.api.conftest import GROUPS, FakeIssuer, oidc_settings
    issuer = FakeIssuer()
    app = create_app(repo=InMemoryRepository(), settings=oidc_settings(), oidc_http_client=issuer)
    with TestClient(app) as client:
        path = f"/api/v2/coverage/connections/{uuid.uuid4()}/gcp-values"
        assert client.get(path).status_code == 404
        for role in ("viewer", "analyst", "remediator"):
            headers = {"Authorization": "Bearer " + issuer.mint(groups=(GROUPS[role],))}
            assert client.get(path, headers=headers).status_code == 404
            assert client.post("/api/v1/provider-connections", headers=headers,
                               json={"provider": "gcp"}).status_code == 403
        admin = {"Authorization": "Bearer " + issuer.mint(groups=(GROUPS["admin"],))}
        client.headers.update(admin)
        cid = create(client)
        assert client.get(f"/api/v2/coverage/connections/{cid}/gcp-values").status_code == 404
