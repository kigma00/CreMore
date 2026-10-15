"""The schema 2 coverage API: roles, scope separation and machine submissions.

Schema 1 and schema 2 share a store and a worker, so every test here asks the
same question from a different side: can one version's connection be read,
changed, collected or submitted to through the other version's routes, and does
a caller ever reach a record the connection did not approve.
"""

from __future__ import annotations

import uuid

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.config import Settings
from cremore.db.repository import InMemoryRepository

TOKEN = "metadata-token-" + "0" * 32
AUTH = {"Authorization": "Bearer " + TOKEN}
GITLAB = {
    "schema_version": 2, "name": "GitLab group tokens", "provider": "gitlab",
    "origin": "https://gitlab.com", "edition": "cloud",
    "scopes": [{"kind": "group", "id": "10"}], "capabilities": ["inventory"],
    "auth_type": "token", "secret_refs": {"token": "vault://gitlab/token"},
    "options": {"mode": "inventory"},
}
AWS = {"name": "Synthetic IAM", "provider": "aws_iam", "account_id": "123456789012"}
PROJECT = "cremore-demo-project"
# GCP takes no stored secret and its machine guard accepts a source report, so
# it is the connection the submission tests use.
GCP = {
    "schema_version": 2, "name": "GCP project inventory", "provider": "gcp",
    "origin": "https://googleapis.com", "edition": "cloud",
    "scopes": [{"kind": "project", "id": PROJECT}], "capabilities": ["inventory"],
    "auth_type": "adc", "options": {"mode": "inventory"},
}


class Signed:
    """Every call carries the local operator credential the API expects."""

    def __init__(self, inner):
        self.inner = inner

    def request(self, method, url, **kwargs):
        headers = {**AUTH, **kwargs.pop("headers", {})}
        return self.inner.request(method, url, headers=headers, **kwargs)

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def put(self, url, **kwargs):
        return self.request("PUT", url, **kwargs)

    def patch(self, url, **kwargs):
        return self.request("PATCH", url, **kwargs)


@pytest.fixture
def client():
    app = create_app(repo=InMemoryRepository(),
                     settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN,
                                       FINGERPRINT_KEY="ab" * 32))
    with TestClient(app) as value:
        yield Signed(value)


def create(client, spec=None):
    """A collection as a provider connection's step 4 creates it (cremore/onboarding)."""
    from fastapi.encoders import jsonable_encoder

    from cremore.coverage.correlation import public_connection
    from cremore.onboarding.fixtures_test import collection

    row, token = collection(client.inner.app.state.repo, {"schema_version": 2, **(spec or GITLAB)})
    return jsonable_encoder({**public_connection(row, include_references=True), "collector_token": token})


def test_the_provider_catalog_lists_only_installed_adapters(client):
    body = client.get("/api/v2/coverage/providers").json()
    assert body["schema_version"] == 2
    names = {entry["provider"] for entry in body["items"]}
    assert {"gitlab", "gcp", "github", "atlassian", "bitbucket"} <= names
    gcp = next(entry for entry in body["items"] if entry["provider"] == "gcp")
    # Onboarding needs to know ADC takes no stored secret at all. Since the
    # gcp-dashboard-oauth integration, dashboard OAuth stores three sealed slots.
    assert gcp["auth_secret_roles"] == {"adc": [], "workload_identity": [],
                                        "google_oauth": ["client_id", "client_secret", "refresh_token"]}
    assert any("PRIVATE_KEYS" in reason for reason in gcp["limitations"])
    assert {"notion", "azure_entra", "azure_key_vault"} <= names


@pytest.mark.parametrize("spec", [
    {"name": "Enterprise PAT", "provider": "notion", "origin": "https://api.notion.com",
     "scopes": [{"kind": "workspace", "id": "11111111-2222-4333-8444-555555555555"}],
     "capabilities": ["inventory"], "auth_type": "bearer", "secret_refs": {"token": "vault://notion/admin"}},
    {"name": "Entra", "provider": "azure_entra", "origin": "https://graph.microsoft.com",
     "tenant": "11111111-2222-4333-8444-555555555555", "tenant_confirmed": True,
     "scopes": [{"kind": "organization", "id": "11111111-2222-4333-8444-555555555555"}],
     "capabilities": ["inventory"], "auth_type": "workload_identity"},
])
def test_new_provider_connections_round_trip_and_enqueue_without_provider_calls(client, spec):
    created = create(client, spec)
    cid = created["id"]
    loaded = client.get(f"/api/v2/coverage/connections/{cid}")
    assert loaded.status_code == 200, loaded.text
    assert loaded.json()["spec"]["provider"] == spec["provider"]
    # The admin detail intentionally contains references; list responses do not.
    assert "vault://notion/admin" not in client.get("/api/v2/coverage/connections").text
    queued = client.post(f"/api/v2/coverage/connections/{cid}/collect", json={})
    assert queued.status_code == 202, queued.text


def test_public_metadata_omits_provider_hash_evidence_without_mutating_storage():
    from cremore.api.metadata_coverage import public_metadata

    private = {"evidence": "PROVIDER_DIGEST", "fingerprint": "a" * 64}
    record = {"body": {"value_match": private, "facts": []}}
    original = {"items": [{"summary": record["body"]}], "records": {"items": [record]}}
    shown = public_metadata(original)
    assert shown["items"][0]["summary"]["value_match"] is None
    assert shown["records"]["items"][0]["body"]["value_match"] is None
    assert original["records"]["items"][0]["body"]["value_match"] is private


def test_public_metadata_hides_payload_digests_and_retired_storage_options():
    from cremore.api.metadata_coverage import public_metadata

    original = {"items": [{"body": {"payload_digest": {"fingerprint": "a" * 64}, "facts": []}}],
                "spec": {"options": {"store_values": True, "include_values": True}}}
    assert public_metadata(original) == {"items": [{"body": {"facts": []}}],
        "spec": {"options": {"include_values": True}}}
    assert original["spec"]["options"]["store_values"] is True


def test_public_metadata_filters_legacy_issuer_identifiers_without_mutating_storage():
    from cremore.api.metadata_coverage import public_metadata

    email = "scanner@synthetic-project.iam.gserviceaccount.com"
    safe = f"serviceAccountKey:{email}:" + "a" * 40
    invalid = f"serviceAccountKey:{email}:legacy-key-id"
    # A syntactically valid email local part can still contain a recognized token.
    unsafe = "serviceAccountKey:glpat-" + "a" * 20 + "@synthetic-project.iam.gserviceaccount.com:" + "b" * 40
    bodies = [{"issuer_identifier": value} for value in (safe, invalid, unsafe, "")]
    original = {"items": [{"summary": body} for body in bodies],
                "records": {"items": [{"body": body} for body in bodies]}}
    shown = public_metadata(original)
    expected = [{"issuer_identifier": safe}, {}, {}, {"issuer_identifier": ""}]
    assert [row["summary"] for row in shown["items"]] == expected
    assert [row["body"] for row in shown["records"]["items"]] == expected
    assert [row["body"]["issuer_identifier"] for row in original["records"]["items"]] == [safe, invalid, unsafe, ""]


def test_public_metadata_omits_private_session_fingerprint_but_preserves_legacy_value_contract():
    from cremore.api.metadata_coverage import public_metadata

    private = {"evidence": "VALUE", "fingerprint": "a" * 64, "session_fingerprint": "b" * 64}
    body = {"value_match": private, "facts": []}
    original = {"items": [{"summary": body}], "records": {"items": [{"body": body}]}}
    shown = public_metadata(original)
    for record in (shown["items"][0]["summary"], shown["records"]["items"][0]["body"]):
        assert record["value_match"] == {"evidence": "VALUE", "fingerprint": "a" * 64}
    assert original["records"]["items"][0]["body"]["value_match"]["session_fingerprint"] == "b" * 64


def test_a_connection_round_trips_without_echoing_its_secret_reference(client):
    created = create(client)
    assert created["collector_token"]
    # A vault path is a pointer an Admin may read back; a sealed value is not.
    assert created["spec"]["secret_refs"] == {"token": "vault://gitlab/token"}
    sealed = create(client, {**GITLAB, "name": "Sealed GitLab",
                             "secret_refs": {"token": "sealed:v1:" + "a" * 60}})
    assert sealed["spec"]["secret_refs"]["token"] != "sealed:v1:" + "a" * 60

    listed = client.get("/api/v2/coverage/connections").json()["items"]
    assert {row["id"] for row in listed} == {created["id"], sealed["id"]}
    # The list is a read for every signed-in role, so it names no reference.
    assert all(row["spec"]["secret_refs"] == {"token": "configured"} for row in listed)
    assert listed[0]["latest_run"] is None
    detail = client.get(f"/api/v2/coverage/connections/{created['id']}").json()
    assert detail["revision"] == 1


def test_worker_authentication_failure_reaches_connection_status(client):
    from cremore.worker import JobWorker

    created = create(client)
    path = f"/api/v2/coverage/connections/{created['id']}"
    assert client.post(path + "/collect").status_code == 202
    assert JobWorker(client.inner.app.state.repo).process_next()
    detail = client.get(path).json()
    assert detail["latest_run"] is None
    assert detail["latest_job"]["status"] == "FAILED"
    assert detail["latest_job"]["error"] == "METADATA_SECRET_UNAVAILABLE"


def test_an_edit_keeps_the_stored_reference_and_never_takes_a_new_one(client):
    created = create(client)
    spec = {key: value for key, value in GITLAB.items() if key != "secret_refs"}
    spec["name"] = "Renamed"
    changed = client.patch(f"/api/v2/coverage/connections/{created['id']}",
                           json={"revision": 1, "spec": spec})
    assert changed.status_code == 200, changed.text
    assert changed.json()["revision"] == 2
    assert changed.json()["spec"]["secret_refs"] == {"token": "vault://gitlab/token"}
    # The credential is its provider connection's: an edit cannot point it elsewhere.
    moved = client.patch(f"/api/v2/coverage/connections/{created['id']}",
                         json={"revision": 2, "spec": {**spec, "secret_refs": {"token": "vault://other/token"}}})
    assert moved.status_code == 409 and moved.json()["error"] == "CREDENTIAL_BELONGS_TO_PROVIDER_CONNECTION"
    # So is how it signs in: the provider connection's method decides the auth type.
    signed = client.patch(f"/api/v2/coverage/connections/{created['id']}",
                          json={"revision": 2, "spec": {**spec, "auth_type": "bearer"}})
    assert signed.status_code == 409 and signed.json()["error"] == "CREDENTIAL_BELONGS_TO_PROVIDER_CONNECTION"
    # A stale revision is a conflict, not a silent overwrite.
    assert client.patch(f"/api/v2/coverage/connections/{created['id']}",
                        json={"revision": 1, "enabled": False}).status_code == 409


def test_an_edit_the_adapter_refuses_never_reaches_the_connection(client):
    created = create(client)
    for change in ({"scopes": [{"kind": "workspace", "id": "x"}]},
                   {"origin": "https://gitlab.example.com", "edition": "cloud",
                    "options": {"mode": "inventory", "include_enterprise_pat": True}},
                   {"capabilities": ["inventory", "policy"]}):
        spec = {**{key: value for key, value in GITLAB.items() if key != "secret_refs"}, **change}
        response = client.patch(f"/api/v2/coverage/connections/{created['id']}", json={"revision": 1, "spec": spec})
        assert response.status_code in (409, 422), (change, response.text)
    assert client.get(f"/api/v2/coverage/connections/{created['id']}").json()["revision"] == 1


def test_a_collection_is_queued_once_and_only_for_an_enabled_connection(client):
    created = create(client)
    first = client.post(f"/api/v2/coverage/connections/{created['id']}/collect")
    assert first.status_code == 202, first.text
    second = client.post(f"/api/v2/coverage/connections/{created['id']}/collect")
    assert second.json()["job_id"] == first.json()["job_id"]
    # The logs name the collection a queued run belongs to.
    [listed] = [run for run in client.get("/api/v1/scan-runs").json() if run["id"] == first.json()["job_id"]]
    assert listed["kind"] == "provider-metadata-inventory" and listed["coverage_connection_id"] == created["id"]
    client.patch(f"/api/v2/coverage/connections/{created['id']}",
                 json={"revision": 1, "enabled": False})
    assert client.post(f"/api/v2/coverage/connections/{created['id']}/collect").status_code == 409


def test_a_recollection_needs_a_finished_run_of_this_connection(client):
    created = create(client)
    response = client.post(f"/api/v2/coverage/connections/{created['id']}/collect",
                           json={"operations": ["org_sso"]})
    assert response.status_code == 409
    assert response.json()["error"] == "RETRY_RUN_REQUIRED"
    missing = str(uuid.uuid4())
    assert client.post(f"/api/v2/coverage/connections/{created['id']}/collect",
                       json={"retry_from_run": missing}).status_code == 404


@pytest.mark.parametrize("provider", ["atlassian", "gcp"])
def test_recollection_api_uses_the_registered_runtime_planner(client, monkeypatch, provider):
    from cremore_atlassian_provider.metadata import adapter

    scope_id = "12345678-1234-4234-8234-123456789012"
    spec = GCP if provider == "gcp" else {
        "name": "Synthetic organization", "provider": "atlassian",
        "origin": "https://api.atlassian.com",
        "scopes": [{"kind": "organization", "id": scope_id}],
        "capabilities": ["inventory"], "auth_type": "bearer",
        "secret_refs": {"token": "vault://synthetic/admin"},
    }
    created = create(client, spec)
    headers = {"X-Cremore-Collector-Token": created["collector_token"]}
    config = client.get(f"/api/v2/coverage/collector/{created['id']}", headers=headers).json()
    started = client.post(f"/api/v2/coverage/collector/{created['id']}/runs", headers=headers,
        json={"revision": 1, "request_id": str(uuid.uuid4()), "contract": config["contract"]})
    assert started.status_code == 200, started.text
    run_id = started.json()["id"]
    finished = client.post(f"/api/v2/coverage/collector/{created['id']}/runs/{run_id}/finish",
        headers=headers, json={"batch_count": 0, "item_count": 0, "status": "PARTIAL"})
    assert finished.status_code == 200, finished.text
    calls = []

    def planner(records, **selection):
        calls.append((list(records), selection))
        return {"report_type": "metadata_recollection_plan"}

    monkeypatch.setattr(adapter, "plan_recollection", planner)
    response = client.post(f"/api/v2/coverage/connections/{created['id']}/collect",
        json={"retry_from_run": run_id, "scope_id": scope_id,
              "operations": ["service-accounts"], "include_unverified": True})
    if provider == "atlassian":
        assert response.status_code == 202, response.text
        assert calls == [([], {"scope_id": scope_id, "operations": ["service-accounts"],
                               "include_unverified": True})]
    else:
        assert response.status_code == 409, response.text
        assert response.json()["error"] == "METADATA_RECOLLECTION_UNSUPPORTED"
        assert calls == []


def test_schema_1_and_schema_2_connections_never_reach_each_other(client):
    from cremore.onboarding.fixtures_test import collection

    v1, _token = collection(client.inner.app.state.repo, AWS)
    v1 = {"id": str(v1["id"])}
    v2 = create(client)

    assert [row["id"] for row in client.get("/api/v2/coverage/connections").json()["items"]] == [v2["id"]]
    assert client.get(f"/api/v2/coverage/connections/{v1['id']}").status_code == 409

    # A schema 2 connection is invisible to every schema 1 write path.
    assert client.patch(f"/api/v1/coverage/connections/{v2['id']}",
                        json={"revision": 1, "enabled": False}).status_code == 409
    assert client.post(f"/api/v1/coverage/connections/{v2['id']}/collect").status_code == 409
    # The token is this connection's own, so the refusal names the schema rather
    # than pretending the caller is unauthenticated.
    mismatch = client.get(f"/api/v1/coverage/collector/{v2['id']}",
                          headers={"X-Cremore-Collector-Token": v2["collector_token"]})
    assert mismatch.status_code == 409
    assert mismatch.json()["error"] == "COVERAGE_SCHEMA_MISMATCH"


def test_a_missing_v1_connection_keeps_its_own_status_codes(client):
    missing = "00000000-0000-4000-8000-000000000001"
    assert client.patch(f"/api/v1/coverage/connections/{missing}",
                        json={"revision": 1, "enabled": False}).status_code == 404
    assert client.post(f"/api/v1/coverage/connections/{missing}/collect").status_code == 409


def test_a_machine_collector_reads_its_own_configuration_without_references(client):
    created = create(client)
    headers = {"X-Cremore-Collector-Token": created["collector_token"]}
    config = client.get(f"/api/v2/coverage/collector/{created['id']}", headers=headers)
    assert config.status_code == 200, config.text
    body = config.json()
    assert body["spec"]["secret_refs"] == {}
    assert body["auth_slots"] == ["token"]
    assert body["contract"]["principal_verified"] is False
    assert "MACHINE_REQUIRES_EXPLICIT_RESOURCE_SCOPES" in body["limitations"]
    assert client.get(f"/api/v2/coverage/collector/{created['id']}",
                      headers={"X-Cremore-Collector-Token": "wrong"}).status_code == 401


def record(scope=("project", PROJECT), *, operation="gcp.service_accounts"):
    from cremore_gcp_provider.metadata import CONTRACT_VERSION, SOURCE_COMMIT

    return {
        "record_type": "operation_report", "purpose": "issuer_inventory",
        "scope": {"kind": scope[0], "id": scope[1]},
        "provenance": {"operation": operation, "observed_at": "2026-09-21T00:00:00+00:00",
                       "resource_id": "", "source_commit": SOURCE_COMMIT,
                       "contract_version": CONTRACT_VERSION},
        "status": "COMPLETE", "reasons": [], "pages": 1, "received_records": 0,
        "saved_records": 0, "facts": [], "omissions": [],
    }


def submit(client, created, batch, *, run=None):
    headers = {"X-Cremore-Collector-Token": created["collector_token"]}
    if run is None:
        started = client.post(
            f"/api/v2/coverage/collector/{created['id']}/runs", headers=headers,
            json={"revision": created["revision"], "request_id": str(uuid.uuid4()),
                  "contract": client.get(f"/api/v2/coverage/collector/{created['id']}",
                                         headers=headers).json()["contract"]})
        assert started.status_code == 200, started.text
        run = started.json()["id"]
    return run, client.put(f"/api/v2/coverage/collector/{created['id']}/runs/{run}/batches",
                           headers=headers, json={"schema_version": 2, "index": 0, "items": batch})


def test_a_submitted_record_outside_the_approved_scope_is_refused(client):
    created = create(client, GCP)
    run, accepted = submit(client, created, [record()])
    assert accepted.status_code == 200, accepted.text
    _run, refused = submit(client, created, [record(("project", "other-project-id"))], run=run)
    assert refused.status_code == 409
    _run, wrong_provider = submit(client, created, [
        {**record(), "provenance": {**record()["provenance"], "source_commit": "0" * 40}}], run=run)
    assert wrong_provider.status_code == 409


def test_a_finished_run_is_readable_and_its_reports_are_kept(client):
    created = create(client, GCP)
    headers = {"X-Cremore-Collector-Token": created["collector_token"]}
    run, accepted = submit(client, created, [record(), record(operation="gcp.api_keys")])
    assert accepted.status_code == 200, accepted.text
    finished = client.post(f"/api/v2/coverage/collector/{created['id']}/runs/{run}/finish",
                           headers=headers,
                           json={"schema_version": 2, "batch_count": 1, "item_count": 2,
                                 "status": "PARTIAL", "reasons": ["AUDIT_FORBIDDEN"]})
    assert finished.status_code == 200, finished.text

    detail = client.get(f"/api/v2/coverage/runs/{run}?record_type=operation_report").json()
    assert detail["schema_version"] == 2
    assert detail["run"]["status"] == "PARTIAL"
    assert detail["run"]["reasons"] == ["AUDIT_FORBIDDEN"]
    assert [item["body"]["provenance"]["operation"] for item in detail["records"]["items"]] == [
        "gcp.service_accounts", "gcp.api_keys"]

    listed = client.get("/api/v2/coverage/connections").json()["items"][0]
    assert listed["latest_run"]["status"] == "PARTIAL"


def test_the_inventory_pages_on_the_server_and_counts_what_it_filtered(client):
    created = create(client)
    body = client.get("/api/v2/coverage/inventory?offset=0&limit=1").json()
    assert body["schema_version"] == 2
    assert body["limit"] == 1 and body["offset"] == 0
    assert body["items"] == [] and body["total"] == 0 and body["total_all"] == 0
    assert body["facets"] == {"provider": [], "object_kind": [], "purpose": []}
    assert client.get("/api/v2/coverage/inventory?limit=0").status_code == 422
    assert client.get("/api/v2/coverage/inventory?limit=501").status_code == 422
    assert client.get("/api/v2/coverage/inventory?provider=nowhere").status_code == 422
    assert client.get(f"/api/v2/coverage/inventory?connection_id={created['id']}").status_code == 200


def test_inventory_route_exposes_stored_facets_without_changing_filtered_counts(client):
    collected(client, [observation("apiKey:first"), observation("apiKey:second")])
    body = client.get("/api/v2/coverage/inventory?provider=gcp&q=apiKey:first&limit=1").json()
    assert body["total"] == 1 and body["total_all"] == 2 and body["counts"] == {"credential": 1}
    assert body["facets"] == {"provider": ["gcp"], "object_kind": ["credential"], "purpose": ["issuer_inventory"]}


def test_an_unknown_entity_run_or_connection_is_a_not_found(client):
    missing = str(uuid.uuid4())
    assert client.get(f"/api/v2/coverage/inventory/{missing}").status_code == 404
    assert client.get(f"/api/v2/coverage/runs/{missing}").status_code == 404
    assert client.get(f"/api/v2/coverage/connections/{missing}").status_code == 404


def test_a_native_export_needs_an_adapter_that_offers_one(client):
    created = create(client, GCP)
    headers = {"X-Cremore-Collector-Token": created["collector_token"]}
    run, _accepted = submit(client, created, [record()])
    client.post(f"/api/v2/coverage/collector/{created['id']}/runs/{run}/finish", headers=headers,
                json={"schema_version": 2, "batch_count": 1, "item_count": 1,
                      "status": "COMPLETE", "reasons": []})
    records = client.get(f"/api/v2/coverage/runs/{run}/export?format=records")
    assert records.status_code == 200 and records.json()["schema_version"] == 2
    native = client.get(f"/api/v2/coverage/runs/{run}/export?format=native")
    assert native.status_code == 200, native.text
    assert "snapshot" in native.json() or "snapshots" in native.json()
    assert client.get(f"/api/v2/coverage/runs/{run}/export?format=csv").status_code == 422


def test_a_comparison_refuses_two_runs_that_are_not_comparable(client):
    created = create(client, GCP)
    headers = {"X-Cremore-Collector-Token": created["collector_token"]}
    run, _ = submit(client, created, [record()])
    client.post(f"/api/v2/coverage/collector/{created['id']}/runs/{run}/finish", headers=headers,
                json={"schema_version": 2, "batch_count": 1, "item_count": 1,
                      "status": "COMPLETE", "reasons": []})
    assert client.get(f"/api/v2/coverage/runs/{run}/compare/{run}").status_code == 409
    other = create(client, {**GCP, "name": "Second GCP connection"})
    other_run, _ = submit(client, other, [record()])
    assert client.get(f"/api/v2/coverage/runs/{run}/compare/{other_run}").status_code == 409


def test_a_collector_token_cannot_run_an_identity_collection(client):
    # Its records would all be refused, and the empty run would still become the collection's latest.
    created = create(client, {
        "name": "Synthetic directory", "provider": "google_workspace", "origin": "https://admin.googleapis.com",
        "tenant": "acme.com", "tenant_confirmed": True, "scopes": [{"kind": "organization", "id": "acme.com"}],
        "capabilities": ["identity_status"], "auth_type": "private_key_jwt",
        "secret_refs": {"private_key": "vault://synthetic/key", "username": "vault://synthetic/key"}})
    headers = {"X-Cremore-Collector-Token": created["collector_token"]}
    config = client.get(f"/api/v2/coverage/collector/{created['id']}", headers=headers).json()
    started = client.post(f"/api/v2/coverage/collector/{created['id']}/runs", headers=headers,
        json={"revision": 1, "request_id": str(uuid.uuid4()), "contract": config["contract"]})
    assert started.status_code == 409 and started.json()["error"] == "IDENTITY_COLLECTION_IS_WORKER_ONLY"
    # Nor can it close the worker's own run half-way, which would make everyone not yet listed look gone.
    from cremore.coverage.metadata_store import MetadataStore

    run = MetadataStore(client.inner.app.state.repo).start(uuid.UUID(created["id"]), 1, str(uuid.uuid4()),
                                                           config["contract"])
    closed = client.post(f"/api/v2/coverage/collector/{created['id']}/runs/{run['id']}/finish", headers=headers,
                         json={"batch_count": 0, "item_count": 0, "status": "COMPLETE"})
    assert closed.status_code == 409 and closed.json()["error"] == "IDENTITY_COLLECTION_IS_WORKER_ONLY"


def test_an_invalid_v2_request_body_keeps_the_coverage_error_shape(client):
    created = create(client)
    response = client.post(f"/api/v2/coverage/connections/{created['id']}/collect", json={"operations": "all"})
    assert response.status_code == 422
    assert response.json() == {"detail": "INVALID_COVERAGE_REQUEST",
                               "error": "INVALID_COVERAGE_REQUEST"}


# -- linking a finding to the managed objects it could be ----------------------


def gcp_identity(object_id, kind="credential", origin="https://googleapis.com"):
    return {"provider": "gcp", "origin": origin, "tenant": "", "tenant_confirmed": False,
            "kind": kind, "object_id": object_id}


def _base(operation, resource_id):
    base = record(operation=operation)
    return {"purpose": base["purpose"], "scope": base["scope"], "facts": [], "omissions": [],
            "provenance": {**base["provenance"], "resource_id": resource_id}}


def observation(object_id, *, kind="credential", origin="https://googleapis.com",
                operation="gcp.service_account_keys"):
    return {**_base(operation, f"projects/{PROJECT}/keys/{object_id.rsplit(':', 1)[-1]}"),
            "record_type": "entity_observation",
            "identity": gcp_identity(object_id, kind, origin), "provider_state": "ENABLED",
            "normalized_state": "ACTIVE", "state_basis": "PROVIDER_REPORTED"}


def used(object_id, *, origin="https://googleapis.com", count=1, confidence="EXACT"):
    """GCP records use as a relation drawn from its logs, not as an audit event."""
    return [{**_base("gcp.secret_access", f"projects/{PROJECT}/keys/{object_id}"),
             "record_type": "relation", "purpose": "usage",
             "subject": gcp_identity("apiKey:" + object_id, origin=origin),
             "target": gcp_identity(f"gcp_api:service{index}.googleapis.com", "resource", origin),
             "relation": "used", "match_basis": "AUDIT_REFERENCE", "confidence": confidence}
            for index in range(count)]


def collected(client, items, *, spec=None):
    created = create(client, spec or {**GCP, "capabilities": ["inventory", "vault_metadata", "relations"]})
    headers = {"X-Cremore-Collector-Token": created["collector_token"]}
    run, accepted = submit(client, created, [record(), *items])
    assert accepted.status_code == 200, accepted.text
    finished = client.post(f"/api/v2/coverage/collector/{created['id']}/runs/{run}/finish",
                           headers=headers,
                           json={"schema_version": 2, "batch_count": 1, "item_count": 1 + len(items),
                                 "status": "COMPLETE", "reasons": []})
    assert finished.status_code == 200, finished.text
    return created


def finding_for(client, credential_type, provider, *, metadata=None):
    import uuid as _uuid

    from cremore.domain.models import Credential, Exposure

    repo = client.inner.app.state.repo
    credential = repo.upsert_credential(Credential(
        fingerprint=_uuid.uuid4().hex * 2, credential_type=credential_type, provider=provider))
    exposure = repo.upsert_exposure(Exposure(
        credential_id=credential.id, source_type="github", resource_name="acme/app",
        location="deploy.env", severity="HIGH", status="OPEN", metadata=metadata or {}))
    return repo.upsert_finding(credential.id, exposure.id, "HIGH")


def test_a_managed_object_is_offered_as_a_candidate_and_never_as_a_match(client):
    collected(client, [observation("serviceAccountKey:svc@demo.iam.gserviceaccount.com:abc123"),
                       observation("serviceAccountKey:svc@demo.iam.gserviceaccount.com:def456")])
    finding = finding_for(client, "GCP_SERVICE_ACCOUNT", "gcp")
    body = client.get(f"/api/v2/coverage/findings/{finding.id}").json()
    assert body["schema_version"] == 2 and body["provider"] == "gcp"
    assert body["evidence"] == "CANDIDATE" and body["total"] == 2
    assert {item["object_id"] for item in body["items"]} == {
        "serviceAccountKey:svc@demo.iam.gserviceaccount.com:abc123",
        "serviceAccountKey:svc@demo.iam.gserviceaccount.com:def456"}
    # Two candidates for one credential: the operator must not read either as
    # the answer, so the reason for that is stated, not implied by the count.
    assert "NO_SHARED_MATCHING_EVIDENCE" in body["reasons"]
    assert all(item["verification"] == "NOT_PERFORMED" for item in body["items"])


@pytest.mark.parametrize("confidence,expected", [
    ("EXACT", 2), ("IDENTIFIER", 0), ("CANDIDATE", 0), ("UNKNOWN", 0),
])
def test_recorded_use_separates_a_live_candidate_from_an_untouched_one(client, confidence, expected):
    collected(client, [observation("apiKey:used", operation="gcp.api_keys"),
                       observation("apiKey:never", operation="gcp.api_keys"),
                       *used("used", count=2, confidence=confidence)])
    finding = finding_for(client, "GCP_API_KEY", "gcp")
    items = {row["object_id"]: row for row in
             client.get(f"/api/v2/coverage/findings/{finding.id}").json()["items"]}
    assert items["apiKey:used"]["usage_events"] == expected
    # Zero means no event was collected, never "this key was never used".
    assert items["apiKey:never"]["usage_events"] == 0


def test_an_empty_inventory_is_not_evidence_that_nothing_manages_the_credential(client):
    finding = finding_for(client, "GCP_API_KEY", "gcp")
    body = client.get(f"/api/v2/coverage/findings/{finding.id}").json()
    assert body["evidence"] == "NONE" and body["items"] == []
    assert "NO_MANAGED_OBJECT_COLLECTED" in body["reasons"]


def test_an_entra_client_secret_is_looked_for_in_the_entra_inventory(client):
    finding = finding_for(client, "AZURE_ENTRA_CLIENT_SECRET", "azure")
    body = client.get(f"/api/v2/coverage/findings/{finding.id}").json()
    assert body["provider"] == "azure_entra" and body["object_kind"] == "credential"
    assert "NO_MANAGED_OBJECT_COLLECTED" in body["reasons"]


def test_a_provider_with_no_managed_inventory_says_so_rather_than_showing_nothing(client):
    finding = finding_for(client, "STRIPE_SECRET_KEY", "stripe")
    body = client.get(f"/api/v2/coverage/findings/{finding.id}").json()
    assert body["provider"] == "" and body["evidence"] == "NONE"
    assert "PROVIDER_HAS_NO_MANAGED_INVENTORY" in body["reasons"]


def test_a_finding_that_does_not_exist_is_a_404_not_an_empty_candidate_list(client):
    assert client.get(f"/api/v2/coverage/findings/{uuid.uuid4()}").status_code == 404


def test_content_installation_never_filters_the_credential_issuer(client):
    collected(client, [observation("apiKey:cloud")])
    finding = finding_for(client, "GCP_API_KEY", "gcp",
                          metadata={"source_instance": "https://elsewhere.example.test"})
    body = client.get(f"/api/v2/coverage/findings/{finding.id}").json()
    # A GCP credential can be exposed in content hosted by any provider.
    assert body["origins"] == []
    assert body["total"] == 1 and body["items"][0]["object_id"] == "apiKey:cloud"
    same = finding_for(client, "GCP_API_KEY", "gcp",
                       metadata={"source_instance": "https://googleapis.com"})
    assert client.get(f"/api/v2/coverage/findings/{same.id}").json()["total"] == 1


def test_an_exposure_in_two_installations_narrows_to_neither(client):
    from cremore.domain.models import Exposure

    collected(client, [observation("apiKey:cloud")])
    finding = finding_for(client, "GCP_API_KEY", "gcp",
                          metadata={"source_instance": "https://googleapis.com"})
    repo = client.inner.app.state.repo
    repo.upsert_exposure(Exposure(credential_id=finding.credential_id, source_type="gitlab",
                                  resource_name="group/app", location="ci.env", severity="HIGH",
                                  status="OPEN", metadata={"source_instance": "https://other.example.test"}))
    body = client.get(f"/api/v2/coverage/findings/{finding.id}").json()
    assert body["origins"] == []
    assert "ISSUER_INSTALLATION_NOT_INFERRED_FROM_CONTENT" in body["reasons"]
    # Narrowing to one would have dropped the other installation's objects.
    assert body["total"] == 1


def test_a_runner_token_is_looked_for_among_runners_not_among_issued_tokens(client):
    # A GitLab runner token is not a personal access token; looking for it in
    # the issued-credential list would compare it against the wrong objects.
    runner = finding_for(client, "GITLAB_RUNNER_TOKEN", "gitlab")
    assert client.get(f"/api/v2/coverage/findings/{runner.id}").json()["object_kind"] == "runner"
    pat = finding_for(client, "GITLAB_PERSONAL_ACCESS_TOKEN", "gitlab")
    assert client.get(f"/api/v2/coverage/findings/{pat.id}").json()["object_kind"] == "credential"


def test_gcp_json_identity_links_from_other_content_but_is_not_value_or_authentication_proof(client):
    import json

    from cremore.detection import ResourceRef
    from cremore.detection.engine import Engine, EngineConfig
    from cremore.scanning.orchestrator import Orchestrator
    email, key_id = "app@demo.iam.gserviceaccount.com", "a" * 40
    identity = f"serviceAccountKey:{email}:{key_id}"
    collected(client, [observation(identity)])
    repo = client.inner.app.state.repo
    engine = Engine(EngineConfig(fingerprint_key=b"k" * 32))
    pem = "-----BEGIN PRIVATE KEY-----\n" + "abCDefGHIjklMNopqRsTUVxyz0123456789+/=" * 5 + "\n-----END PRIVATE KEY-----"
    raw = json.dumps({"type": "service_account", "client_email": email, "private_key_id": key_id, "private_key": pem}).encode()
    Orchestrator(repo, engine=engine, config=engine.config).scan_resource(raw,
        ResourceRef(source_type="notion", resource="fixture"), verify=False)
    finding = next(item for item in repo.list_findings() if repo.get_credential(item.credential_id).credential_type == "GCP_SERVICE_ACCOUNT")
    body = client.get(f"/api/v2/coverage/findings/{finding.id}").json()
    assert body["identifier_match_count"] == 1 and body["value_match_count"] == 0
    assert body["items"][0]["evidence"] == "IDENTIFIER"
    assert body["items"][0]["verification"] == "NOT_PERFORMED"
    public = client.get(f"/api/v1/findings/{finding.id}")
    assert public.status_code == 200
    assert "issuer_comparison" not in public.text and pem not in public.text


GCP_EMAIL = "app@demo.iam.gserviceaccount.com"
GCP_KEY = f"serviceAccountKey:{GCP_EMAIL}:{'a' * 40}"


def gcp_key_json(key_id):
    pem = "-----BEGIN PRIVATE KEY-----\n" + "abCDefGHIjklMNopqRsTUVxyz0123456789+/=" * 5 + "\n-----END PRIVATE KEY-----"
    return {"type": "service_account", "client_email": GCP_EMAIL, "private_key_id": key_id, "private_key": pem}


def issued_gcp_key_row(client, vault_value):
    import json
    from datetime import UTC, datetime

    from cremore.coverage.hasher import hash_value
    from cremore.coverage.models import Batch, ConnectionSpec, Contract, Finish
    from cremore.coverage.store import CoverageStore
    issued = observation(GCP_KEY)
    collected(client, [{**issued, "provenance": {**issued["provenance"], "observed_at": datetime.now(UTC).isoformat()}}])
    orchestrator = client.inner.app.state.orchestrator
    store = CoverageStore(client.inner.app.state.repo)
    owner, _ = store.create(ConnectionSpec(name="Vault", provider="aws_secrets_manager",
                                           account_id="123456789012", regions=["us-east-1"]), "admin")
    run = store.start(owner["id"], owner["revision"], str(uuid.uuid4()), Contract(
        engine_digest=orchestrator.engine.detection_digest, policy_digest=orchestrator.coverage_policy_digest).model_dump())
    items = hash_value(orchestrator.engine, json.dumps(vault_value).encode(), {
        "reference": "arn:aws:secretsmanager:us-east-1:123456789012:secret:app-Ab12Cd",
        "account_id": "123456789012", "region": "us-east-1"}, max_bytes=65536)
    store.append(owner["id"], run["id"], Batch(index=0, items=items))
    store.finish(owner["id"], run["id"], Finish(batch_count=1, item_count=len(items), status="COMPLETE"))
    revision = client.get("/api/v1/coverage").json()["scope_revision"]
    assert client.put("/api/v1/coverage/scope", json={"revision": revision, "confirmed": True}).status_code == 200
    return next(row for row in client.get("/api/v1/coverage").json()["items"] if row["identifier"] == GCP_KEY)


@pytest.mark.parametrize("vault_value,state,reason", [
    (gcp_key_json("a" * 40), "IDENTIFIER_ONLY", None),
    (gcp_key_json("b" * 40), "IDENTIFIER_NOT_OBSERVED", None),
    # One PEM reused under two key IDs: the vault may hold this key, so absence is unproven.
    ([gcp_key_json("a" * 40), gcp_key_json("b" * 40)], "UNKNOWN", "VAULT_SERVICE_ACCOUNT_KEY_UNIDENTIFIED"),
], ids=["stored", "absent", "ambiguous"])
def test_an_issued_gcp_key_is_compared_with_the_vault_by_key_id(client, vault_value, state, reason):
    row = issued_gcp_key_row(client, vault_value)
    assert row["state"] == state and row["match_basis"] == ("IDENTIFIER" if state == "IDENTIFIER_ONLY" else "NONE")
    assert "IDENTIFIER_COMPARISON_ONLY" in row["reasons"]
    assert reason is None or reason in row["reasons"]


# -- a provider's own events are not CreMore's audit log ----------------------


def provider_event(object_id, *, event_type="google.iam.admin.v1.CreateServiceAccountKey",
                   occurred_at="2026-09-20T00:00:00+00:00", event_id="log-1"):
    return {**_base("gcp.audit", f"projects/{PROJECT}/keys/{object_id}"),
            "record_type": "provider_event", "purpose": "usage",
            "event_id": event_id, "event_type": event_type, "occurred_at": occurred_at,
            "subject": gcp_identity("apiKey:" + object_id),
            "match_basis": "AUDIT_REFERENCE", "confidence": "IDENTIFIER"}


def project(client, spec, items):
    """Write records through the real projection, skipping provider submission
    rules: the ordering and subject resolution are what is under test here."""
    import uuid as _uuid

    from cremore.coverage.metadata_models import (
        MetadataBatch,
        MetadataConnectionSpec,
        metadata_contract,
    )
    from cremore.coverage.metadata_store import MetadataStore, project_batch

    store = MetadataStore(client.inner.app.state.repo)
    model = MetadataConnectionSpec.model_validate(spec)
    row, token = store.create(model, "synthetic-admin")
    run = store.start(row["id"], row["revision"], str(_uuid.uuid4()),
                      metadata_contract(model).model_dump(), token=token)
    batch = MetadataBatch.model_validate({"schema_version": 2, "index": 0, "items": items})
    with store.transaction() as conn:
        project_batch(store, conn, store._get(conn, "runs", run["id"]), batch)
    return store


def test_events_are_newest_first_with_their_subject_and_how_it_was_matched(client):
    store = project(client, GCP, [
        provider_event("older", event_id="log-1", occurred_at="2026-09-18T00:00:00+00:00"),
        provider_event("newer", event_id="log-2", occurred_at="2026-09-20T00:00:00+00:00",
                       event_type="google.iam.admin.v1.DeleteServiceAccountKey"),
    ])
    page = store.provider_events()
    assert page["total"] == 2
    assert [item["event_id"] for item in page["items"]] == ["log-2", "log-1"]
    first = page["items"][0]
    assert first["provider"] == "gcp"
    assert first["subject"]["object_id"] == "apiKey:newer"
    assert first["subject"]["object_kind"] == "credential"
    assert first["target"] is None
    # An event matched by candidate is not an event about that object, so how
    # the provider tied them together travels with the row.
    assert first["match_basis"] == "AUDIT_REFERENCE" and first["confidence"] == "IDENTIFIER"
    assert page["boundary"] == "PROVIDER_REPORTED_NOT_CREMORE_ACTIONS"
    # Filters are offered from the kinds actually present, never from a fixed list.
    assert page["event_types"] == ["google.iam.admin.v1.CreateServiceAccountKey",
                                   "google.iam.admin.v1.DeleteServiceAccountKey"]
    narrowed = store.provider_events(event_type="google.iam.admin.v1.DeleteServiceAccountKey")
    assert [item["event_id"] for item in narrowed["items"]] == ["log-2"]
    response = client.get("/api/v2/coverage/events?event_type=google.iam.admin.v1.DeleteServiceAccountKey&limit=1").json()
    assert response["facets"] == {"provider": ["gcp"], "event_type": page["event_types"]}
    assert response["event_types"] == ["google.iam.admin.v1.DeleteServiceAccountKey"]
    assert store.provider_events(provider="github")["total"] == 0
    assert store.provider_events(offset=1)["items"][0]["event_id"] == "log-1"


def test_an_empty_event_list_never_reads_as_a_provider_that_did_nothing(client):
    body = client.get("/api/v2/coverage/events").json()
    assert body["items"] == [] and body["total"] == 0 and body["event_types"] == []
    assert body["facets"] == {"provider": [], "event_type": []}
    # The boundary is part of the answer, not a caption the screen invents.
    assert body["boundary"] == "PROVIDER_REPORTED_NOT_CREMORE_ACTIONS"


def test_the_events_route_validates_its_paging_and_provider(client):
    assert client.get("/api/v2/coverage/events?limit=0").status_code == 422
    assert client.get("/api/v2/coverage/events?limit=501").status_code == 422
    assert client.get("/api/v2/coverage/events?provider=nowhere").status_code == 422
    assert client.get("/api/v2/coverage/events?provider=github").status_code == 200


# -- setup progress for a connection that only collects metadata --------------


def test_a_metadata_connection_has_no_content_steps_to_finish(client):
    created = create(client, GCP)
    body = client.get(f"/api/v2/coverage/connections/{created['id']}/setup").json()
    assert body["schema_version"] == 2
    setup = body["onboarding"]
    assert setup["management_only"] is True
    statuses = {row["code"]: row["status"] for row in setup["steps"]}
    # No catalog, no target selection, no approved scan scope exist here, so
    # they are not applicable rather than unfinished.
    assert [statuses[code] for code in ("CATALOG", "SELECTION", "SCOPE_SAVED")] == ["NOT_APPLICABLE"] * 3
    assert statuses["PURPOSE"] == "COMPLETE" and statuses["ENVIRONMENT"] == "COMPLETE"
    # This path has no read-only identity call, so the screen must not offer one.
    assert setup["probe"] == "NOT_AVAILABLE" and setup["investigation"] == "NOT_AVAILABLE"


def test_a_registered_connection_that_never_collected_is_not_authenticated(client):
    created = create(client, GCP)
    setup = client.get(f"/api/v2/coverage/connections/{created['id']}/setup").json()["onboarding"]
    step = next(row for row in setup["steps"] if row["code"] == "AUTHENTICATION")
    # Registering a connection proves nothing about whether the provider
    # answers it; only a run that finished does.
    assert step["status"] == "PENDING" and "recent_run" not in setup
    assert setup["stage"] == "AUTHENTICATION" and setup["status"] == "IN_PROGRESS"


def test_a_finished_collection_is_what_proves_the_provider_answered(client):
    created = create(client, GCP)
    headers = {"X-Cremore-Collector-Token": created["collector_token"]}
    run, accepted = submit(client, created, [record()])
    assert accepted.status_code == 200, accepted.text
    client.post(f"/api/v2/coverage/collector/{created['id']}/runs/{run}/finish", headers=headers,
                json={"schema_version": 2, "batch_count": 1, "item_count": 1,
                      "status": "COMPLETE", "reasons": []})
    setup = client.get(f"/api/v2/coverage/connections/{created['id']}/setup").json()["onboarding"]
    step = next(row for row in setup["steps"] if row["code"] == "AUTHENTICATION")
    assert step["status"] == "COMPLETE" and step["observed_at"]
    assert setup["recent_run"]["status"] == "COMPLETED"
    assert "recent_failure" not in setup


def test_a_metadata_checkpoint_cannot_choose_a_content_execution(client):
    created = create(client, GCP)
    setup = client.get(f"/api/v2/coverage/connections/{created['id']}/setup").json()["onboarding"]
    path = f"/api/v2/coverage/connections/{created['id']}/setup"
    body = {"expected_version": 0, "evidence_digest": setup["evidence_digest"]}
    assert client.post(path, json={**body, "choice": "RUN_NOW"}).status_code == 409
    saved = client.post(path, json={**body, "choice": "MANAGEMENT_ONLY"})
    assert saved.status_code == 200, saved.text
    stored = saved.json()["onboarding"]
    assert stored["choice"] == "MANAGEMENT_ONLY" and stored["version"] == 1
    assert stored["checkpoint_current"] is True
    # A second save against the same version is a conflict, not an overwrite.
    assert client.post(path, json={**body, "choice": "MANAGEMENT_ONLY"}).status_code == 409


def test_setup_progress_is_readable_by_any_signed_in_role_but_saved_by_an_admin(client):
    created = create(client, GCP)
    assert client.get(f"/api/v2/coverage/connections/{created['id']}/setup").status_code == 200
    unsigned = client.inner.post(f"/api/v2/coverage/connections/{created['id']}/setup",
                                 json={"expected_version": 0, "evidence_digest": "a" * 64,
                                       "choice": "DRAFT"})
    assert unsigned.status_code in (401, 403)


def test_setup_progress_of_a_schema_1_connection_is_not_served_here(client):
    from cremore.coverage.store import CoverageStore

    row, _token = CoverageStore(client.inner.app.state.repo).create(
        __import__("cremore.coverage.models", fromlist=["ConnectionSpec"]).ConnectionSpec.model_validate(AWS),
        "synthetic-admin")
    assert client.get(f"/api/v2/coverage/connections/{row['id']}/setup").status_code == 409


def test_metadata_collection_pause_resume_and_stop_routes():
    repo = InMemoryRepository()
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32))
    with TestClient(app) as raw:
        client = Signed(raw)
        created = create(client)
        base = f"/api/v2/coverage/connections/{created['id']}"
        idle = client.post(base + "/collect/pause")
        assert idle.status_code == 409 and idle.json()["error"] == "METADATA_COLLECTION_NOT_RUNNING"
        job_id = client.post(base + "/collect").json()["job_id"]
        paused = client.post(base + "/collect/pause")
        assert paused.status_code == 200 and paused.json() == {"job_id": job_id, "status": "QUEUED", "paused": True}
        assert client.get(base).json()["collection_paused"] is True
        assert client.post(base + "/collect/resume").json()["paused"] is False
        assert client.get(base).json()["collection_paused"] is False
        client.post(base + "/collect/pause")
        # A queued collection is withdrawn at once; a running one stops at its next request.
        stopped = client.post(base + "/collect/stop")
        assert stopped.status_code == 200 and stopped.json()["status"] == "CANCELLED"
        view = client.get(base).json()
        assert view["collection_paused"] is False and view["latest_job"]["status"] == "CANCELLED"
        assert client.post(base + "/collect/stop").status_code == 409
        assert client.inner.post(base + "/collect/pause").status_code == 401
        trail = sorted(event.event_type for event in repo.finding_events.values()
                       if event.event_type.startswith("METADATA_COLLECTION_") and event.event_type != "METADATA_COLLECTION_REQUESTED")
        assert trail == ["METADATA_COLLECTION_PAUSED", "METADATA_COLLECTION_PAUSED", "METADATA_COLLECTION_RESUMED",
                         "METADATA_COLLECTION_STOP_REQUESTED"]


def test_a_people_directory_is_for_analysts_on_every_v2_read(issuer):
    """A people-directory collection (cremore.identity.idp) says who is employed, since when, and -- keeping profiles --
    their name, email, department and title. GET /api/v1/people and the departed-owner lists are Analyst-only; so is
    every v2 read of such a collection: below Analyst its people are not listed, searched or shown, nor its runs read."""
    from cremore_okta_provider.tests import test_identity as okta

    from cremore.api.conftest import GROUPS, oidc_settings
    from cremore.api.metadata_coverage import public_metadata
    from cremore.coverage.metadata_store import MetadataStore
    from cremore.identity.leavers_test import save
    from cremore.identity.people_test import okta_records, okta_row

    repo = InMemoryRepository()
    client = TestClient(create_app(repo=repo, settings=oidc_settings(), oidc_http_client=issuer))
    store = MetadataStore(repo)
    spec = okta.spec(options={"page_size": 200, "keep_profiles": True})
    owner = save(store, spec, okta_records(spec, okta_row("00uada000001", "ACTIVE", "ada@acme.test", "Ada", "Lovelace", "Platform")))
    run = store.connection_runs(owner["id"], limit=1)["items"][0]["id"]
    [entity] = store.inventory(purpose="identity_status")["items"]

    def as_role(role):
        return {"Authorization": "Bearer " + issuer.mint(sub=role, groups=(GROUPS[role],))}

    viewer, analyst = as_role("viewer"), as_role("analyst")
    # Manual directory refresh reuses the analyst collection route and active-job protection.
    collect_path = f"/api/v2/coverage/connections/{owner['id']}/collect"
    assert client.post(collect_path, headers=viewer).status_code == 403
    refreshed = client.post(collect_path, headers=analyst)
    assert refreshed.status_code == 202 and refreshed.json()["status"] == "QUEUED"
    assert client.post(collect_path, headers=analyst).json()["job_id"] == refreshed.json()["job_id"]
    # Not listed, counted or offered as a facet below Analyst.
    listed = client.get("/api/v2/coverage/inventory", headers=viewer).json()
    assert listed["items"] == [] and listed["total_all"] == 0 and "identity_status" not in listed["facets"]["purpose"]
    assert client.get("/api/v2/coverage/inventory?purpose=identity_status", headers=viewer).json()["total"] == 0
    # Not searched.
    found = client.get("/api/v1/search?q=00uada", headers=viewer).json()
    assert next(group for group in found["groups"] if group["kind"] == "managed_object")["total"] == 0
    # Not shown, nor its runs read, exported or compared.
    # An entity id can be computed from what it names: below Analyst a person reads as absent, not as refused.
    assert client.get(f"/api/v2/coverage/inventory/{entity['id']}", headers=viewer).status_code == 404
    for path in (f"/api/v2/coverage/runs/{run}",
                 f"/api/v2/coverage/runs/{run}/export?format=records", f"/api/v2/coverage/runs/{run}/export?format=native",
                 f"/api/v2/coverage/runs/{run}/compare/{run}"):
        assert client.get(path, headers=viewer).status_code == 403, path
    # An Analyst reads all of it, the profile included.
    for path in ("/api/v2/coverage/inventory?purpose=identity_status", f"/api/v2/coverage/inventory/{entity['id']}",
                 f"/api/v2/coverage/runs/{run}", f"/api/v2/coverage/runs/{run}/export?format=records"):
        full = client.get(path, headers=analyst)
        assert full.status_code == 200 and "Lovelace" in full.text and "ada@acme.test" in full.text, path
    found = client.get("/api/v1/search?q=00uada", headers=analyst).json()
    assert next(group for group in found["groups"] if group["kind"] == "managed_object")["total"] == 1
    # A people-directory record that reaches the public shape for anyone else keeps no facts; others are untouched.
    shown = public_metadata(store.entity_detail(entity["id"]))
    assert shown["current_record"]["body"]["facts"] == [] and shown["entity"]["summary"]["facts"] == []
    other = {"purpose": "issuer_inventory", "facts": [{"name": "name", "state": "PRESENT", "value": "deploy-token"}]}
    assert public_metadata(other) == other
    # The stored record keeps the profile: this is a view, not a deletion.
    stored = store.entity_detail(entity["id"])
    assert any(fact["name"] == "email" for fact in stored["current_record"]["body"]["facts"])


def test_a_people_directorys_events_are_for_analysts(issuer):
    from datetime import UTC, datetime

    from cremore.api.conftest import GROUPS, oidc_settings
    from cremore.coverage.metadata_store import MetadataStore

    now = datetime(2026, 9, 30, tzinfo=UTC)  # a fixed moment for both events

    repo = InMemoryRepository()
    client = TestClient(create_app(repo=repo, settings=oidc_settings(), oidc_http_client=issuer))
    store = MetadataStore(repo)
    # Two provider events, one a people-directory change (who left, and when), one an issuer's.
    base = {"run_id": uuid.uuid4(), "connection_id": uuid.uuid4(), "revision": 1, "batch_index": 0, "record_type": "provider_event",
            "entity_id": None, "subject_id": None, "target_id": None, "scope_key": "s", "operation": "op", "event_key": None}
    for index, (provider, purpose) in enumerate((("okta", "identity_status"), ("github", "usage"))):
        rid = uuid.uuid4()
        store.memory["records"][rid] = {**base, "id": rid, "item_index": index, "provider": provider, "purpose": purpose,
                                        "observed_at": now, "effective_at": now,
                                        "body": {"event_type": "user.deleted" if purpose == "identity_status" else "token.used"}}

    def as_role(role):
        return {"Authorization": "Bearer " + issuer.mint(sub=role, groups=(GROUPS[role],))}

    viewer = client.get("/api/v2/coverage/events", headers=as_role("viewer")).json()
    assert [item["provider"] for item in viewer["items"]] == ["github"] and viewer["facets"]["provider"] == ["github"]
    analyst = client.get("/api/v2/coverage/events", headers=as_role("analyst")).json()
    assert sorted(item["provider"] for item in analyst["items"]) == ["github", "okta"]
