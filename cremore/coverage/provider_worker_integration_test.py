"""Provider API fixtures through the leased worker, both stores and public reads."""

from __future__ import annotations

import json
import uuid
from functools import partial
from types import SimpleNamespace

import httpx
import pytest
from cremore_azure_provider.metadata import adapter as azure_adapter
from cremore_azure_provider.metadata.azure_key_vault_test import ORIGIN as VAULT_ORIGIN
from cremore_azure_provider.metadata.azure_key_vault_test import secret
from cremore_azure_provider.metadata.azure_key_vault_test import spec as azure_spec
from cremore_azure_provider.metadata.transport import ApiError
from cremore_azure_provider.metadata.values_test import VALUE, ValueVault, configured
from cremore_notion_provider.metadata import API_VERSION
from cremore_notion_provider.metadata import adapter as notion_adapter
from cremore_notion_provider.metadata.tests.test_adapter import (
    BEARER,
    TOKEN_ID,
    WORKSPACE,
    client_for,
    mcp,
    pat,
    payload,
)
from cremore_notion_provider.metadata.tests.test_adapter import spec as notion_spec
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.config import Settings
from cremore.coverage.metadata_job_test import repo as repo  # noqa: PLC0414
from cremore.coverage.metadata_store import MetadataStore
from cremore.coverage.providers.facts import unpack_facts
from cremore.db.task_store import TaskStore
from cremore.detection import ResourceRef
from cremore.worker import JobWorker

API_TOKEN = "offline-provider-worker-test-" + "a" * 32
RAW_MARKER = "SYNTHETIC_PROVIDER_VALUE_MUST_NOT_SURVIVE"


@pytest.fixture
def stack(repo):
    settings = Settings(AUTH_MODE="local", API_TOKEN=API_TOKEN, FINGERPRINT_KEY="ab" * 32)
    app = create_app(repo=repo, settings=settings)
    references = []

    def resolve(reference):
        references.append(reference)
        assert reference == "vault://notion/admin"
        return {"token": BEARER}

    worker = JobWorker(repo, orchestrator=app.state.orchestrator,
                       metadata_secret_resolver=SimpleNamespace(resolve=resolve))
    with TestClient(app, headers={"Authorization": "Bearer " + API_TOKEN}) as client:
        yield SimpleNamespace(repo=repo, client=client, worker=worker,
                              orchestrator=app.state.orchestrator, references=references)


@pytest.fixture
def azure_wire(monkeypatch):
    collect = azure_adapter.collect_pages

    def use(responses):
        vault = ValueVault(responses)
        monkeypatch.setattr(azure_adapter, "collect_pages", partial(collect, transport=vault))
        return vault

    return use


def create(stack, spec):
    """A collection as a provider connection's step 4 creates it (cremore/onboarding)."""
    from cremore.onboarding.fixtures_test import collection

    row, _token = collection(stack.repo, spec.model_dump())
    return str(row["id"])


def collect(stack, connection_id):
    response = stack.client.post(f"/api/v2/coverage/connections/{connection_id}/collect")
    assert response.status_code == 202, response.text
    job_id = uuid.UUID(response.json()["job_id"])
    assert stack.worker.process_next()
    job = stack.repo.get_job(job_id)
    runs = MetadataStore(stack.repo).connection_runs(uuid.UUID(connection_id))
    assert runs["items"], job.error
    return job, MetadataStore(stack.repo).run_detail(runs["items"][0]["id"], limit=1)["run"]


def expose(stack, value=VALUE):
    stack.orchestrator.scan_resource(
        value.encode(), ResourceRef(source_type="github", resource="synthetic/repository",
                                    location="fixture.env"), verify=False,
    )
    findings = stack.repo.list_findings()
    assert len(findings) == 1
    exposure = stack.repo.exposures_for_credential(findings[0].credential_id)[0]
    assert exposure.metadata["verification_state"] == "not_attempted"
    return findings[0]


def public_views(stack, connection_id, run_id):
    paths = [
        "/api/v2/coverage/connections",
        f"/api/v2/coverage/connections/{connection_id}",
        f"/api/v2/coverage/inventory?connection_id={connection_id}",
        f"/api/v2/coverage/runs/{run_id}",
        f"/api/v2/coverage/runs/{run_id}/export",
        f"/api/v2/coverage/runs/{run_id}/export?format=native",
    ]
    result = []
    for path in paths:
        response = stack.client.get(path)
        assert response.status_code == 200, response.text
        result.append(response.text)
    return "\n".join(result)


def coverage(stack, finding):
    response = stack.client.get(f"/api/v1/findings/{finding.id}/coverage")
    assert response.status_code == 200, response.text
    assert VALUE not in response.text
    assert '"fingerprint":' not in response.text and '"provider_digest":' not in response.text
    return response.json()


def test_notion_api_spec_worker_pagination_and_public_inventory_keep_safe_metadata(stack, monkeypatch):
    spec = notion_spec(options={"sources": ["personal_access_tokens", "mcp_client_connections"],
                                "requests_per_second": 100.0})
    cid = create(stack, spec)
    second_id = "00000000-0000-4000-8000-000000000011"
    first = pat()
    first["creator"]["profile_photo_url"] = "https://images.example.test/" + RAW_MARKER
    requests = []
    responses = [payload(first, cursor="next-page"), payload(pat(id=second_id, status="revoked")), payload(mcp())]
    with client_for(responses, requests) as client:
        monkeypatch.setattr(notion_adapter, "collect_pages", partial(
            notion_adapter.collect_pages, client=client, sleep=lambda _seconds: None,
        ))
        job, run = collect(stack, cid)
    assert job.status == "SUCCEEDED", job.error
    assert run["status"] == "COMPLETE"
    assert stack.references == ["vault://notion/admin"]
    assert len(requests) == 3 and all(request.method == "GET" for request in requests)
    assert all(request.headers["Notion-Version"] == API_VERSION for request in requests)
    assert requests[1].url.params["cursor"] == "next-page"
    assert requests[2].url.params["workspace_ids"] == WORKSPACE
    stored = list(MetadataStore(stack.repo).iter_records(run["id"]))
    entities = [row for row in stored if row["record_type"] == "entity_observation"]
    assert {row["identity"]["object_id"] for row in entities if row["identity"]["kind"] == "credential"} == {
        f"pat:{WORKSPACE}:{TOKEN_ID}", f"pat:{WORKSPACE}:{second_id}"}
    assert {row["identity"]["kind"] for row in entities} == {"credential", "installation"}
    assert all(row["scope"] == {"kind": "workspace", "id": WORKSPACE} for row in entities)
    assert all(row["value_match"] is None for row in entities)
    assert run["contract"]["principal_verified"] is False
    assert run["contract"]["principal_id"] is None
    inventory = stack.client.get("/api/v2/coverage/inventory", params={"connection_id": cid}).json()
    assert inventory["total"] == 3
    assert stack.repo.list_findings() == []
    outputs = public_views(stack, cid, run["id"])
    outputs += json.dumps(stored, default=str) + json.dumps(job.payload, default=str)
    outputs += json.dumps(TaskStore(stack.repo).list_for_run(job.id), default=str)
    assert BEARER not in outputs and RAW_MARKER not in outputs
    task = TaskStore(stack.repo).list_for_run(job.id)[0]
    assert task["status"] == "SUCCEEDED" and task["result"]["source_reports_total"] == 2


def test_notion_unexpected_secret_fields_are_omitted_and_make_worker_collection_partial(stack, monkeypatch):
    cid = create(stack, notion_spec())
    requests = []
    with client_for([payload(pat(access_token=RAW_MARKER, private_key=RAW_MARKER))], requests) as client:
        monkeypatch.setattr(notion_adapter, "collect_pages", partial(
            notion_adapter.collect_pages, client=client, sleep=lambda _seconds: None,
        ))
        job, run = collect(stack, cid)
    assert job.status == "SUCCEEDED", job.error
    assert run["status"] == "PARTIAL"
    stored = list(MetadataStore(stack.repo).iter_records(run["id"]))
    entity = next(row for row in stored if row["record_type"] == "entity_observation")
    assert entity["omissions"] and entity["value_match"] is None
    assert RAW_MARKER not in json.dumps(stored) + public_views(stack, cid, run["id"])


def test_notion_permission_failure_keeps_prior_metadata_without_claiming_current_collection(stack, monkeypatch):
    cid = create(stack, notion_spec())
    requests = []
    collect_pages = notion_adapter.collect_pages
    with client_for([payload(pat()), httpx.Response(403, json={"message": RAW_MARKER})], requests) as client:
        monkeypatch.setattr(notion_adapter, "collect_pages", partial(
            collect_pages, client=client, sleep=lambda _seconds: None,
        ))
        _, first = collect(stack, cid)
        job, failed = collect(stack, cid)
    assert first["status"] == "COMPLETE" and failed["status"] == "FAILED"
    store = MetadataStore(stack.repo)
    assert store.connection_runs(uuid.UUID(cid))["total"] == 2
    assert store.inventory(connection_id=uuid.UUID(cid))["total"] == 1
    original = list(store.iter_records(first["id"]))
    assert any(row.get("identity", {}).get("object_id") == f"pat:{WORKSPACE}:{TOKEN_ID}" for row in original)
    assert failed["contract"]["principal_verified"] is False
    outputs = public_views(stack, cid, failed["id"])
    outputs += json.dumps(TaskStore(stack.repo).list_for_run(job.id), default=str)
    assert RAW_MARKER not in outputs and BEARER not in outputs


def test_azure_default_worker_path_stays_metadata_only_and_cannot_claim_value_match(stack, azure_wire):
    finding = expose(stack)
    cid = create(stack, azure_spec())
    vault = azure_wire({"/secrets": {"value": [secret()]}})
    job, run = collect(stack, cid)
    assert job.status == "SUCCEEDED", job.error
    assert run["status"] == "COMPLETE"
    assert [path for path, _ in vault.calls] == ["/secrets"]
    records = list(MetadataStore(stack.repo).iter_records(run["id"]))
    assert all(row.get("value_match") is None for row in records)
    assert coverage(stack, finding)["item"]["state"] == "UNKNOWN"
    assert coverage(stack, finding)["item"]["locations"] == []


def test_azure_opt_in_worker_values_match_exposure_without_saving_or_returning_plaintext(stack, azure_wire):
    finding = expose(stack)
    cid = create(stack, configured())
    vault = azure_wire({"/secrets": {"value": [secret()]},
                        "/secrets/db-password": {**secret(version="a1"), "value": VALUE}})
    job, run = collect(stack, cid)
    assert job.status == "SUCCEEDED", job.error
    assert run["status"] == "COMPLETE"
    assert [path for path, _ in vault.calls] == ["/secrets", "/secrets/db-password"]
    assert run["contract"]["principal_verified"] is False
    records = list(MetadataStore(stack.repo).iter_records(run["id"]))
    matched = next(row["value_match"] for row in records if row.get("value_match"))
    credential = stack.repo.get_credential(finding.credential_id)
    assert matched["evidence"] == "VALUE" and matched["fingerprint"] == credential.fingerprint
    assert matched["version"] == "a1" and matched["version_state"] == "CURRENT"
    assert matched["provider_digest"]
    item = coverage(stack, finding)["item"]
    assert item["state"] == "MATCHED" and item["match_basis"] == "VALUE_FINGERPRINT"
    assert len(item["locations"]) == 1
    assert item["locations"][0]["provider"] == "azure_key_vault"
    assert item["locations"][0]["reference"] == VAULT_ORIGIN + "/secrets/db-password/a1"
    report = stack.client.get("/api/v1/coverage").json()
    assert report["summary"]["matched"] == report["summary"]["exposed"] == 1
    access = next(row for row in records if row["provenance"]["operation"] == "azure.key_vault.value_access"
                  and row["record_type"] == "operation_report")
    assert access["value_access"] == "COMPLETE"
    outputs = public_views(stack, cid, run["id"])
    assert VALUE not in json.dumps(records) + json.dumps(job.payload, default=str) + outputs
    assert matched["provider_digest"] not in outputs and '"provider_digest"' not in outputs
    assert len(stack.repo.list_findings()) == 1  # Vault collection itself creates no exposure.


def test_arm_worker_hands_discovered_sas_to_the_offline_signer_check(stack, monkeypatch):
    from cremore_azure_provider.arm import adapter as arm_adapter
    from cremore_azure_provider.arm import arm_test as arm

    _, encoded, signed = arm.signed_sas(arm.VALUE, stack.orchestrator.config.fingerprint_key)
    stack.orchestrator.scan_resource(
        ("https://acmeprod.blob.core.windows.net/?sv=2022-11-02&ss=b&srt=o&sp=r&se=2027-01-01T00:00:00Z&sig="
         + encoded).encode(), ResourceRef(source_type="github", resource="synthetic/repository",
                                          location="fixture.env"), verify=False)
    [finding] = stack.repo.list_findings()
    assert stack.repo.get_credential(finding.credential_id).fingerprint == signed
    monkeypatch.setattr(arm_adapter, "collect_pages", partial(
        arm_adapter.collect_pages, transport=arm.Arm({arm.ACCOUNT + "/listKeys": arm.two_keys()})))
    cid = create(stack, arm.value_spec())
    job, run = collect(stack, cid)
    assert job.status == "SUCCEEDED", job.error
    response = stack.client.get(f"/api/v2/coverage/findings/{finding.id}")
    assert response.status_code == 200, response.text
    linked = {item["object_id"].rsplit("/", 1)[1]: (item["evidence"], item["match_basis"])
              for item in response.json()["items"]}
    assert linked == {"key1": ("VALUE", "SAS_SIGNATURE"), "key2": ("IDENTIFIER", "STORAGE_ACCOUNT_NAME")}
    outputs = public_views(stack, cid, run["id"]) + response.text + json.dumps(job.payload, default=str)
    for private in (signed, encoded, arm.VALUE):
        assert private not in outputs


def test_azure_repeated_value_failures_preserve_match_history_and_never_claim_absence(stack, azure_wire):
    finding = expose(stack)
    cid = create(stack, configured())
    azure_wire({"/secrets": {"value": [secret()]},
                "/secrets/db-password": {**secret(version="a1"), "value": VALUE}})
    _, first = collect(stack, cid)
    assert coverage(stack, finding)["item"]["state"] == "MATCHED"
    for _ in range(2):
        azure_wire({"/secrets": {"value": [secret()]},
                    "/secrets/db-password": ApiError("permission_denied")})
        job, failed = collect(stack, cid)
        assert job.status == "SUCCEEDED", job.error
        assert failed["status"] == "PARTIAL" and "PERMISSION_DENIED" in failed["reasons"]
        result = coverage(stack, finding)
        assert result["item"]["state"] == "UNKNOWN"
        assert result["item"]["locations"] == []
        assert any(row["run_id"] == str(first["id"]) for row in result["item"]["history"])
        assert "VAULT_VALUE_SCOPE_NOT_COMPLETE" in result["scope_reasons"]
        assert stack.client.get("/api/v1/coverage").json()["summary"]["no_vault_match"] == 0
    store = MetadataStore(stack.repo)
    assert store.connection_runs(uuid.UUID(cid))["total"] == 3
    records = list(store.iter_records(failed["id"]))
    unresolved = next(row["value_match"] for row in records if row.get("value_match"))
    assert unresolved["evidence"] == "UNRESOLVED" and unresolved["fingerprint"] is None
    assert VALUE not in json.dumps(records) + public_views(stack, cid, failed["id"])


def test_azure_explicit_old_version_is_history_not_a_current_value_match(stack, azure_wire):
    finding = expose(stack)
    cid = create(stack, configured(versions=True))
    different = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"
    azure_wire({"/secrets": {"value": [secret()]},
                "/secrets/db-password/versions": {"value": [secret(version="a0")]},
                "/secrets/db-password": {**secret(version="a1"), "value": different},
                "/secrets/db-password/a0": {**secret(version="a0"), "value": VALUE}})
    job, run = collect(stack, cid)
    assert job.status == "SUCCEEDED", job.error
    assert run["status"] == "COMPLETE"
    records = list(MetadataStore(stack.repo).iter_records(run["id"]))
    assert {(row["value_match"]["version"], row["value_match"]["version_state"])
            for row in records if row.get("value_match")} == {("a1", "CURRENT"), ("a0", "UNKNOWN")}
    result = coverage(stack, finding)
    assert result["item"]["state"] == "UNKNOWN" and not result["item"]["locations"]
    assert result["item"]["history"][0]["version"] == "a0"
    assert result["item"]["history"][0]["current_evidence"] is False
    assert all(unpack_facts(row["facts"]).get("last_rotated_at") is None for row in records)
