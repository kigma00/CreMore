"""A completed version list is not proof of a secret's current value."""

import base64
import hashlib
import uuid
from datetime import UTC, datetime

import httpx
import pytest
from cremore_gcp_provider.coverage import collect_gcp
from cremore_gcp_provider.metadata import adapter
from cremore_gcp_provider.metadata.tests.fake import PROJECT, SECRET, FakeTransport, drain, spec

from cremore.coverage.correlation import report, scope_revision
from cremore.coverage.coverage_test import GH, contract, engine, save
from cremore.coverage.gcp_integration_test import responses
from cremore.coverage.hasher import hash_value
from cremore.coverage.metadata_job_test import repo as repo  # noqa: PLC0414
from cremore.coverage.metadata_models import MetadataBatch, MetadataFinish, metadata_contract
from cremore.coverage.metadata_store import MetadataStore
from cremore.coverage.models import ConnectionSpec
from cremore.coverage.store import CoverageStore
from cremore.detection import ResourceRef
from cremore.scanning.orchestrator import Orchestrator


def schema2_collection(repo, *, empty=False, synthetic_versions=None):
    eng = engine()
    config = spec(capabilities=["inventory", "vault_metadata", "vault_value"], options={"include_values": True})
    data = responses()
    if empty:
        data[f"https://secretmanager.googleapis.com/v1/projects/{PROJECT}/secrets"] = {"secrets": []}
    else:
        data[f"https://secretmanager.googleapis.com/v1/{SECRET}/versions/2:access"] = {
            "name": SECRET + "/versions/2", "payload": {"data": base64.b64encode(GH.encode()).decode()},
        }
    context = {"engine": eng, "key_id": hashlib.sha256(eng.config.fingerprint_key).hexdigest(),
               "engine_digest": eng.detection_digest, "policy_digest": contract()["policy_digest"]}
    transport = FakeTransport(data)
    records, final = drain(adapter.collect_pages(config, secrets={}, checkpoint={}, check=lambda: None,
        transport=transport, now=datetime.now(UTC), value_context=context))
    assert final.status == "COMPLETE" and not final.reasons
    if synthetic_versions is not None:
        # Generic schema 2 boundary cases. The real GCP collector above keeps
        # UNKNOWN; these typed copies do not claim that it discovers CURRENT.
        [template] = [item for item in records if getattr(item, "value_match", None)]
        records = [item for item in records if not getattr(item, "value_match", None)]
        records.extend(version_observation(template, *version) for version in synthetic_versions)
    store = MetadataStore(repo)
    owner, _ = store.create(config, "test")
    run = store.start(owner["id"], 1, str(uuid.uuid4()), metadata_contract(config).model_dump())
    store.append(owner["id"], run["id"], MetadataBatch(index=0, items=records), trusted_discovery=True)
    completed = store.finish(owner["id"], run["id"], MetadataFinish(
        batch_count=1, item_count=len(records), status=final.status, reasons=final.reasons))
    assert completed["status"] == "COMPLETE"
    return records, transport


def version_observation(template, name, version, state, material):
    reference = f"projects/{PROJECT}/secrets/{name}/versions/{version}"
    [hashed] = hash_value(engine(), material.encode(), {"reference": reference}, max_bytes=4096)
    body = template.model_dump()
    body["identity"]["object_id"] = f"secretVersion:global:{name}/versions/{version}"
    body["provenance"]["resource_id"] = reference
    body["facts"] = []
    body["value_match"].update(reference=reference, version=version, version_state=state,
                               fingerprint=hashed.fingerprint, provider_digest=hashed.provider_digest)
    return type(template).model_validate(body)


def coverage(repo):
    eng = engine()
    Orchestrator(repo, engine=eng, config=eng.config).scan_resource(
        GH.encode(), ResourceRef(source_type="inline", resource="synthetic"), verify=False)
    repo.put_setting("coverage_scope", {
        "confirmed": True, "revision": scope_revision(CoverageStore(repo).list_connections()),
    }, "test")
    result = report(repo, contract(), fingerprint_key_id=hashlib.sha256(eng.config.fingerprint_key).hexdigest())
    row = next(item for item in result["items"] if item["origin"] == "EXPOSURE")
    return result, row


def test_gcp_schema2_unknown_version_equality_stays_history_and_cannot_prove_absence(repo):
    records, transport = schema2_collection(repo)
    [match] = [item.value_match for item in records if getattr(item, "value_match", None)]
    assert match.evidence == "VALUE" and match.version_state == "UNKNOWN"
    assert match.credential_type == "GITHUB_TOKEN"
    assert any(url.endswith("/versions/2:access") for _, url, _ in transport.calls)
    assert not any("/versions/latest" in url for _, url, _ in transport.calls)
    assert any(getattr(item, "value_access", None) == "COMPLETE" for item in records)
    result, row = coverage(repo)
    assert row["state"] == "UNKNOWN" and not row["locations"]
    assert "CURRENT_VERSION_NOT_CONFIRMED" in result["scope_reasons"]
    assert "CURRENT_VERSION_NOT_CONFIRMED" in row["reasons"]
    assert row["history"][0]["version_state"] == "UNKNOWN"
    assert row["history"][0]["current_evidence"] is False


def test_explicit_schema1_latest_value_can_match_alongside_unknown_schema2_history(repo):
    schema2_collection(repo)
    config = ConnectionSpec(name="GCP latest", provider="gcp_secret_manager", project=PROJECT)
    calls = []

    def handle(request):
        calls.append(request.url.path)
        if request.url.path.endswith("/secrets"):
            return httpx.Response(200, json={"secrets": [{"name": SECRET}]})
        assert request.url.path.endswith("/versions/latest:access")
        return httpx.Response(200, json={"name": SECRET + "/versions/2",
                                       "payload": {"data": base64.b64encode(GH.encode()).decode()}})

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        collected = collect_gcp(config, client, lambda: "synthetic", engine())
    assert collected.status == "COMPLETE" and collected.items[0].version_state == "CURRENT"
    store = CoverageStore(repo)
    owner, _ = store.create(config, "test")
    save(store, owner, collected.items)
    result, row = coverage(repo)
    assert row["state"] == "MATCHED"
    assert row["locations"][0]["version_state"] == "CURRENT"
    assert row["history"][0]["version_state"] == "UNKNOWN"
    assert "CURRENT_VERSION_NOT_CONFIRMED" in result["scope_reasons"]
    assert any(path.endswith("/versions/latest:access") for path in calls)


def test_empty_complete_gcp_vault_scope_retains_normal_absence_evidence(repo):
    records, _ = schema2_collection(repo, empty=True)
    assert not any(getattr(item, "value_match", None) for item in records)
    result, row = coverage(repo)
    assert row["state"] == "NO_VAULT_MATCH"
    assert not row["locations"] and not row["history"]
    assert result["scope_reasons"] == []


def test_explicit_previous_version_without_current_observation_cannot_prove_current_absence(repo):
    schema2_collection(repo, synthetic_versions=[("deploy-token", "2", "PREVIOUS", GH)])
    result, row = coverage(repo)
    assert row["state"] == "UNKNOWN" and not row["locations"]
    assert "CURRENT_VERSION_NOT_CONFIRMED" in result["scope_reasons"]
    assert row["history"][0]["version_state"] == "PREVIOUS"


@pytest.mark.parametrize("history_state", ["UNKNOWN", "PREVIOUS"])
def test_current_version_confirms_absence_with_older_same_object_value(repo, history_state):
    schema2_collection(repo, synthetic_versions=[
        ("deploy-token", "2", history_state, GH),
        ("deploy-token", "3", "CURRENT", GH[:-2] + "D7"),
    ])
    result, row = coverage(repo)
    assert row["state"] == "NO_VAULT_MATCH" and not row["locations"]
    assert row["history"][0]["version_state"] == history_state
    assert result["scope_reasons"] == []


@pytest.mark.parametrize("history_state", ["UNKNOWN", "PREVIOUS"])
def test_current_version_of_another_object_does_not_clear_unconfirmed_current_version(repo, history_state):
    schema2_collection(repo, synthetic_versions=[
        ("deploy-token", "2", history_state, GH),
        ("other-token", "3", "CURRENT", GH[:-2] + "D7"),
    ])
    result, row = coverage(repo)
    assert row["state"] == "UNKNOWN" and not row["locations"]
    assert "CURRENT_VERSION_NOT_CONFIRMED" in result["scope_reasons"]
    assert row["history"][0]["version_state"] == history_state
