"""Passive STS session evidence survives each schema 2 vault adapter and worker."""

import base64
import hashlib
import json
from functools import partial
from types import SimpleNamespace

import pytest
from cremore_azure_provider.metadata import adapter as azure_adapter
from cremore_azure_provider.metadata.azure_key_vault_test import secret
from cremore_azure_provider.metadata.values_test import ValueVault, configured
from cremore_gcp_provider.metadata import adapter as gcp_adapter
from cremore_gcp_provider.metadata.tests.fake import (
    SECRET as GCP_SECRET,
)
from cremore_gcp_provider.metadata.tests.fake import (
    FakeTransport,
    inventory_responses,
)
from cremore_gcp_provider.metadata.tests.fake import (
    spec as gcp_spec,
)
from cremore_gitlab_provider.metadata import adapter as gitlab_adapter
from cremore_gitlab_provider.metadata.tests.test_extensions import Fixture, variable
from cremore_gitlab_provider.metadata.tests.test_extensions import spec as gitlab_spec

from cremore.api.metadata_coverage import public_metadata
from cremore.coverage import METADATA_JOB_KIND
from cremore.coverage.aws_evidence_correlation_test import (
    ID,
    KEY,
    OTHER_TOKEN,
    SECRET,
    TOKEN,
    material,
)
from cremore.coverage.correlation import report, scope_revision
from cremore.coverage.metadata_job_test import repo as repo  # noqa: PLC0414 -- shared store fixture
from cremore.coverage.metadata_models import MetadataValueMatch
from cremore.coverage.metadata_store import MetadataStore
from cremore.coverage.models import Contract, Observation
from cremore.coverage.store import CoverageStore
from cremore.db.task_store import TaskStore
from cremore.detection import ResourceRef
from cremore.detection.engine import EngineConfig
from cremore.domain.models import ScanJob
from cremore.scanning.orchestrator import Orchestrator
from cremore.worker import JobWorker


def _value(**changes):
    return {"evidence": "VALUE", "reference": "synthetic-session", "credential_type": "AWS_ACCESS_KEY",
            "identifier": ID, "fingerprint": "a" * 64, "session_fingerprint": "b" * 64, **changes}


def _metadata(**changes):
    return {**_value(), "key_id": "c" * 64, "engine_digest": "d" * 64,
            "policy_digest": "e" * 64, "read_at": "2026-09-25T00:00:00Z", **changes}


@pytest.mark.parametrize("changes", [
    {"credential_type": "GITHUB_TOKEN"}, {"identifier": "AKIA" + ID[4:]},
    {"identifier": ID[:-1]}, {"identifier": ID + "A"},
    {"evidence": "IDENTIFIER", "fingerprint": None},
    {"evidence": "UNRESOLVED", "fingerprint": None, "reason": "VALUE_UNAVAILABLE"},
    {"session_fingerprint": "not-a-digest"},
])
def test_schema2_session_constraints_equal_schema1(changes):
    for model, values in ((Observation, _value(**changes)), (MetadataValueMatch, _metadata(**changes))):
        with pytest.raises(ValueError):
            model.model_validate(values)


def test_schema2_session_field_is_optional_for_existing_records():
    assert MetadataValueMatch.model_validate(_metadata()).session_fingerprint == "b" * 64
    old = _metadata()
    old.pop("session_fingerprint")
    assert MetadataValueMatch.model_validate(old).session_fingerprint is None


def _wire(provider, data, monkeypatch):
    if provider == "azure_key_vault":
        spec = configured()
        source = ValueVault({"/secrets": {"value": [secret()]},
                             "/secrets/db-password": {**secret(version="a1"), "value": data.decode()}})
        module, kwargs = azure_adapter, {"transport": source}
    elif provider == "gitlab":
        spec = gitlab_spec(["ci_variables"], values=True, scopes=[{"kind": "group", "id": "10"}])
        source = Fixture(spec, {"/groups/10/variables": [variable(value=data.decode())]})
        module, kwargs = gitlab_adapter, {"client": source}
    else:
        spec = gcp_spec(capabilities=["inventory", "vault_metadata", "vault_value"],
                        options={"include_values": True})
        responses = inventory_responses(locations=())
        for body in responses.values():
            if "accounts" in body:
                body["accounts"] = [row for row in body["accounts"] if "@" in row["email"]]
            if "keys" in body:
                body["keys"] = [row for row in body["keys"] if row.get("name", "").startswith("projects/")]
            if "versions" in body:
                body["versions"] = [row for row in body["versions"] if row["state"] != "PENDING"]
        responses[f"https://secretmanager.googleapis.com/v1/{GCP_SECRET}/versions/2:access"] = {
            "name": GCP_SECRET + "/versions/2", "payload": {"data": base64.b64encode(data).decode()}}
        source = FakeTransport(responses)
        module, kwargs = gcp_adapter, {"transport": source}
    monkeypatch.setattr(module, "collect_pages", partial(module.collect_pages, **kwargs))
    return spec


@pytest.mark.parametrize("provider", ["azure_key_vault", "gitlab", "gcp"])
@pytest.mark.parametrize("stored_token", [TOKEN, OTHER_TOKEN, None], ids=["same-session", "other-session", "pair-only"])
def test_worker_preserves_session_evidence_without_claiming_current_unknown_version(repo, monkeypatch, provider, stored_token):
    spec = _wire(provider, material(stored_token), monkeypatch)
    store = MetadataStore(repo)
    connection, _ = store.create(spec, "synthetic-admin")
    orchestrator = Orchestrator(repo, config=EngineConfig(fingerprint_key=KEY))
    orchestrator.scan_resource(material(), ResourceRef(source_type="inline", resource="synthetic-session"), verify=False)
    finding = next(row for row in repo.list_findings()
                   if repo.get_credential(row.credential_id).credential_type == "AWS_ACCESS_KEY")
    job = repo.enqueue_job(ScanJob(kind=METADATA_JOB_KIND, payload={
        "provider": provider, "coverage_connection_id": str(connection["id"]),
        "coverage_revision": connection["revision"],
    }))
    worker = JobWorker(repo, orchestrator=orchestrator, metadata_secret_resolver=SimpleNamespace(
        resolve=lambda _reference: {"token": "SYNTHETIC_ADMIN"}))
    assert worker.process_next()
    assert repo.get_job(job.id).status == "SUCCEEDED", repo.get_job(job.id).error
    run = store.connection_runs(connection["id"])["items"][0]
    assert run["status"] == "COMPLETE", run["reasons"]
    records = list(store.iter_records(run["id"]))
    matches = [row["value_match"] for row in records if (row.get("value_match") or {}).get("credential_type") == "AWS_ACCESS_KEY"]
    assert len(matches) == 1
    match = matches[0]
    assert bool(match["session_fingerprint"]) is (stored_token is not None)
    repo.put_setting("coverage_scope", {
        "confirmed": True, "revision": scope_revision(CoverageStore(repo).list_connections()),
    }, "synthetic-admin")
    contract = Contract(engine_digest=orchestrator.engine.detection_digest,
                        policy_digest=orchestrator.coverage_policy_digest).model_dump()
    view = report(repo, contract, finding_id=finding.id, fingerprint_key_id=hashlib.sha256(KEY).hexdigest())
    item = view["item"]
    same = stored_token == TOKEN
    if provider == "gcp":
        assert match["version_state"] == "UNKNOWN"
        assert item["state"] == item["session_match_state"] == "UNKNOWN"
        assert not item["locations"]
        locations = item["history"]
    else:
        assert match["version_state"] == "CURRENT"
        assert item["state"] == ("MATCHED" if same else "UNKNOWN")
        assert item["session_match_state"] == ("MATCHED" if same else "PAIR_ONLY")
        locations = item["locations"]
    assert locations and locations[0]["match_basis"] == ("SESSION_FINGERPRINT" if same else "KEY_PAIR_FINGERPRINT")
    if provider != "gcp" and not same:
        assert "STS_SESSION_BINDING_NOT_CONFIRMED" in item["reasons"]
    persisted = json.dumps([records, TaskStore(repo).list_for_run(job.id)], default=str)
    public = json.dumps([view, public_metadata({"records": records})], default=str)
    for raw in (TOKEN, OTHER_TOKEN, SECRET):
        assert raw not in persisted and raw not in public
    assert "session_fingerprint" not in public
    if match["session_fingerprint"]:
        assert match["session_fingerprint"] not in public
    assert match["fingerprint"] not in json.dumps(view, default=str)
