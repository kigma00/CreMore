"""Cross-source evidence from synthetic saved observations; no vault or network."""

import json
import os

import pytest
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.credential_components import component_evidence
from cremore.config import Settings
from cremore.db.postgres_scan_test import (
    pg as pg,  # noqa: PLC0414 -- Shared isolated PostgreSQL fixture.
)
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.detection import ResourceRef
from cremore.detection.aws_material_test import ID, KEY, LABEL, SAK
from cremore.detection.engine import Engine, EngineConfig
from cremore.scanning.orchestrator import Orchestrator


@pytest.mark.parametrize("backend", ["memory", "sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def test_cross_source_parts_need_saved_binding_evidence_but_not_a_vault(backend, request):
    if backend == "memory":
        repo = InMemoryRepository()
    elif backend == "postgres":
        repo = request.getfixturevalue("pg")[1]
    else:
        database = make_engine("sqlite:///:memory:")
        create_all(database)
        repo = SqlRepository(database)
    eng = Engine(EngineConfig(fingerprint_key=KEY))
    orch = Orchestrator(repo, engine=eng, config=eng.config)

    def scan(value, source, path):
        findings = orch.scan_resource(value.encode(), ResourceRef(source_type=source, resource="synthetic", location=path), verify=False).findings
        assert len(findings) == 1
        return findings[0], repo.get_credential(findings[0].credential_id)

    id_finding, id_cred = scan(ID, "s3", "identifier.txt")
    secret_finding, secret_cred = scan(LABEL + SAK, "github", "config.txt")

    def project(cred):
        return component_evidence(repo, cred, repo.exposures_for_credential(cred.id))

    # Coexistence, even in the same installation, does not establish a pair.
    assert project(id_cred)["status"] == project(secret_cred)["status"] == "RELATION_UNCONFIRMED"
    pair_finding, pair_cred = scan(ID + " " + SAK, "s3", "previous-config.txt")
    pair_exposure = repo.exposures_for_credential(pair_cred.id)[0]
    repo.mark_exposure_removed(pair_exposure.id)
    for cred in (id_cred, secret_cred, pair_cred):
        view = project(cred)
        assert view["status"] == "BOTH_COMPONENTS_OBSERVED" and view["authentication_attempted"] is False
        assert len(view["links"]) == 1
        link = view["links"][0]
        assert link["pair_location"]["status"] == "REMOVED"
        assert link["verification_state"] == "not_attempted" and link["verification_checked_at"] is None
        assert {part["finding_id"] for part in link["components"]} == {str(id_finding.id), str(secret_finding.id)}
        assert SAK not in json.dumps(view) and ID not in json.dumps(view)
    # A passive repeat preserves the saved component relation.
    scan(ID + " " + SAK, "s3", "previous-config.txt")
    assert project(secret_cred)["status"] == "BOTH_COMPONENTS_OBSERVED"

    token = "synthetic-component-api-" + "t" * 32
    client = TestClient(create_app(repo=repo, settings=Settings(
        AUTH_MODE="local", API_TOKEN=token, FINGERPRINT_KEY="ab" * 32)))
    endpoint = f"/api/v1/findings/{secret_finding.id}"
    assert client.get(endpoint).status_code == 401
    response = client.get(endpoint, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200 and SAK not in response.text
    detail = response.json()
    assert detail["component_evidence"]["status"] == "BOTH_COMPONENTS_OBSERVED"
    assert detail["credential"]["governance"]["metadata"][0]["availability"] == "NOT_VERIFIABLE"
    # Join evidence remains available without publishing private join keys.
    for saved, finding in ((secret_cred, secret_finding), (pair_cred, pair_finding), (id_cred, id_finding)):
        view = client.get(f"/api/v1/findings/{finding.id}", headers={"Authorization": f"Bearer {token}"})
        assert view.status_code == 200 and saved.fingerprint not in view.text
        for exposure in repo.exposures_for_credential(saved.id):
            for name, fingerprint in exposure.metadata.items():
                if name.endswith("fingerprint") and fingerprint:
                    assert fingerprint not in view.text
    repo.update_finding_status(pair_finding.id, "FALSE_POSITIVE")
    assert project(secret_cred)["status"] == "RELATION_UNCONFIRMED"


def test_unkeyed_scans_do_not_publish_component_join_material():
    from cremore.detection import DetectorInput

    row = next(d for d in Engine().scan(DetectorInput((ID + " " + SAK).encode())) if d.provider == "aws")
    assert not any(key.endswith("component_fingerprint") for key in row.extra_safe_data)


def _repo_with_pair(verification=None):
    """A complete pair plus its two halves, each observed in a different source."""
    from cremore.api.credential_components import _FIELDS

    repo = InMemoryRepository()
    eng = Engine(EngineConfig(fingerprint_key=KEY))
    orch = Orchestrator(repo, engine=eng, config=eng.config)

    def scan(value, source, path, detections=None):
        result = orch.scan_resource(value.encode(), ResourceRef(source_type=source, resource="synthetic", location=path),
                                    detections=detections, verify=False)
        finding = result.findings[0]
        return finding, repo.get_credential(finding.credential_id)

    _, id_cred = scan(ID, "s3", "identifier.txt")
    _, secret_cred = scan(LABEL + SAK, "github", "config.txt")
    pair_finding, pair_cred = scan(ID + " " + SAK, "s3", "previous-config.txt")
    row = repo.exposures_for_credential(pair_cred.id)[0]
    if verification is not None:
        # The pair's own recorded provider answer, as a verified scan would save it.
        repo.upsert_exposure(row.model_copy(update={"metadata": {**row.metadata, **verification}}))
    components = repo.exposures_for_credential(pair_cred.id)[0].metadata
    assert components[_FIELDS["AWS_ACCESS_KEY_ID"]] == id_cred.fingerprint
    assert components[_FIELDS["AWS_SECRET_ACCESS_KEY"]] == secret_cred.fingerprint
    return repo, orch, id_cred, secret_cred, pair_finding


def test_a_verified_pair_answers_for_the_half_that_cannot_be_verified_alone():
    from cremore.api.credential_governance import credential_governance

    at = "2026-09-18T10:00:00+00:00"
    repo, _, id_cred, secret_cred, _ = _repo_with_pair(
        {"verification_state": "verified", "verification_checked_at": at,
         "verification_arn": "arn:aws:iam::222222222222:user/ci-deployer"})

    for cred in (id_cred, secret_cred):
        exposures = repo.exposures_for_credential(cred.id)
        component = component_evidence(repo, cred, exposures)
        facts = {f["key"]: f for f in credential_governance(cred, exposures, component=component)["metadata"]}
        # Without the link this said NOT_SUPPORTED while the panel beside it
        # showed a verified pair built from these exact bytes.
        assert facts["verification"]["value"] == "VERIFIED_ACTIVE"
        assert facts["verification"]["source"] == "LINKED_PAIR_ACTIVE_VERIFICATION"
        assert facts["verification"]["observed_at"] == at
        # The half is still a half, and its own owner was never returned to it.
        assert facts["material_completeness"]["value"] in ("AWS_IDENTIFIER_ONLY", "AWS_SECRET_ONLY")
        assert facts["provider_owner"]["reason"] == "NOT_COLLECTED"


def test_a_rejected_pair_does_not_declare_a_component_dead():
    """A rejection cannot separate a dead key from a pairing that was never real."""
    from cremore.api.credential_governance import credential_governance

    repo, _, id_cred, _, _ = _repo_with_pair(
        {"verification_state": "rejected", "verification_checked_at": "2026-09-18T10:00:00+00:00",
         "verification_error": "InvalidClientTokenId"})
    exposures = repo.exposures_for_credential(id_cred.id)
    view = credential_governance(id_cred, exposures, component=component_evidence(repo, id_cred, exposures))
    facts = {f["key"]: f for f in view["metadata"]}
    assert facts["verification"]["value"] == "NOT_SUPPORTED"
    assert facts["verification"]["availability"] == "NOT_VERIFIABLE"


def test_an_observation_recorded_before_component_evidence_is_reported_as_uncompared():
    """A pair seen in two places, one of them before the fields were recorded."""
    repo, orch, id_cred, _, pair_finding = _repo_with_pair()
    orch.scan_resource((ID + " " + SAK).encode(),
                       ResourceRef(source_type="github", resource="synthetic", location="older.txt"), verify=False)
    pair_cred_id = pair_finding.credential_id
    rows = repo.exposures_for_credential(pair_cred_id)
    assert len(rows) == 2
    older = next(row for row in rows if row.location == "older.txt")
    for key in [k for k in older.metadata if k.endswith("component_fingerprint")]:
        older.metadata.pop(key)  # as a record written before the fields existed

    view = component_evidence(repo, repo.get_credential(pair_cred_id), repo.exposures_for_credential(pair_cred_id))
    assert view["status"] == "BOTH_COMPONENTS_OBSERVED" and len(view["links"]) == 1
    # "Not comparable" must not read as "compared and unrelated".
    assert view["stale_evidence"] is True
    # The comparable half is unaffected.
    assert component_evidence(repo, id_cred, repo.exposures_for_credential(id_cred.id))["stale_evidence"] is False


def test_the_same_secret_under_another_label_links_by_bytes_without_being_retyped():
    repo, orch, _, _, _ = _repo_with_pair()
    result = orch.scan_resource(f'secret = "{SAK}"'.encode(),
                                ResourceRef(source_type="github", resource="synthetic", location="app.py"), verify=False)
    finding = result.findings[0]
    generic = repo.get_credential(finding.credential_id)
    assert generic.credential_type == "GENERIC_SECRET" and generic.provider != "aws"

    exposures = repo.exposures_for_credential(generic.id)
    view = component_evidence(repo, generic, exposures)
    assert view["status"] == "BOTH_COMPONENTS_OBSERVED"
    assert view["subject_component"] == "AWS_SECRET_ACCESS_KEY" and view["subject_matched_by_shape"] is True
    assert SAK not in json.dumps(view)
    # Linking is byte equality; it never reclassifies the value or raises its confidence.
    assert repo.get_credential(finding.credential_id).credential_type == "GENERIC_SECRET"


def test_a_shape_match_with_nothing_to_link_says_nothing_at_all():
    repo = InMemoryRepository()
    eng = Engine(EngineConfig(fingerprint_key=KEY))
    orch = Orchestrator(repo, engine=eng, config=eng.config)
    result = orch.scan_resource(f'secret = "{SAK}"'.encode(),
                                ResourceRef(source_type="github", resource="synthetic", location="app.py"), verify=False)
    cred = repo.get_credential(result.findings[0].credential_id)
    assert component_evidence(repo, cred, repo.exposures_for_credential(cred.id)) is None
