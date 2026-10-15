"""Saved verification survives passive scans, failed attempts and UI sessions."""

from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.credential_governance import credential_governance
from cremore.api.finding_evidence import detection_details
from cremore.config import Settings
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.detection import ResourceRef, SanitizedDetection
from cremore.domain.models import Credential, Exposure
from cremore.risk.model import ExposureFacts, Facts, Verification
from cremore.risk.verification import latest_verification
from cremore.scanning.orchestrator import Orchestrator
from cremore.scanning.rescore import RescoreService

AT = datetime(2026, 9, 15, 10, tzinfo=UTC)


@pytest.fixture(params=["memory", "sqlite"])
def repo(request):
    if request.param == "memory":
        return InMemoryRepository()
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


def forbidden(*args, **kwargs):
    raise AssertionError("saved-evidence test must never fetch content or call a provider")


def metadata(view):
    return {row["key"]: row for row in view["metadata"]}


def test_passive_scan_and_expired_session_preserve_check_time_and_risk(repo, monkeypatch):
    orch = Orchestrator(repo, potential_access_provider=forbidden)
    monkeypatch.setattr(orch.engine, "scan", forbidden)
    resource = ResourceRef(source_type="github", resource="synthetic/repo", location="fixture.txt",
                           metadata={"exposure": "internal"})

    def scan(extra):
        result = orch.scan_resource(b"", resource, detections=[SanitizedDetection(
            detector_name="Synthetic", credential_type="GITHUB_TOKEN", provider="github", fingerprint="synthetic",
            line_number=1, redacted_line="token = ***", extra_safe_data={"catalog_id": "github-pat", **extra})])
        finding = result.findings[0]
        return repo.get_credential(finding.credential_id), repo.exposures_for_credential(finding.credential_id)[0], finding

    cred, row, finding = scan({"verification_state": "verified", "verification_checked_at": AT.isoformat(),
                               "verification_scopes": "repo", "verification_owner_name": "synthetic-owner"})
    initial = detection_details(row, cred)
    assert initial["risk_evidence"][0] == "exploitability 35/35 verification_valid"
    cred, row, _ = scan({})
    passive = detection_details(row, cred)
    assert passive["verification_checked_at"] == AT.isoformat()
    assert passive["risk_score"] == initial["risk_score"]
    assert metadata(credential_governance(cred, [row]))["verification"]["value"] == "VERIFIED_ACTIVE"

    failed_at = AT + timedelta(minutes=5)
    cred, row, _ = scan({"verification_state": "indeterminate", "verification_checked_at": failed_at.isoformat(),
                         "verification_error": "ExpiredToken"})
    failed = detection_details(row, cred)
    facts = metadata(credential_governance(cred, [row]))
    assert facts["verification"]["value"] == "INCONCLUSIVE"
    assert facts["last_confirmed_verification"]["value"] == "VERIFIED_ACTIVE"
    assert facts["last_confirmed_verification"]["observed_at"] == AT.isoformat()
    assert "verification_owner_name" not in row.metadata  # not attributed to the failed attempt
    assert failed["risk_evidence"][0] == "exploitability 35/35 verification_historical_valid"
    assert failed["risk_score"] == initial["risk_score"] and failed["risk_confidence"] == "low"
    assert RescoreService(orch).rescore_all()["needs_rescan"] == 0

    # Session authorization affects access to the saved record, never its contents.
    token = "synthetic-api-token-" + "t" * 32
    client = TestClient(create_app(repo=repo, settings=Settings(
        AUTH_MODE="local", API_TOKEN=token, FINGERPRINT_KEY="ab" * 32)))
    auth = {"Authorization": f"Bearer {token}"}
    before = client.get(f"/api/v1/findings/{finding.id}", headers=auth).json()
    assert client.get(f"/api/v1/findings/{finding.id}").status_code == 401
    after = client.get(f"/api/v1/findings/{finding.id}", headers=auth).json()
    assert before == after
    assert client.get("/api/v1/findings", headers=auth).json()[0]["severity"] == after["severity"]

    cred, row, _ = scan({"verification_state": "rejected", "verification_checked_at": (AT + timedelta(minutes=10)).isoformat()})
    assert metadata(credential_governance(cred, [row]))["verification"]["value"] == "VERIFIED_INACTIVE"
    assert detection_details(row, cred)["risk_evidence"][0] == "exploitability 0/35 verification_invalid"


def test_legacy_mixed_badge_and_passive_score_use_saved_check_without_inventing_time():
    cred = Credential(id=uuid4(), fingerprint="synthetic", credential_type="AWS_ACCESS_KEY", provider="aws")
    row = Exposure(credential_id=cred.id, source_type="s3", resource_name="synthetic-bucket", location="fixture.txt",
        last_seen_at=AT, metadata={"verification_state": "verified", "risk_facts": asdict(Facts(
            provider="aws", credential_type="AWS_ACCESS_KEY", verification=Verification(),
            exposure=ExposureFacts(level="internal")))})
    facts = metadata(credential_governance(cred, [row]))
    assert facts["verification"]["value"] == "VERIFIED_ACTIVE"
    assert facts["verification"]["observed_at"] is None
    assert facts["verification"]["reason"] == "ACTIVE_VERIFICATION_CHECK_TIME_NOT_RECORDED"
    assert detection_details(row, cred)["risk_evidence"][0] == "exploitability 35/35 verification_valid"


def test_check_time_not_content_seen_time_controls_latest_and_expiration():
    cred = Credential(id=uuid4(), fingerprint="synthetic", credential_type="GITHUB_TOKEN", provider="github")
    def row(state, check, seen, **extra):
        return Exposure(credential_id=cred.id, source_type="github", resource_name="synthetic/repo", location=str(seen),
            last_seen_at=seen, metadata={"verification_state": state, "verification_checked_at": check.isoformat(), **extra})
    active = row("verified", AT, AT + timedelta(days=3), verification_expires_at=(AT + timedelta(hours=2)).isoformat())
    rejected = row("rejected", AT + timedelta(hours=1), AT + timedelta(days=1))
    assert latest_verification([active, rejected], cred, now=AT + timedelta(days=4)).state == "rejected"
    assert latest_verification([active], cred, now=AT + timedelta(hours=1)).risk_status == "valid"
    assert latest_verification([active], cred, now=AT + timedelta(hours=2)).risk_status == "expired"
    future = row("verified", AT + timedelta(days=8), AT)
    assert latest_verification([future], cred, now=AT).state == "indeterminate"
