import uuid
from dataclasses import asdict
from datetime import UTC, datetime, timedelta

import pytest

from cremore.db.repository import InMemoryRepository
from cremore.db.scan_store import stable_digest
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import Credential, CustomRule, Exposure, FPProfile
from cremore.risk.model import ExposureFacts, Facts, Verification
from cremore.scanning.learned_fp import LearnedFPService, features
from cremore.scanning.orchestrator import Orchestrator
from cremore.scanning.rescore import RescoreService


@pytest.fixture(params=["memory", "sqlite"])
def repo(request):
    if request.param == "memory":
        return InMemoryRepository()
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


def seed(repo, *, count=1, severity="CRITICAL", metadata=None):
    credential = repo.upsert_credential(Credential(fingerprint=str(uuid.uuid4()), credential_type="GITHUB_TOKEN", provider="github"))
    safe = {"catalog_id": "github-pat", "detector_name": "GitHubPAT", "detection_confidence": "medium",
        "exposure": "internal", "risk_facts": asdict(Facts(provider="github", credential_type="GITHUB_TOKEN",
            verification=Verification(), exposure=ExposureFacts(level="internal")))}
    safe.update(metadata or {})
    cid = uuid.uuid4()
    for i in range(count):
        exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="github", source_connection_id=cid,
            resource_name="org/repo", location=f"tests/fixture{i}.py", severity=severity, redacted_line="token = ***", metadata=safe))
    finding = repo.upsert_finding(credential.id, exposure.id, severity)
    return credential, finding


def forbidden(*args, **kwargs):
    raise AssertionError("rescore must never fetch, detect, verify or simulate IAM")


@pytest.mark.parametrize("assessment_version", [None, 2])
def test_rescore_uses_the_same_later_simulation_as_the_dashboard(repo, assessment_version):
    from cremore_aws_provider.investigation.potential_access import ACTION_CATALOG

    from cremore.api.finding_evidence import _risk

    facts = Facts(provider="aws", credential_type="AWS_ACCESS_KEY_ID", exposure=ExposureFacts(level="internal"))
    credential, finding = seed(repo, severity="LOW", metadata={"catalog_id": "aws-access-key-id", "risk_facts": asdict(facts)})
    arn = "arn:aws:iam::123456789012:user/ci"
    repo.update_credential(credential.id, provider="aws", credential_type="AWS_ACCESS_KEY_ID", principal_arn=arn,
        usage_snapshot={"collected_account_id": "123456789012", "potential_access": {
            "principal_arn": arn, "evaluated_at": "2026-10-04T00:00:00Z", "collection_status": "COMPLETE",
            "assessment_version": assessment_version,
            "actions": [{"action": action, "decision": "ALLOWED"} for action, _ in ACTION_CATALOG]}})
    result = RescoreService(Orchestrator(repo, potential_access_provider=forbidden)).rescore_all()
    assert result["needs_rescan"] == 0 and result["processed"] == 1
    credential = repo.get_credential(credential.id)
    [exposure] = repo.exposures_for_credential(credential.id)
    expected = _risk(exposure, credential)
    assert repo.get_finding(finding.id).severity == expected["effective_severity"]
    if assessment_version == 2:
        assert "privilege_scope 20/20 aws_iam_privilege_escalation_allowed" in expected["risk_evidence"]
    else:
        assert "privilege_scope 2/20 privilege_scope_unknown" in expected["risk_evidence"]


def test_bounded_restart_safe_rescore_has_one_digest_and_no_provider_calls(repo, monkeypatch):
    credential, finding = seed(repo, count=5)
    orch = Orchestrator(repo, potential_access_provider=forbidden)
    monkeypatch.setattr(orch.engine, "scan", forbidden)
    service = RescoreService(orch)
    first = service.run_batch(2)
    assert first["processed"] == 2 and not first["done"]
    result = RescoreService(orch).rescore_all(batch_size=2)
    assert result["processed"] == 3 and result["done"]
    assert repo.get_finding(finding.id).severity == "LOW"
    rows = repo.exposures_for_credential(credential.id)
    assert all(e.severity == "LOW" and not e.metadata["rescore"]["needs_rescan"] for e in rows)
    assert all("digest" not in e.metadata["rescore"] for e in rows)
    assert service.run_batch()["processed"] == 0
    audits = [e for e in repo.list_finding_events(finding.id) if e.event_type == "RISK_REEVALUATED"]
    assert len(audits) == 3


def test_quarantine_attachment_is_preserved_without_upgrading_stored_risk(repo, monkeypatch):
    snapshot = {"collected_account_id": "123456789012", "identity_policies": {
        "summary": {"quarantine_policies": ["AWSCompromisedKeyQuarantineV3"]}}}
    credential = repo.upsert_credential(Credential(fingerprint=str(uuid.uuid4()), credential_type="AWS_ACCESS_KEY",
        provider="aws", principal_arn="arn:aws:iam::123456789012:user/ci", usage_snapshot=snapshot))
    facts = Facts(provider="aws", credential_type="AWS_ACCESS_KEY", exposure=ExposureFacts(level="internal"))
    exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="s3", source_connection_id=uuid.uuid4(),
        resource_name="bucket", location="config", severity="HIGH", redacted_line="key = ***",
        metadata={"catalog_id": "aws-access-key", "detector_name": "AWS", "detection_confidence": "high",
                  "exposure": "internal", "risk_facts": asdict(facts)}))
    finding = repo.upsert_finding(credential.id, exposure.id, "HIGH")
    orch = Orchestrator(repo, potential_access_provider=forbidden)
    monkeypatch.setattr(orch.engine, "scan", forbidden)
    result = RescoreService(orch).rescore_all()
    assert result["processed"] == 1 and result["needs_rescan"] == 0
    assert repo.get_finding(finding.id).severity == "LOW"
    assert repo.get_credential(credential.id).usage_snapshot == snapshot
    assert [event.event_type for event in repo.list_finding_events(finding.id)].count("RISK_REEVALUATED") == 1


@pytest.mark.parametrize("metadata", [
    {"catalog_id": ""}, {"risk_facts": {}}, {"exposure": "unknown"},
    {"risk_facts": {"provider": "github", "credential_type": "GITHUB_TOKEN", "verification": {}, "exposure": {}, "detection": {}}},
])
def test_missing_historical_evidence_keeps_score_and_requests_rescan(repo, metadata):
    credential, finding = seed(repo, metadata=metadata)
    result = RescoreService(Orchestrator(repo)).rescore_all()
    assert result["needs_rescan"] == 1
    assert repo.get_finding(finding.id).severity == "CRITICAL"
    row = repo.exposures_for_credential(credential.id)[0]
    assert row.status == "OPEN" and row.metadata["rescore"]["needs_rescan"]


def test_custom_severity_change_rescores_but_scope_pattern_change_needs_detection(repo):
    rule = CustomRule(id=uuid.uuid4(), name="test rule", pattern="corp_[a-zA-Z0-9]{24}", severity="HIGH")
    catalog_id = f"custom-{rule.id}"
    orch = Orchestrator(repo)
    orch._rules = {catalog_id: rule}
    credential, finding = seed(repo, metadata={"catalog_id": catalog_id,
        "rule_detection_digest": stable_digest(orch._rule_detection_policy(rule))})
    service = RescoreService(orch)
    assert service.rescore_all()["processed"] == 1
    assert repo.get_finding(finding.id).severity == "HIGH"
    detection_digest = orch.detection_policy_digest
    rule.severity = "LOW"
    assert service.rescore_all()["processed"] == 1
    assert repo.get_finding(finding.id).severity == "LOW"
    assert orch.detection_policy_digest == detection_digest
    rule.include_globs = ["tests/*"]
    assert orch.detection_policy_digest != detection_digest
    assert service.rescore_all()["needs_rescan"] == 1
    assert repo.exposures_for_credential(credential.id)[0].metadata["rescore"]["reason"] == "RULE_DETECTION_CHANGED"


def test_audit_failure_rolls_back_exposures_rollup_and_cursor(repo, monkeypatch):
    credential, finding = seed(repo, count=2)
    original = type(repo).record_finding_event

    def crash(self, event):
        if event.event_type == "RISK_REEVALUATED":
            raise RuntimeError("injected audit failure")
        return original(self, event)

    monkeypatch.setattr(type(repo), "record_finding_event", crash)
    service = RescoreService(Orchestrator(repo))
    with pytest.raises(RuntimeError, match="injected"):
        service.run_batch(1)
    assert all(e.severity == "CRITICAL" and "rescore" not in e.metadata for e in repo.exposures_for_credential(credential.id))
    assert repo.get_finding(finding.id).all_locations_removed is None
    monkeypatch.setattr(type(repo), "record_finding_event", original)
    assert service.rescore_all(batch_size=1)["processed"] == 2


def learned_service(repo, credential):
    exposures = repo.exposures_for_credential(credential.id)
    centroid = {f: 1.0 for e in exposures for f in features(e.location, e.redacted_line)}
    profile = repo.save_fp_profile(FPProfile(scope_kind="source", scope_id=exposures[0].source_connection_id,
        source_type="github", detector_name="GitHubPAT", credential_type="GITHUB_TOKEN", sample_count=3,
        distinct_actors=2, active=True, threshold=0.2, min_samples=3, centroid=centroid))
    svc = LearnedFPService(repo, enabled=True, min_samples=3, threshold=0.2, max_confidence="high")
    return RescoreService(Orchestrator(repo, learned_fp=svc)), profile


@pytest.mark.parametrize("status", ["ACKNOWLEDGED", "IGNORED", "FALSE_POSITIVE", "RESOLVED"])
def test_rescore_preserves_manual_workflow_status(repo, status):
    credential, finding = seed(repo)
    repo.update_finding_status(finding.id, status, resolution="analyst decision")
    service, _ = learned_service(repo, credential)
    service.rescore_all()
    updated = repo.get_finding(finding.id)
    assert updated.workflow_status == status
    if status != "ACKNOWLEDGED":
        assert updated.resolution == "analyst decision"


def test_rescore_learned_fp_requires_every_active_location_and_unchanged_evidence(repo):
    credential, finding = seed(repo, count=2)
    service, _ = learned_service(repo, credential)
    # Make the clock boundary explicit without sleeps.
    old = datetime.now(UTC) - timedelta(seconds=5)
    if hasattr(repo, "engine"):
        from sqlalchemy import update

        from cremore.db.schema import exposures
        with repo.engine.begin() as conn:
            conn.execute(update(exposures).values(last_seen_at=old))
    else:
        for e in repo.exposures.values():
            e.last_seen_at = old
    service.rescore_all(batch_size=1)
    assert repo.get_finding(finding.id).workflow_status == "FALSE_POSITIVE"

    other, unsafe = seed(repo, count=2)
    service, _ = learned_service(repo, other)
    row = repo.exposures_for_credential(other.id)[0]
    repo.upsert_exposure(row.model_copy(update={"metadata": {**row.metadata, "exposure": "public"}}))
    service.rescore_all(batch_size=1)
    assert repo.get_finding(unsafe.id).workflow_status == "OPEN"


def test_new_observation_or_manual_ack_between_batches_prevents_auto_fp(repo):
    credential, finding = seed(repo, count=2)
    service, _ = learned_service(repo, credential)
    assert service.run_batch(1)["processed"] == 1
    repo.update_finding_status(finding.id, "ACKNOWLEDGED")
    service.rescore_all(batch_size=1)
    assert repo.get_finding(finding.id).workflow_status == "ACKNOWLEDGED"


def test_observation_changed_after_processed_chunk_blocks_auto_fp(repo):
    credential, finding = seed(repo, count=2)
    service, _ = learned_service(repo, credential)
    service.run_batch(1)
    # Change a row already behind the cursor. Its prior eligibility cannot be
    # applied to new evidence even when the incoming masked context is equal.
    row = min(repo.exposures_for_credential(credential.id), key=lambda e: str(e.id))
    repo.upsert_exposure(row)
    service.rescore_all(batch_size=1)
    assert repo.get_finding(finding.id).workflow_status == "OPEN"


def test_stored_verified_observation_never_auto_fp_and_is_not_reverified(repo):
    snapshot = asdict(Facts(provider="github", credential_type="GITHUB_TOKEN",
        verification=Verification(status="valid"), exposure=ExposureFacts(level="internal")))
    credential, finding = seed(repo, metadata={"risk_facts": snapshot})
    service, _ = learned_service(repo, credential)
    service.orchestrator.potential_access_provider = forbidden
    service.rescore_all()
    assert repo.get_finding(finding.id).workflow_status == "OPEN"
    rescore = repo.exposures_for_credential(credential.id)[0].metadata["rescore"]
    assert rescore["status"] == "SCORED_STORED_EVIDENCE" and rescore["evidence_as_of"]


def test_invalid_batch_size_is_rejected(repo):
    service = RescoreService(Orchestrator(repo))
    for size in (0, -1, 1001, True, "10"):
        with pytest.raises(ValueError, match="RESCORE_BATCH_SIZE"):
            service.run_batch(size)


def test_privilege_scores_without_a_proven_account_are_kept_and_marked_for_rescan(repo):
    from cremore.risk.model import AWSPrivilegeSignal

    def aws_seed(signal):
        credential = repo.upsert_credential(Credential(fingerprint=str(uuid.uuid4()), credential_type="AWS_ACCESS_KEY",
                                                       provider="aws", principal_arn="arn:aws:iam::123456789012:user/ci"))
        facts = asdict(Facts(provider="aws", credential_type="AWS_ACCESS_KEY",
                             verification=Verification(status="valid", aws_privilege=signal), exposure=ExposureFacts(level="internal")))
        facts["verification"]["aws_privilege"]["allowed_risks"] = sorted(signal.allowed_risks)
        exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="s3", source_connection_id=uuid.uuid4(),
            resource_name="bucket", location="k", severity="CRITICAL", redacted_line="x",
            metadata={"catalog_id": "aws-access-key", "detector_name": "AWS", "detection_confidence": "high",
                      "exposure": "internal", "risk_facts": facts}))
        repo.upsert_finding(credential.id, exposure.id, "CRITICAL")
        return credential

    legacy = aws_seed(AWSPrivilegeSignal(evaluated=True, allowed_risks=frozenset({"PRIVILEGE_ESCALATION"}), allowed_count=1, actions_evaluated=10))
    proven = aws_seed(AWSPrivilegeSignal(evaluated=True, allowed_risks=frozenset({"PRIVILEGE_ESCALATION"}), allowed_count=1,
                                         actions_evaluated=10, account_id="123456789012"))
    elsewhere = aws_seed(AWSPrivilegeSignal(evaluated=True, allowed_count=0, actions_evaluated=10, account_id="999999999999"))
    RescoreService(Orchestrator(repo)).rescore_all()
    reasons = {c.id: repo.exposures_for_credential(c.id)[0].metadata["rescore"]["reason"] for c in (legacy, proven, elsewhere)}
    assert reasons == {legacy.id: "PRIVILEGE_ACCOUNT_UNVERIFIED", proven.id: "", elsewhere.id: "PRIVILEGE_ACCOUNT_UNVERIFIED"}
    assert repo.exposures_for_credential(legacy.id)[0].severity == "CRITICAL"  # prior score kept until re-collected
