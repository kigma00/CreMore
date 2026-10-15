"""End-to-end orchestration tests over the in-memory repository."""

from __future__ import annotations

from cremore import risk
from cremore.db.repository import InMemoryRepository
from cremore.detection import ResourceRef, SanitizedDetection
from cremore.detection.engine import EngineConfig
from cremore.detection.verify import VerifierConfig, load_default_verifiers
from cremore.risk.model import AWSPrivilegeSignal
from cremore.scanning import Orchestrator

GH = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"


class FakeResp:
    def __init__(self, status, text="", headers=None):
        self.status_code, self.text, self.headers = status, text, headers or {}


class FakeClient:
    def __init__(self, resp):
        self._resp = resp

    def request(self, *a, **k):
        return self._resp

    def post(self, *a, **k):
        return self._resp

    def close(self):
        pass


def _resource(exposure="public"):
    return ResourceRef(source_type="github", resource="org/repo", location="app.py",
                       metadata={"exposure": exposure})


def test_scan_persists_credential_exposure_finding():
    repo = InMemoryRepository()
    orch = Orchestrator(repo)
    result = orch.scan_resource(f"token = {GH}".encode(), _resource(exposure="internal"))

    assert result.detections == 1
    assert len(repo.credentials) == 1
    assert len(repo.exposures) == 1
    assert len(repo.findings) == 1

    cred = next(iter(repo.credentials.values()))
    assert cred.credential_type == "GITHUB_TOKEN"
    assert cred.fingerprint
    finding = repo.list_findings()[0]
    # not verified + internal exposure: 2 + 25 + 2 + 5 = 34 -> LOW
    assert finding.severity == "LOW"


def test_public_unverified_is_medium():
    repo = InMemoryRepository()
    Orchestrator(repo).scan_resource(f"token = {GH}".encode(), _resource(exposure="public"))
    # 2 + 25 + 2 + 15 = 44 -> MEDIUM
    assert repo.list_findings()[0].severity == "MEDIUM"


def test_rescan_dedupes_by_fingerprint():
    repo = InMemoryRepository()
    orch = Orchestrator(repo)
    for _ in range(3):
        orch.scan_resource(f"token = {GH}".encode(), _resource())
    assert len(repo.credentials) == 1
    assert len(repo.exposures) == 1
    assert len(repo.findings) == 1


def test_same_credential_two_locations_two_exposures_one_finding():
    repo = InMemoryRepository()
    orch = Orchestrator(repo)
    orch.scan_resource(f"a = {GH}".encode(),
                       ResourceRef(source_type="github", resource="org/repo", location="a.py",
                                   metadata={"exposure": "internal"}))
    orch.scan_resource(f"b = {GH}".encode(),
                       ResourceRef(source_type="github", resource="org/repo", location="b.py",
                                   metadata={"exposure": "public"}))
    assert len(repo.credentials) == 1
    assert len(repo.exposures) == 2
    assert len(repo.findings) == 1
    # The finding takes the highest severity across its exposures (public wins).
    assert repo.list_findings()[0].severity == "MEDIUM"


def _aws_detection(arn: str) -> SanitizedDetection:
    return SanitizedDetection(
        detector_name="aws-access-key-pair-v1",
        credential_type="AWS_ACCESS_KEY",
        fingerprint="fp-aws",
        provider="aws",
        identifier_hint="AKIA••••••••••••ZAM2",
        line_number=1,
        extra_safe_data={"verification_state": "verified", "verification_arn": arn},
    )


def test_potential_access_provider_feeds_privilege_axis():
    # A curated IAM evaluation that found a privilege-escalation action should
    # reach the risk model's privilege_scope axis at full weight.
    arn = "arn:aws:iam::123456789012:user/ci-deployer"
    signal = AWSPrivilegeSignal(
        evaluated=True,
        allowed_risks=frozenset({"PRIVILEGE_ESCALATION"}),
        allowed_count=1,
        actions_evaluated=20,
    )
    calls: list[str] = []

    def provider(principal_arn: str) -> AWSPrivilegeSignal:
        calls.append(principal_arn)
        return signal

    orch = Orchestrator(InMemoryRepository(), potential_access_provider=provider)
    facts = orch._facts(_aws_detection(arn), _resource(exposure="internal"), occurrences=1)

    assert calls == [arn]
    assert facts.verification.aws_privilege is signal

    result = risk.assess(facts, "fp-aws")
    privilege = next(e for e in result.evidence if e.dimension == "privilege_scope")
    assert privilege.points == privilege.max_points  # escalation -> full weight


def test_no_provider_leaves_privilege_unscored():
    arn = "arn:aws:iam::123456789012:user/ci-deployer"
    orch = Orchestrator(InMemoryRepository())  # no potential_access_provider
    facts = orch._facts(_aws_detection(arn), _resource(exposure="internal"), occurrences=1)
    assert facts.verification.aws_privilege is None


def test_scan_does_not_promote_quarantine_policy_to_public_key_exposure():
    from cremore.domain.models import Credential

    arn = "arn:aws:iam::123456789012:user/ci"
    repo = InMemoryRepository()
    snapshot = {"collected_account_id": "123456789012", "identity_policies": {
        "summary": {"quarantine_policies": ["AWSCompromisedKeyQuarantineV3"]}}}
    repo.upsert_credential(Credential(fingerprint="fp-aws", credential_type="AWS_ACCESS_KEY", provider="aws",
                                     principal_arn=arn, usage_snapshot=snapshot))
    detection = _aws_detection(arn)
    detection.extra_safe_data = {"verification_state": "not_attempted", "verification_arn": arn}
    Orchestrator(repo).scan_resource(b"", _resource(exposure="internal"), detections=[detection])
    assert repo.list_findings()[0].severity == "LOW"
    assert next(iter(repo.credentials.values())).usage_snapshot == snapshot


def test_verified_public_is_critical():
    load_default_verifiers()
    repo = InMemoryRepository()
    client = FakeClient(FakeResp(200, "{}", {"X-OAuth-Scopes": "repo"}))
    orch = Orchestrator(
        repo,
        config=EngineConfig(verify=VerifierConfig(enabled=True), http_client=client),
    )
    orch.scan_resource(f"token = {GH}".encode(), _resource(exposure="public"), verify=True)
    cred = next(iter(repo.credentials.values()))
    assert cred.credential_status == "Active"  # verified
    # valid + broad scope + public -> override to CRITICAL
    assert repo.list_findings()[0].severity == "CRITICAL"
