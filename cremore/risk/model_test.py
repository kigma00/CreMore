"""Risk model tests, including the evidence-based floor policy (v5)."""

from __future__ import annotations

from cremore.risk.model import (
    AWSPrivilegeSignal,
    DetectionFacts,
    ExposureFacts,
    Facts,
    Verification,
    assess,
)


def priv(result):
    return next(e for e in result.evidence if e.dimension == "privilege_scope")


def test_score_is_the_sum_of_axes():
    r = assess(Facts(
        provider="aws", credential_type="AWS_ACCESS_KEY",
        verification=Verification(status="valid"),
        exposure=ExposureFacts(level="internal", occurrences=1),
    ))
    # 35 usable + 30 AWS + 2 unknown-privilege floor + 5 internal.
    assert r.score_before_overrides == 72
    assert r.level == "HIGH"
    assert sum(e.points for e in r.evidence) == r.score_before_overrides


def test_no_information_scores_low_not_medium():
    r = assess(Facts(
        provider="aws", credential_type="AWS_ACCESS_KEY",
        verification=Verification(status="not_attempted"),
        exposure=ExposureFacts(level="unknown"),
    ))
    # 2 + 30 + 2 + 2 = 36 -> LOW, with low confidence.
    assert r.score == 36
    assert r.level == "LOW"
    assert r.confidence == "low"
    assert "provider_validity_not_confirmed" in r.missing_evidence


def test_unknown_axes_are_floors_not_zero():
    r = assess(Facts(provider="x", credential_type="X",
                     verification=Verification(status="not_attempted"),
                     exposure=ExposureFacts(level="unknown")))
    for e in r.evidence:
        assert not (e.points == 0 and not e.confirmed), e


def test_valid_public_is_critical_override():
    r = assess(Facts(provider="notion", credential_type="NOTION_TOKEN",
                     verification=Verification(status="valid"),
                     exposure=ExposureFacts(level="public")))
    assert r.level == "CRITICAL" and r.score >= 90
    assert any(o.reason_code == "valid_public_credential_minimum_critical" for o in r.overrides)


def test_valid_aws_root_is_critical():
    r = assess(Facts(provider="aws", credential_type="AWS_ACCESS_KEY",
                     verification=Verification(status="valid", owner_kind="root"),
                     exposure=ExposureFacts(level="internal")))
    assert r.level == "CRITICAL"
    assert any(o.reason_code == "valid_aws_root_minimum_critical" for o in r.overrides)


def test_invalid_is_capped_not_dismissed():
    r = assess(Facts(provider="aws", credential_type="AWS_ACCESS_KEY",
                     verification=Verification(status="invalid"),
                     exposure=ExposureFacts(level="public", occurrences=4)))
    assert r.score <= 69
    assert r.level not in ("CRITICAL", "HIGH")
    assert r.level != "INFO"


def test_low_confidence_detector_lowers_reported_confidence():
    # A labelled (non-self-identifying) match reports lower confidence so triage
    # can tell a self-identifying hit from a value recognised only by its label.
    base = {"provider": "github", "credential_type": "GITHUB_TOKEN",
                "verification": Verification(status="valid"),
                "exposure": ExposureFacts(level="internal")}
    high = assess(Facts(**base, detection=DetectionFacts(low_confidence_detector=False)))
    low = assess(Facts(**base, detection=DetectionFacts(low_confidence_detector=True)))
    assert "detection_confidence_not_high" in low.confidence_reasons
    assert "detection_confidence_not_high" not in high.confidence_reasons
    # Evidence-based v5 already keeps these at MEDIUM max regardless of impact.


def test_github_scopes_drive_privilege():
    for scopes, want in [
        (("admin:org",), 20), (("repo",), 20), (("write:org",), 15),
        (("gist",), 10), (("read:user",), 5), (("future_permission",), 5),
    ]:
        r = assess(Facts(provider="github", credential_type="GITHUB_TOKEN",
                         verification=Verification(status="valid", scopes=scopes),
                         exposure=ExposureFacts(level="internal")))
        assert priv(r).points == want, (scopes, priv(r).points)


def test_aws_iam_simulation_drives_privilege():
    cases = [
        (frozenset({"PRIVILEGE_ESCALATION"}), 20, "aws_iam_privilege_escalation_allowed"),
        (frozenset({"DESTRUCTIVE"}), 18, "aws_iam_high_impact_actions_allowed"),
        (frozenset({"WRITE"}), 15, "aws_iam_write_actions_allowed"),
        (frozenset({"READ"}), 10, "aws_iam_read_only_actions_allowed"),
        (frozenset(), 5, "aws_iam_no_high_impact_actions_allowed"),
    ]
    for risks, want, reason in cases:
        sig = AWSPrivilegeSignal(evaluated=True, allowed_risks=risks, actions_evaluated=20)
        r = assess(Facts(provider="aws", credential_type="AWS_ACCESS_KEY",
                         verification=Verification(status="valid", aws_privilege=sig),
                         exposure=ExposureFacts(level="internal")))
        assert priv(r).points == want and priv(r).reason_code == reason


def test_aws_iam_not_evaluated_stays_unknown_floor():
    sig = AWSPrivilegeSignal(evaluated=False)
    r = assess(Facts(provider="aws", credential_type="AWS_ACCESS_KEY",
                     verification=Verification(status="valid", aws_privilege=sig),
                     exposure=ExposureFacts(level="internal")))
    assert priv(r).points == 2 and priv(r).reason_code == "privilege_scope_unknown"


def test_exposure_occurrences_raise_within_cap():
    one = assess(Facts(provider="x", credential_type="X",
                       verification=Verification(status="valid"),
                       exposure=ExposureFacts(level="internal", occurrences=1)))
    many = assess(Facts(provider="x", credential_type="X",
                        verification=Verification(status="valid"),
                        exposure=ExposureFacts(level="internal", occurrences=20)))
    assert many.score_before_overrides > one.score_before_overrides
    for e in many.evidence:
        if e.dimension == "exposure":
            assert e.points <= 15


def test_quarantine_policy_attachment_is_not_key_exposure_evidence():
    """A customer can attach the AWS-managed policy; it identifies no key."""

    from dataclasses import asdict

    from cremore.risk.model import facts_from_snapshot

    def score(level, status, *, quarantine=False):
        facts = Facts(provider="aws", credential_type="AWS_ACCESS_KEY",
                      verification=Verification(status=status), exposure=ExposureFacts(level=level))
        return assess(facts, "f" * 64, provider_quarantine=quarantine)

    for level in ("unknown", "internal", "public"):
        for status in ("not_attempted", "valid", "historical_valid", "invalid", "expired"):
            assert score(level, status, quarantine=True) == score(level, status)
    # Real publicness and validity evidence still determine risk independently.
    assert score("public", "valid").score == 90 and score("internal", "valid").overrides == []
    stored = asdict(Facts(provider="aws", credential_type="AWS_ACCESS_KEY"))
    assert "quarantine" not in repr(stored) and facts_from_snapshot(stored) == Facts(
        provider="aws", credential_type="AWS_ACCESS_KEY")
