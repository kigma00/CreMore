import datetime as dt
import uuid

import pytest

from cremore.api.credential_governance import credential_governance, verification_fact
from cremore.config import Settings
from cremore.domain.models import Credential, Exposure

T1 = dt.datetime(2026, 9, 15, 12, 0, tzinfo=dt.UTC)
T2 = T1 + dt.timedelta(hours=1)
ARN = "arn:aws:iam::123456789012:user/scanner-test-user"


def exposure(state, at=T1, **meta):
    return Exposure(credential_id=uuid.uuid4(), source_type="s3", resource_name="b", location=str(uuid.uuid4()),
                    last_seen_at=at, metadata={"verification_state": state, "verification_checked_at": at.isoformat() if at else None, **meta} if state else {})


def facts(view):
    return {f["key"]: f for f in view["metadata"]}


def test_verified_key_is_active_with_its_verified_owner_and_check_time():
    cred = Credential(id=uuid.uuid4(), fingerprint="f", credential_type="AWS_ACCESS_KEY", provider="aws",
                      principal_arn=ARN, credential_status="Active")
    view = credential_governance(cred, [exposure("verified")])
    got = facts(view)
    assert got["verification"]["value"] == "VERIFIED_ACTIVE" and got["verification"]["source"] == "ACTIVE_VERIFICATION"
    assert got["verification"]["availability"] == "AVAILABLE" and got["verification"]["observed_at"] == T1.isoformat()
    assert got["provider_owner"]["value"] == ARN and got["provider_owner_kind"]["value"] == "IAM_USER"
    assert got["provider_account_id"]["value"] == "123456789012"
    assert "AWS_ACTIVITY" in view["panel_hints"] and view["type_capability"]["execution_authorized"] is False
    # usage lookups that never ran in the owner account are not evidence
    assert got["last_used_at"]["availability"] == "NOT_COLLECTED"


def test_every_verification_outcome_maps_to_the_dashboard_vocabulary():
    assert verification_fact([exposure("rejected")])["value"] == "VERIFIED_INACTIVE"
    assert verification_fact([exposure("restricted")])["value"] == "VERIFIED_ACTIVE"
    inconclusive = verification_fact([exposure("indeterminate", verification_error="SignatureDoesNotMatch")])
    assert (inconclusive["value"], inconclusive["availability"], inconclusive["source_detail"]) == ("INCONCLUSIVE", "UNKNOWN", "SignatureDoesNotMatch")
    assert verification_fact([exposure("unsupported")])["availability"] == "NOT_SUPPORTED"
    for untouched in ([], [exposure(None)], [exposure("not_attempted")]):
        assert verification_fact(untouched)["value"] == "NOT_REQUESTED"
    # the latest check wins; disagreeing checks at the same time are not resolved by guessing
    assert verification_fact([exposure("verified", T1), exposure("rejected", T2)])["value"] == "VERIFIED_INACTIVE"
    conflict = verification_fact([exposure("verified", T2), exposure("rejected", T2)])
    assert conflict["value"] == "INCONCLUSIVE" and conflict["reason"] == "ACTIVE_VERIFICATION_SAME_TIME_CONFLICT"
    # provider error text never passes through, only a safe code
    assert verification_fact([exposure("indeterminate", verification_error="bad <script> text")])["source_detail"] == ""


def test_usage_facts_only_from_a_lookup_in_the_owner_account():
    base = {"id": uuid.uuid4(), "fingerprint": "f", "credential_type": "AWS_ACCESS_KEY", "provider": "aws",
            "principal_arn": ARN, "last_used_at": T1, "last_used_service": "sts"}
    elsewhere = Credential(**base, usage_snapshot={"collected_account_id": "999999999999", "collected_at": T2.isoformat()})
    assert facts(credential_governance(elsewhere, []))["last_used_at"]["availability"] == "NOT_COLLECTED"
    owner = Credential(**base, usage_snapshot={
        "collected_account_id": "123456789012", "collected_at": T2.isoformat(),
        "last_used": {"status": "AVAILABLE", "at": T1.isoformat(), "service": "sts", "observed_at": T1.isoformat()},
    })
    got = facts(credential_governance(owner, []))
    assert got["last_used_at"]["availability"] == "AVAILABLE" and got["last_used_service"]["value"] == "sts"
    assert got["last_used_at"]["observed_at"] == T1.isoformat()


@pytest.mark.parametrize("status,availability", [
    ("NO_INFORMATION", "NOT_OBSERVED"), ("DENIED", "NOT_COLLECTED"), ("FAILED", "NOT_COLLECTED"),
    ("NOT_REQUESTED", "NOT_COLLECTED"), (None, "NOT_COLLECTED"),
])
@pytest.mark.parametrize("prior_success", [False, True])
def test_last_used_facts_do_not_refresh_historical_native_columns(status, availability, prior_success):
    snapshot = {"collected_account_id": "123456789012", "collected_at": T2.isoformat()}
    if status:
        snapshot["last_used"] = {"status": status, "observed_at": T1.isoformat()}
    cred = Credential(fingerprint="f", credential_type="AWS_ACCESS_KEY", provider="aws", principal_arn=ARN,
                      last_used_at=T1 if prior_success else None,
                      last_used_service="sts" if prior_success else None, usage_snapshot=snapshot)
    got = facts(credential_governance(cred, []))
    assert got["last_used_at"]["availability"] == availability
    assert got["last_used_at"]["value"] is None and "last_used_service" not in got and "last_used_region" not in got
    assert got["last_used_at"]["observed_at"] == (T1.isoformat() if status else None)
    assert got["last_used_at"]["reason"] == (status or "NOT_COLLECTED")


def test_partial_material_is_not_an_active_credential_and_sts_is_not_long_lived():
    # Neither half can be verified: that needs both. But only the secret half is
    # unactionable -- a key is disabled or rotated by its id, which we have.
    for kind, reason, rotation in (("AWS_ACCESS_KEY_ID", "AWS_IDENTIFIER_ONLY", "CONDITIONAL"),
                                   ("AWS_SECRET_ACCESS_KEY", "AWS_SECRET_ONLY", "NOT_SUPPORTED")):
        cred = Credential(id=uuid.uuid4(), fingerprint="synthetic", provider="aws", credential_type=kind,
                          identifier="AKIA" + "Z5X9K2MBV7QP3LN6" if kind == "AWS_ACCESS_KEY_ID" else None)
        view = credential_governance(cred, [])
        assert facts(view)["verification"]["availability"] == "NOT_VERIFIABLE"
        assert facts(view)["verification"]["reason"] == reason
        assert facts(view)["material_completeness"]["value"] == reason
        assert view["type_capability"]["supports_verification"]["documented_support"] == "NOT_SUPPORTED"
        assert view["type_capability"]["supports_rotation"]["documented_support"] == rotation
    # A temporary session credential is no IAM user's access key, id or not.
    session_id = Credential(id=uuid.uuid4(), fingerprint="s", provider="aws", credential_type="AWS_ACCESS_KEY_ID",
                            identifier="ASIA" + "Z5X9K2MBV7QP3LN6")
    assert credential_governance(session_id, [])["type_capability"][
        "supports_rotation"]["documented_support"] == "NOT_SUPPORTED"
    cred = Credential(id=uuid.uuid4(), fingerprint="synthetic", provider="aws", credential_type="AWS_ACCESS_KEY",
                      identifier="ASIA" + "Z5X9K2MBV7QP3LN6")
    view = credential_governance(cred, [exposure("unsupported", verification_error="AWS_STS_SESSION_TOKEN_NOT_BOUND")])
    assert facts(view)["verification"]["reason"] == "AWS_STS_SESSION_TOKEN_NOT_BOUND"
    assert view["type_capability"]["supports_expiration"]["reason"] == "PROVIDER_EXPIRATION_EVIDENCE_REQUIRED"
    assert view["type_capability"]["supports_refresh"]["reason"] == "NEW_STS_SESSION_REQUIRED"


def test_saved_incomplete_sts_rejection_is_reinterpreted_without_overwriting_evidence():
    from cremore.risk.verification import latest_verification

    cred = Credential(id=uuid.uuid4(), fingerprint="synthetic", provider="aws", credential_type="AWS_ACCESS_KEY",
                      identifier="ASIA" + "Z5X9K2MBV7QP3LN6", credential_status="Inactive")
    row = exposure("rejected", catalog_id="aws-access-key-pair-v1", verification_error="InvalidClientTokenId")
    observation = latest_verification([row], cred)
    assert observation.state == "indeterminate" and observation.risk_status == "unknown"
    assert observation.last_confirmed == {}
    assert facts(credential_governance(cred, [row]))["verification"]["value"] == "INCONCLUSIVE"
    assert row.metadata["verification_state"] == "rejected" and cred.credential_status == "Inactive"
    cred.identifier = cred.identifier.replace("ASIA", "AKIA")
    assert latest_verification([row], cred).state == "rejected"


@pytest.mark.parametrize(("state", "material", "expected"), [
    ("verified", "COMPLETE", "VERIFIED_ACTIVE"),
    ("not_attempted", "COMPLETE", "NOT_REQUESTED"),
    ("unsupported", "UNBOUND", "NOT_SUPPORTED"),
])
def test_sts_saved_results_and_conditional_support_do_not_authorize_execution(state, material, expected):
    cred = Credential(id=uuid.uuid4(), fingerprint="synthetic", provider="aws", credential_type="AWS_ACCESS_KEY",
                      identifier="ASIA" + "Z5X9K2MBV7QP3LN6")
    row = exposure(state, aws_session_material=material)
    view = credential_governance(cred, [row])
    assert facts(view)["verification"]["value"] == expected
    assert facts(view)["material_completeness"]["value"] == "AWS_STS_MATERIAL_" + material
    assert view["type_capability"]["supports_verification"] == {
        "documented_support": "CONDITIONAL",
        "reason": "AWS_STS_COMPLETE_SESSION_AND_VERIFICATION_ENABLED_REQUIRED",
    }
    assert view["type_capability"]["execution_authorized"] is False
    if state == "verified":
        assert facts(view)["verification"]["observed_at"] == T1.isoformat()
        assert facts(view)["verification"]["reason"] == "ACTIVE_VERIFICATION_OUTCOME_AT_CHECK_TIME_NOT_CURRENT_USABILITY"


def test_complete_bound_sts_triple_rejection_is_real_and_stands():
    from cremore.risk.verification import latest_verification

    cred = Credential(id=uuid.uuid4(), fingerprint="synthetic", provider="aws", credential_type="AWS_ACCESS_KEY",
                      identifier="ASIA" + "Z5X9K2MBV7QP3LN6")
    # A COMPLETE triple was probed with its session token, so InvalidClientTokenId
    # is a genuine rejection, not the old two-component ambiguity.
    invalid = exposure("rejected", catalog_id="aws-access-key-pair-v1",
                       verification_error="InvalidClientTokenId", aws_session_material="COMPLETE")
    assert latest_verification([invalid], cred).state == "rejected"
    # An expired session is a definite terminal state regardless of binding.
    expired = exposure("rejected", catalog_id="aws-access-key-pair-v1",
                       verification_error="ExpiredToken", aws_session_material="COMPLETE")
    assert latest_verification([expired], cred).state == "rejected"


def test_finding_detail_points_investigations_at_the_owner_account():
    from fastapi.testclient import TestClient

    from cremore.api import create_app
    from cremore.config import Settings
    from cremore.db.repository import InMemoryRepository
    from cremore.domain.models import AwsAccount

    repo = InMemoryRepository()
    owner = repo.create_aws_account(AwsAccount(account_id="123456789012", name="owner"))
    cred = repo.upsert_credential(Credential(fingerprint="f", credential_type="AWS_ACCESS_KEY", provider="aws",
                                             identifier="AKIA" + "A" * 16, principal_arn=ARN, credential_status="Active"))
    exp = repo.upsert_exposure(Exposure(credential_id=cred.id, source_type="s3", resource_name="b", location="k",
                                        last_seen_at=T1, metadata={"verification_state": "verified"}))
    finding = repo.upsert_finding(cred.id, exp.id, "HIGH")
    token = "t" * 40
    c = TestClient(create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=token, FINGERPRINT_KEY="ab" * 32)))
    detail = c.get(f"/api/v1/findings/{finding.id}", headers={"Authorization": f"Bearer {token}"}).json()
    assert detail["aws_account"]["id"] == str(owner.id)
    assert detail["credential"]["governance"]["metadata"][0]["value"] == "VERIFIED_ACTIVE"
    listed = c.get("/api/v1/findings", headers={"Authorization": f"Bearer {token}"}).json()[0]
    assert listed["principal"] == ARN and listed["governance"]["panel_hints"][-1] == "AWS_ACTIVITY"


@pytest.mark.parametrize("kind,identifier,arn", [
    ("AWS_ACCESS_KEY_ID", "AKIA" + "Z5X9K2MBV7QP3LN6", "arn:aws:iam::123456789012:user/ci-deployer"),
    ("AWS_ACCESS_KEY_ID", "AKIA" + "Z5X9K2MBV7QP3LN6", None),
    ("AWS_ACCESS_KEY_ID", "ASIA" + "Z5X9K2MBV7QP3LN6", "arn:aws:iam::123456789012:user/ci-deployer"),
    ("AWS_SECRET_ACCESS_KEY", None, "arn:aws:iam::123456789012:user/ci-deployer"),
    ("AWS_ACCESS_KEY", "AKIA" + "Z5X9K2MBV7QP3LN6", "arn:aws:iam::123456789012:user/ci-deployer"),
])
def test_the_panel_never_offers_an_action_the_remediation_gate_would_refuse(kind, identifier, arn):
    """A projection that says CONDITIONAL where nothing can ever be planned is the
    contradiction this pairing exists to prevent."""
    from cremore.db.repository import InMemoryRepository
    from cremore.remediation.action_plans import ActionPlanService

    cred = Credential(id=uuid.uuid4(), fingerprint=f"fp-{kind}-{identifier}-{arn}", provider="aws",
                      credential_type=kind, identifier=identifier, principal_arn=arn)
    documented = credential_governance(cred, [])["type_capability"]["supports_rotation"]["documented_support"]
    service = ActionPlanService(InMemoryRepository(), Settings(AUTH_MODE="local", API_TOKEN="t" * 32),
                               now=lambda: T1)

    if service.eligible(cred):
        assert documented == "CONDITIONAL", "an actionable key must not be projected as unsupported"
    if documented == "NOT_SUPPORTED":
        assert not service.eligible(cred), "a key projected as unsupported must not be plannable"
