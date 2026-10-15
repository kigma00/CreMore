"""Synthetic evidence joins preserve the difference between IDs, pairs and sessions."""

import json
import uuid
from types import SimpleNamespace

import pytest
from cremore_aws_provider import aws_access

from cremore.api.credential_governance import credential_governance
from cremore.api.finding_evidence import detection_details
from cremore.coverage.correlation import report, scope_revision
from cremore.coverage.hasher import hash_value
from cremore.coverage.models import AWSSession, Batch, ConnectionSpec, Contract, Finish, Observation
from cremore.coverage.store import CoverageStore
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.detection import Engine, ResourceRef
from cremore.detection.engine import EngineConfig
from cremore.domain.models import AwsAccount
from cremore.scanning.orchestrator import Orchestrator

ACCOUNT = "123456789012"
ID = "ASIA" + "Z5X9K2MBV7QP3LN6"
IAM_ID = "AKIA" + "Z5X9K2MBV7QP3LN6"
SECRET = "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4dE6f"
TOKEN = "IQoJb3JpZ2luX2Vj" + "A1b2C3d4E5f6G7h8I9j0K+l/M=n" * 8
OTHER_TOKEN = "IQoJb3JpZ2luX2Vj" + "Z9y8X7w6V5u4T3s2R1q0P+o/N=m" * 8
KEY = b"synthetic-session-fingerprint-domain"
LOCATION = {"reference": f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:synthetic-Ab12Cd",
            "account_id": ACCOUNT, "region": "us-east-1", "version": "v1"}


@pytest.fixture(params=["memory", "sqlite"])
def repo(request):
    if request.param == "memory":
        yield InMemoryRepository()
        return
    database = make_engine("sqlite:///:memory:")
    create_all(database)
    try:
        yield SqlRepository(database)
    finally:
        database.dispose()


@pytest.fixture(scope="module")
def scanner():
    return Engine(EngineConfig(fingerprint_key=KEY))


def material(token=TOKEN, *, identifier=ID):
    fields = {"AccessKeyId": identifier, "SecretAccessKey": SECRET}
    if token is not None:
        fields["SessionToken"] = token
    return json.dumps(fields).encode()


def expose(repo, scanner, data, kind="AWS_ACCESS_KEY"):
    orch = Orchestrator(repo, engine=scanner, config=scanner.config)
    orch.scan_resource(data, ResourceRef(source_type="inline", resource="synthetic", location="input"), verify=False)
    return next(finding for finding in repo.list_findings()
                if repo.get_credential(finding.credential_id).credential_type == kind)


def contract(scanner):
    return Contract(engine_digest=scanner.detection_digest).model_dump()


def save(repo, scanner, spec, items, *, status="COMPLETE", connection=None):
    store = CoverageStore(repo)
    if connection is None:
        connection, _ = store.create(spec, "admin")
    run = store.start(connection["id"], connection["revision"], str(uuid.uuid4()), contract(scanner))
    if items:
        store.append(connection["id"], run["id"], Batch(index=0, items=items))
    store.finish(connection["id"], run["id"], Finish(batch_count=int(bool(items)), item_count=len(items), status=status))
    repo.put_setting("coverage_scope", {"confirmed": True, "revision": scope_revision(store.list_connections())}, "admin")
    return connection


def vault(repo, scanner, data):
    items = hash_value(scanner, data, LOCATION, max_bytes=32768)
    save(repo, scanner, ConnectionSpec(name="Synthetic vault", provider="aws_secrets_manager",
                                     account_id=ACCOUNT, regions=["us-east-1"]), items)
    return items


def finding_report(repo, scanner, finding):
    return report(repo, contract(scanner), finding_id=finding.id)["item"]


def trail(evidence="USAGE", *, identifier=ID, event_id="event-1", source="EVENT_HISTORY"):
    prefix = "trail-s3" if source == "TRAIL_S3" else "event-history"
    return Observation(reference=f"{prefix}/{event_id}", account_id=ACCOUNT, region="us-east-1",
                       evidence=evidence, credential_type="AWS_ACCESS_KEY", identifier=identifier,
                       session=AWSSession(event_id=event_id, event_name="AssumeRole" if evidence == "SESSION_ISSUED" else "ListBuckets",
                                          issuer_account_id=ACCOUNT, evidence_source=source,
                                          event_category="Management", outcome="SUCCEEDED"))


@pytest.mark.parametrize(("exposed_token", "stored_token", "expected"), [
    (TOKEN, TOKEN, "MATCHED"), (TOKEN, OTHER_TOKEN, "PAIR_ONLY"),
    (TOKEN, None, "PAIR_ONLY"), (None, TOKEN, "PAIR_ONLY"),
], ids=["same-session", "different-session", "vault-pair-only", "exposure-pair-only"])
def test_pair_equality_is_not_complete_session_equality(repo, scanner, exposed_token, stored_token, expected):
    finding = expose(repo, scanner, material(exposed_token))
    observations = vault(repo, scanner, material(stored_token))
    item = finding_report(repo, scanner, finding)
    assert item["session_match_state"] == expected
    assert item["state"] == ("MATCHED" if expected == "MATCHED" else "UNKNOWN")
    assert item["match_basis"] == ("SESSION_FINGERPRINT" if expected == "MATCHED" else "KEY_PAIR_FINGERPRINT")
    assert item["locations"][0]["match_basis"] == item["match_basis"]
    assert "TEMPORARY_CREDENTIAL_NOT_EXPECTED_IN_VAULT" in item["reasons"]
    if expected != "MATCHED":
        assert "STS_SESSION_BINDING_NOT_CONFIRMED" in item["reasons"]
    public = json.dumps(item, default=str)
    for observed in observations:
        for value in (SECRET, TOKEN, OTHER_TOKEN, observed.fingerprint, observed.session_fingerprint):
            if value:
                assert value not in public


def test_unbound_rescan_clears_binding_in_both_repositories(repo, scanner):
    finding = expose(repo, scanner, material())
    vault(repo, scanner, material())
    assert finding_report(repo, scanner, finding)["session_match_state"] == "MATCHED"
    expose(repo, scanner, material(None))
    exposures = repo.exposures_for_credential(finding.credential_id)
    assert all(item.metadata["aws_session_material"] == "UNBOUND" for item in exposures)
    assert all("aws_session_fingerprint" not in item.metadata for item in exposures)
    assert finding_report(repo, scanner, finding)["session_match_state"] == "PAIR_ONLY"
    assert TOKEN not in json.dumps([item.model_dump(mode="json") for item in exposures])


@pytest.mark.parametrize("identifier_only", [False, True])
def test_exact_iam_identifier_enriches_exposure_without_secret_or_verification_claim(repo, scanner, identifier_only):
    finding = expose(repo, scanner, IAM_ID.encode() if identifier_only else material(None, identifier=IAM_ID),
                     "AWS_ACCESS_KEY_ID" if identifier_only else "AWS_ACCESS_KEY")
    credential = repo.get_credential(finding.credential_id)
    before = credential.model_dump()
    issuer = Observation(reference=f"arn:aws:iam::{ACCOUNT}:user/synthetic", account_id=ACCOUNT,
                         evidence="ISSUED", credential_type="AWS_ACCESS_KEY", identifier=IAM_ID,
                         state="Active", principal_arn=f"arn:aws:iam::{ACCOUNT}:user/synthetic")
    save(repo, scanner, ConnectionSpec(name="IAM", provider="aws_iam", account_id=ACCOUNT), [issuer])
    item = finding_report(repo, scanner, finding)
    assert item["state"] == "UNKNOWN"
    assert item["match_basis"] == "NONE"
    assert item["inventory_match_count"] == 1
    assert item["inventory_matches"][0]["match_basis"] == "IDENTIFIER"
    assert item["inventory_matches"][0]["principal_arn"] == issuer.principal_arn
    assert repo.get_credential(finding.credential_id).model_dump() == before


def test_sts_usage_and_issuance_are_linked_by_exact_id_with_collection_provenance(repo, scanner):
    finding = expose(repo, scanner, material())
    other_id = "ASIA" + "A1B2C3D4E5F6G7H8"
    save(repo, scanner, ConnectionSpec(name="Trail", provider="aws_cloudtrail", account_id=ACCOUNT, regions=["us-east-1"]),
         [trail("SESSION_ISSUED"), trail(event_id="event-2"), trail(identifier=other_id, event_id="event-3")], status="PARTIAL")
    item = finding_report(repo, scanner, finding)
    assert item["inventory_match_count"] == 2
    assert {row["evidence"] for row in item["inventory_matches"]} == {"SESSION_ISSUED", "USAGE"}
    assert all(row["match_basis"] == "IDENTIFIER" and row["collection_status"] == "PARTIAL"
               and row["current_evidence"] for row in item["inventory_matches"])
    assert item["state"] == "UNKNOWN"


def test_older_inventory_evidence_survives_failed_collection_and_no_match_is_not_foreign(repo, scanner):
    finding = expose(repo, scanner, material())
    assert finding_report(repo, scanner, finding)["inventory_matches"] == []
    spec = ConnectionSpec(name="Trail", provider="aws_cloudtrail", account_id=ACCOUNT, regions=["us-east-1"])
    connection = save(repo, scanner, spec, [trail()])
    save(repo, scanner, spec, [], status="FAILED", connection=connection)
    item = finding_report(repo, scanner, finding)
    assert item["inventory_match_count"] == 1
    assert item["inventory_matches"][0]["current_evidence"] is False
    assert item["inventory_matches"][0]["collection_status"] == "COMPLETE"
    assert "FOREIGN" not in json.dumps(item, default=str)
    assert item["state"] == "UNKNOWN"


def test_unexposed_issued_key_uses_only_identifier_relation_and_honest_absence(repo, scanner):
    vault(repo, scanner, material(None, identifier=IAM_ID))
    issuer = Observation(reference=f"arn:aws:iam::{ACCOUNT}:user/synthetic", account_id=ACCOUNT,
                         evidence="ISSUED", credential_type="AWS_ACCESS_KEY", identifier=IAM_ID)
    save(repo, scanner, ConnectionSpec(name="IAM", provider="aws_iam", account_id=ACCOUNT), [issuer])
    item = next(item for item in report(repo, contract(scanner))["items"] if item["origin"] == "ISSUANCE")
    assert item["state"] == "IDENTIFIER_ONLY"
    assert item["match_basis"] == "IDENTIFIER"
    assert item["exposed"] is False
    assert {"NO_EXPOSURE_OBSERVED", "EXPOSURE_COLLECTION_NOT_PROVEN_COMPLETE", "IDENTIFIER_COMPARISON_ONLY"} <= set(item["reasons"])


def test_issued_keys_are_counted_by_vault_verdict_and_listed_by_origin(repo, scanner):
    vault(repo, scanner, material(None, identifier=IAM_ID))
    issued = [Observation(reference=f"arn:aws:iam::{ACCOUNT}:user/{name}", account_id=ACCOUNT, evidence="ISSUED",
                          credential_type="AWS_ACCESS_KEY", identifier=key)
              for name, key in (("stored", IAM_ID), ("missing", "AKIA" + "Q1W2E3R4T5Y6U7I8"))]
    save(repo, scanner, ConnectionSpec(name="IAM", provider="aws_iam", account_id=ACCOUNT), issued)
    view = report(repo, contract(scanner))
    assert {key: view["summary"][key] for key in ("issued", "issued_in_vault", "issued_not_in_vault", "issued_unknown")} == {
        "issued": 2, "issued_in_vault": 1, "issued_not_in_vault": 1, "issued_unknown": 0}
    assert view["summary"]["no_vault_match"] == 0  # exposure verdicts stay separate
    only = report(repo, contract(scanner), origin="ISSUANCE")
    assert {row["origin"] for row in only["items"]} == {"ISSUANCE"} and only["total"] == 2
    assert only["summary"] == view["summary"]


def test_inventory_links_are_bounded_with_explicit_count(repo, scanner):
    finding = expose(repo, scanner, material())
    save(repo, scanner, ConnectionSpec(name="Trail", provider="aws_cloudtrail", account_id=ACCOUNT, regions=["us-east-1"]),
         [trail(event_id=f"event-{index}") for index in range(101)])
    item = finding_report(repo, scanner, finding)
    assert len(item["inventory_matches"]) == 100
    assert item["inventory_match_count"] == 101
    assert item["inventory_matches_truncated"] is True


def test_standalone_session_token_is_partial_and_not_verifiable(repo, scanner):
    finding = expose(repo, scanner, f"AWS_SESSION_TOKEN={TOKEN}".encode(), "AWS_SESSION_TOKEN")
    vault(repo, scanner, f"AWS_SESSION_TOKEN={TOKEN}".encode())
    item = finding_report(repo, scanner, finding)
    assert item["state"] == "UNKNOWN"
    assert "PARTIAL_AWS_MATERIAL" in item["reasons"]
    facts = credential_governance(repo.get_credential(finding.credential_id), repo.exposures_for_credential(finding.credential_id))
    verification = next(fact for fact in facts["metadata"] if fact["key"] == "verification")
    assert verification["value"] == "NOT_SUPPORTED"
    assert verification["reason"] == "AWS_SESSION_TOKEN_ONLY"
    assert facts["type_capability"]["supports_verification"]["documented_support"] == "NOT_SUPPORTED"


@pytest.mark.parametrize("token", [TOKEN, None], ids=["complete", "unbound"])
def test_finding_public_material_completeness_never_claims_active_verification(repo, scanner, token):
    finding = expose(repo, scanner, material(token))
    credential = repo.get_credential(finding.credential_id)
    exposures = repo.exposures_for_credential(finding.credential_id)
    details = detection_details(exposures[0], credential)
    assert details["aws_session_material"] == ("COMPLETE" if token else "UNBOUND")
    assert "aws_session_fingerprint" not in details
    governance = credential_governance(credential, exposures)
    facts = {fact["key"]: fact for fact in governance["metadata"]}
    assert facts["material_completeness"]["value"] == "AWS_STS_MATERIAL_" + details["aws_session_material"]
    assert facts["verification"]["value"] == "NOT_REQUESTED"
    assert governance["type_capability"]["supports_verification"] == {
        "documented_support": "CONDITIONAL", "reason": "AWS_STS_COMPLETE_SESSION_AND_VERIFICATION_ENABLED_REQUIRED"}


@pytest.mark.parametrize("source", ["EVENT_HISTORY", "TRAIL_S3"])
def test_usage_reason_names_actual_collection_source(repo, scanner, source):
    options = {"cloudtrail_source": "s3", "trail_bucket": "synthetic-trail",
               "trail_prefixes": [f"AWSLogs/{ACCOUNT}/CloudTrail"]} if source == "TRAIL_S3" else {}
    save(repo, scanner, ConnectionSpec(name="Trail", provider="aws_cloudtrail", account_id=ACCOUNT,
                                     regions=["us-east-1"], **options), [trail(source=source)])
    item = next(item for item in report(repo, contract(scanner))["items"] if item["origin"] == "USAGE")
    expected = "BOUNDED_TRAIL_LOG_EVIDENCE" if source == "TRAIL_S3" else "BOUNDED_MANAGEMENT_EVENT_HISTORY"
    assert expected in item["reasons"]


def approved_account(repo, *, pinned=False):
    account = repo.create_aws_account(AwsAccount(
        account_id=ACCOUNT, name="Synthetic approved account", access="RUNTIME_IDENTITY",
        validation_status="VALID", validation_key="1:0" if pinned else "1:1",
        source="ORGANIZATION", org_present=True, org_state="ACTIVE", in_deployment_scope=True))
    if not pinned:
        repo.put_setting(aws_access.APPROVAL_KEYS[aws_access.SCANNER], {"revision": 1}, "admin")
    return account


@pytest.mark.parametrize("provider", ["aws_iam", "aws_cloudtrail"])
@pytest.mark.parametrize(("changes", "reason"), [
    ({"enabled": False}, "ACCOUNT_DISABLED"), ({"org_present": False}, "ORG_ACCOUNT_REMOVED"),
    ({"in_deployment_scope": False}, "OUT_OF_DEPLOYMENT_SCOPE"),
    ({"org_state": "SUSPENDED"}, "ORG_ACCOUNT_SUSPENDED"),
    ({"validation_status": "INVALID"}, "ACCOUNT_NOT_VALIDATED"), ({}, "REVALIDATION_REQUIRED"),
])
def test_revoked_registered_account_lowers_only_inventory_currentness(repo, scanner, provider, changes, reason):
    account = approved_account(repo)
    key_id = IAM_ID if provider == "aws_iam" else ID
    value = material(None if provider == "aws_iam" else TOKEN, identifier=key_id)
    finding = expose(repo, scanner, value)
    vault(repo, scanner, value)
    if provider == "aws_iam":
        options = {}
        observation = Observation(reference=f"arn:aws:iam::{ACCOUNT}:user/synthetic", account_id=ACCOUNT,
                                  evidence="ISSUED", credential_type="AWS_ACCESS_KEY", identifier=key_id)
    else:
        options, observation = {"regions": ["us-east-1"]}, trail()
    connection = save(repo, scanner, ConnectionSpec(name="Inventory", provider=provider, account_id=ACCOUNT, **options),
                      [observation])
    before = finding_report(repo, scanner, finding)
    assert before["inventory_matches"][0]["current_evidence"] is True
    assert before["state"] == "MATCHED"

    if changes:
        repo.update_aws_account(account.id, **changes)
    else:
        repo.put_setting(aws_access.APPROVAL_KEYS[aws_access.SCANNER], {"revision": 2}, "admin")
    after = finding_report(repo, scanner, finding)
    assert after["inventory_match_count"] == before["inventory_match_count"] == 1
    linked = after["inventory_matches"][0]
    assert linked["current_evidence"] is False
    assert linked["access_reasons"] == [reason]
    assert linked["collection_reasons"] == [] and linked["collection_status"] == "COMPLETE"
    assert linked["identifier"] == key_id and linked["match_basis"] == "IDENTIFIER"
    assert after["state"] == before["state"] == "MATCHED"
    assert after["match_basis"] == before["match_basis"]
    assert after["locations"] == before["locations"]
    summary = report(repo, contract(scanner))
    state = next(item for item in summary["connections"] if item["id"] == connection["id"])
    assert state["access_reasons"] == [reason]
    assert summary["scope_reasons"] == []


def test_pinned_scanner_approval_counts_when_settings_are_provided(repo, scanner):
    approved_account(repo, pinned=True)
    finding = expose(repo, scanner, material())
    save(repo, scanner, ConnectionSpec(name="Trail", provider="aws_cloudtrail", account_id=ACCOUNT,
                                     regions=["us-east-1"]), [trail()])
    settings = SimpleNamespace(scanner_principal_arn=f"arn:aws:iam::{ACCOUNT}:role/scanner")
    current = report(repo, contract(scanner), finding_id=finding.id, settings=settings)["item"]["inventory_matches"][0]
    assert current["current_evidence"] is True and current["access_reasons"] == []
    unknown_approval = finding_report(repo, scanner, finding)["inventory_matches"][0]
    assert unknown_approval["current_evidence"] is False
    assert unknown_approval["access_reasons"] == ["IDENTITY_NOT_APPROVED"]


def test_unregistered_external_collector_keeps_its_scoped_fresh_evidence(repo, scanner):
    finding = expose(repo, scanner, material())
    save(repo, scanner, ConnectionSpec(name="External trail", provider="aws_cloudtrail", account_id=ACCOUNT,
                                     regions=["us-east-1"]), [trail()])
    assert not repo.list_aws_accounts()
    linked = finding_report(repo, scanner, finding)["inventory_matches"][0]
    assert linked["current_evidence"] is True and linked["access_reasons"] == []
