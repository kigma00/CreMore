import copy
import datetime as dt
import uuid
from dataclasses import asdict
from urllib.parse import parse_qs, urlparse

import pytest

from cremore.api.finding_evidence import (
    _risk,
    credential_metadata,
    detection_details,
    exposure_path,
    source_location,
)
from cremore.domain.models import Credential, Exposure, Finding
from cremore.risk.model import AWSPrivilegeSignal, ExposureFacts, Facts, Verification

AT = dt.datetime(2026, 9, 15, 12, 54, tzinfo=dt.UTC)
SHA = "a" * 40


def exposure(source_type, resource, location, line=6, **meta):
    if meta.get("verification_state"):
        meta.setdefault("verification_checked_at", AT.isoformat())
    return Exposure(credential_id=uuid.uuid4(), source_type=source_type, resource_name=resource, location=location,
                    line_number=line, last_seen_at=AT, metadata=meta)


def test_new_source_links_preserve_instance_commit_and_literal_object_key():
    row = exposure("gitlab", "7", "src/app env.txt", source_instance="https://gitlab.example.test", gitlab_project_path="org/sub/project")
    row.object_version = SHA
    link = source_location(row)
    assert link["original_link"]["url"] == f"https://gitlab.example.test/org/sub/project/-/blob/{SHA}/src/app%20env.txt#L6"
    row = exposure("confluence", "123", "body", source_instance="https://docs.example.test/confluence")
    assert source_location(row)["original_link"]["url"] == "https://docs.example.test/confluence/pages/viewpage.action?pageId=123"
    row = exposure("gcp", "fixture-bucket", "config/file?#.txt")
    row.object_version = "123"
    assert source_location(row)["original_link"]["url"] == "https://console.cloud.google.com/storage/browser/_details/fixture-bucket/config%2Ffile%3F%23.txt?generation=123"


def test_bitbucket_links_pin_cloud_and_data_center_coordinates():
    for edition, instance, resource, expected in [
        ("cloud", "https://api.bitbucket.org", "team/repo", f"https://bitbucket.org/team/repo/src/{SHA}/src/config%20env.txt#lines-6"),
        ("data_center", "https://code.example.test:8443/bitbucket", "~operator/repo", f"https://code.example.test:8443/bitbucket/projects/~operator/repos/repo/browse/src/config%20env.txt?at={SHA}#6"),
    ]:
        row = exposure("bitbucket", resource, "src/config env.txt", source_instance=instance, bitbucket_edition=edition)
        row.object_version = SHA
        result = source_location(row)
        assert result["original_link"]["url"] == expected and result["original_link"]["historical_content"]
        assert result["source_deployment"] == edition
        row.object_version = "main"
        assert source_location(row)["original_link"]["status"] == "UNAVAILABLE"
    row = exposure("bitbucket", "team/repo", "src/config.txt", source_instance="https://unexpected.example.test", bitbucket_edition="cloud")
    row.object_version = SHA
    assert source_location(row)["original_link"]["status"] == "UNAVAILABLE"


def test_azure_devops_git_links_pin_the_commit_and_tfvc_and_blob_report_no_link():
    for instance, resource, expected in [
        ("https://dev.azure.com", "acme/Platform Team/api",
         f"https://dev.azure.com/acme/Platform%20Team/_git/api?path=/src/app%20env.txt&version=GC{SHA}&_a=contents"),
        ("https://tfs.example.test:8443/tfs", "Default Collection/Platform/api",
         f"https://tfs.example.test:8443/tfs/Default%20Collection/Platform/_git/api?path=/src/app%20env.txt&version=GC{SHA}&_a=contents"),
    ]:
        row = exposure("azure_devops", resource, "src/app env.txt", source_instance=instance)
        row.object_version = SHA
        result = source_location(row)
        assert result["original_link"]["url"] == expected and result["original_link"]["historical_content"]
        assert (result["provider_instance_id"], result["revision_kind"]) == (instance, "COMMIT_SHA")
        row.object_version = "main"
        assert source_location(row)["original_link"]["reason_code"] == "SOURCE_COORDINATES_NOT_RECORDED"
    tampered = exposure("azure_devops", "acme/Platform/api", "a.env", source_instance="http://dev.azure.com")
    tampered.object_version = SHA
    assert source_location(tampered)["original_link"]["status"] == "UNAVAILABLE"
    for row in (exposure("azure_devops", "acme/Platform/$", "src/app.env", source_instance="https://dev.azure.com"),
                exposure("azure_blob", "acmeprod/deploy", "config/app.env")):
        row.object_version = "42"
        link = source_location(row)["original_link"]
        assert (link["status"], link["reason_code"]) == ("UNAVAILABLE", "SOURCE_LINK_NOT_SUPPORTED") and "url" not in link


def test_original_links_open_the_exact_source_for_each_provider():
    s3 = source_location(exposure("s3", "example-scan-bucket", "security-test/a b.txt", region="ap-northeast-2"))
    url = urlparse(s3["original_link"]["url"])
    assert (url.hostname, url.path) == ("s3.console.aws.amazon.com", "/s3/object/example-scan-bucket")
    assert parse_qs(url.query) == {"prefix": ["security-test/a b.txt"], "region": ["ap-northeast-2"]}
    assert s3["coordinate_basis"] == "EXACT_ORIGINAL" and s3["line_start"] == 6 and s3["original_link"]["status"] == "CURRENT_ONLY"

    gh = source_location(exposure("github", "acme/app", "config/prod env.yml", line=12, commit_sha=SHA))
    assert gh["original_link"]["url"] == f"https://github.com/acme/app/blob/{SHA}/config/prod%20env.yml#L12"
    assert gh["original_link"]["historical_content"] is True and gh["revision_kind"] == "COMMIT_SHA"

    notion = source_location(exposure("notion", "Runbook", "https://www.notion.so/x", line=None, page_id="0" * 32))
    assert notion["original_link"]["url"] == "https://www.notion.so/" + "0" * 32

    # no link is invented from coordinates that were never recorded
    assert source_location(exposure("github", "acme/app", "x.py"))["original_link"]["status"] == "UNAVAILABLE"
    assert source_location(exposure("s3", "Bad_Bucket", "k"))["original_link"]["status"] == "UNAVAILABLE"
    decoded = source_location(exposure("s3", "bucket-a", "k", line=None, decoder_type="base64"))
    assert decoded["coordinate_basis"] == "EXTRACTED_TEXT" and "line_start" not in decoded


def test_detection_details_carry_verification_facts_and_the_model_score():
    facts = asdict(Facts(provider="aws", credential_type="AWS_ACCESS_KEY",
                         verification=Verification(status="valid", aws_privilege=AWSPrivilegeSignal(evaluated=True, actions_evaluated=20, account_id="123456789012")),
                         exposure=ExposureFacts(level="internal")))
    facts["verification"]["aws_privilege"]["allowed_risks"] = []
    cred = Credential(id=uuid.uuid4(), fingerprint="fp", credential_type="AWS_ACCESS_KEY", provider="aws")
    e = exposure("s3", "bucket-a", "k", verification_state="verified", verification_arn="arn:aws:iam::123456789012:user/t",
                 verification_account="123456789012", verification_user_id="AIDA", risk_facts=facts, exposure="internal",
                 catalog_id="aws-access-key")
    d = detection_details(e, cred)
    assert d["verification_state"] == "verified" and d["verification_checked_at"] == AT.isoformat()
    assert d["verification_owner_name"].endswith(":user/t") and d["aws_account_id"] == "123456789012"
    assert isinstance(d["risk_score"], int) and d["risk_policy"].startswith("cremore-explainable-risk-")
    assert [row.split(" ")[0] for row in d["risk_evidence"]] == ["exploitability", "credential_impact", "privilege_scope", "exposure"]
    assert all(row.split(" ")[1].count("/") == 1 for row in d["risk_evidence"]) and d["severity_basis"] == "risk_model"
    # an exposure without stored facts is not given a made-up score
    assert "risk_score" not in detection_details(exposure("s3", "bucket-a", "k"), cred)


def test_later_owner_account_simulation_updates_risk_without_authenticating_the_key():
    from cremore_aws_provider.investigation.potential_access import ACTION_CATALOG

    from cremore.api.finding_presenters import present_finding
    from cremore.risk.verification import latest_verification

    arn = "arn:aws:iam::123456789012:user/ci"
    facts = Facts(provider="aws", credential_type="AWS_ACCESS_KEY_ID", exposure=ExposureFacts(level="internal"))
    cred = Credential(id=uuid.uuid4(), fingerprint="test-fp", credential_type="AWS_ACCESS_KEY_ID", provider="aws", principal_arn=arn)
    row = exposure("notion", "PoC", "page", exposure="internal", risk_facts=asdict(facts), catalog_id="aws-access-key-id")
    row.id = uuid.uuid4()
    initial = _risk(row, cred)
    simulation = {"principal_arn": arn, "collection_status": "COMPLETE", "assessment_version": 2,
                  "evaluated_at": AT.isoformat(),
                  "actions": [{"action": action, "decision": "ALLOWED", "risk": "READ"} for action, _ in ACTION_CATALOG]}
    snapshot = {"collected_account_id": "123456789012", "potential_access": simulation}
    cred.usage_snapshot = copy.deepcopy(snapshot)
    current = _risk(row, cred)
    assert "privilege_scope 20/20 aws_iam_privilege_escalation_allowed" in current["risk_evidence"]
    assert current["risk_score"] > initial["risk_score"]
    assert current["risk_evidence"][0] == initial["risk_evidence"][0]
    assert "aws_secret_component_not_observed" in current["risk_missing_evidence"]
    assert latest_verification([row], cred).state == "not_attempted"
    finding = Finding(credential_id=cred.id, primary_exposure_id=row.id, severity="LOW")
    assert present_finding(finding, cred, [row])["severity"] == current["effective_severity"]
    # Neither another account/principal nor incomplete/failed decisions can upgrade the score.
    for field, value in (("collected_account_id", "999999999999"), ("principal_arn", arn + "-other"),
                         ("collection_status", "PARTIAL"), ("collection_status", "FAILED"),
                         ("assessment_version", None), ("actions", [])):
        cred.usage_snapshot = copy.deepcopy(snapshot)
        target = cred.usage_snapshot if field == "collected_account_id" else cred.usage_snapshot["potential_access"]
        target[field] = value
        assert _risk(row, cred)["risk_score"] == initial["risk_score"]
    # A later dated check takes precedence over an older usage simulation.
    cred.usage_snapshot = snapshot
    row.metadata.update(verification_state="indeterminate", verification_checked_at=(AT + dt.timedelta(days=1)).isoformat())
    assert not any("privilege_escalation_allowed" in e for e in _risk(row, cred)["risk_evidence"])


def test_permission_stage_does_not_count_a_failed_policy_read_as_observed():
    cred = Credential(fingerprint="f", credential_type="AWS_ACCESS_KEY_ID", provider="aws")
    def stage(metadata):
        return next(s for s in exposure_path(cred, [], metadata=metadata)["stages"] if s["stage"] == "PRIVILEGED")
    assert stage({"identity_policies": {"collection_status": "FAILED"}})["state"] == "NOT_COLLECTED"
    result = stage({"potential_access": {"collection_status": "PARTIAL", "actions": [{"decision": "ALLOWED"}]}})
    assert result["state"] == "OBSERVED" and result["source"] == "IAM_SIMULATE_PRINCIPAL_POLICY"
    assert result["collection_status"] == "PARTIAL" and result["allowed_actions"] == 1


def test_credential_metadata_for_github_notion_and_aws():
    gh = Credential(id=uuid.uuid4(), fingerprint="f", credential_type="GITHUB_TOKEN", provider="github", identifier_hint="ghp_••••")
    meta = credential_metadata(gh, [exposure("github", "acme/app", "x", verification_state="verified", verification_scopes="repo, read:org",
                                            verification_owner_name="octo", verification_owner_id="42", verification_owner_kind="User",
                                            verification_expires_at="2026-12-01T09:30:00+00:00")])
    assert meta["principal_name"] == "octo" and meta["scopes"] == ["repo", "read:org"] and meta["scope_source"] == "PROVIDER_RESPONSE"
    assert meta["expires_at"]["at"].startswith("2026-12-01") and meta["credential_variant"] == "github.pat.classic"

    notion = Credential(id=uuid.uuid4(), fingerprint="f", credential_type="NOTION_TOKEN", provider="notion")
    meta = credential_metadata(notion, [exposure("notion", "p", "u", verification_state="verified", verification_owner_name="CreMore bot",
                                                verification_owner_kind="bot")])
    assert meta["principal_name"] == "CreMore bot" and meta["field_status"]["scopes"] == "NOT_EXPOSED_BY_PROVIDER"
    # no scopes and probing not run: the capability field says so
    assert meta["field_status"]["capabilities"] == "NOT_PROBED"
    # capability probe results, when present, are parsed and bounded
    probed = credential_metadata(notion, [exposure("notion", "p", "u", verification_state="verified", verification_owner_name="bot",
        verification_capabilities='[{"name":"read_shared_content","status":"ALLOWED","count":3},{"name":"x","status":"nonsense"},{"bad":1}]')])
    assert probed["capabilities"] == [{"name": "read_shared_content", "status": "ALLOWED", "count": 3}, {"name": "x", "status": "UNKNOWN"}]
    assert probed["capability_source"] == "TOKEN_PROBE" and "capabilities" not in probed["field_status"]
    # a rejected or unsupported check says why a field is empty instead of "not collected"
    revoked = credential_metadata(gh, [exposure("github", "acme/app", "x", verification_state="rejected")])["field_status"]
    assert revoked["expires_at"] == revoked["scopes"] == revoked["created_at"] == "NOT_RETURNED"
    generic = Credential(id=uuid.uuid4(), fingerprint="f", credential_type="GENERIC_PASSWORD", provider="generic")
    assert credential_metadata(generic, [exposure("github", "acme/app", "x", verification_state="unsupported")])["field_status"]["scopes"] == "NOT_SUPPORTED"

    arn = "arn:aws:iam::123456789012:user/scanner-test-user"
    aws = Credential(id=uuid.uuid4(), fingerprint="f", credential_type="AWS_ACCESS_KEY", provider="aws", identifier_hint="AKIA••••DRZE",
                     principal_arn=arn, last_used_at=AT, last_used_service="sts", usage_snapshot={
                         "collected_account_id": "123456789012", "collected_at": AT.isoformat(),
                         "access_key": {"status": "Active", "created_at": "2026-09-01T00:00:00+00:00"},
                         "events": [{"event_time": "2026-09-12T14:36:00+00:00", "outcome": "SUCCEEDED"}],
                         "potential_access": {"principal_arn": arn, "collection_status": "COMPLETE", "actions": []},
                         "identity_policies": {"principal_arn": arn, "collection_status": "COMPLETE", "summary": {"deny_all_policies": ["DenyEverything"]}}})
    e = exposure("s3", "bucket-a", "k", verification_state="verified", verification_arn=arn, verification_user_id="AIDA")
    meta = credential_metadata(aws, [e])
    assert meta["principal_arn"] == arn and meta["provider_status"] == "ACTIVE"
    assert meta["created_at"]["source"] == "IAM_ACCESS_KEYS" and meta["last_observed_use_at"]["at"].startswith("2026-09-12")
    assert meta["potential_access"]["collection_status"] == "COMPLETE" and meta["field_status"]["expires_at"] == "NOT_APPLICABLE"
    assert meta["identity_policies"]["summary"]["deny_all_policies"] == ["DenyEverything"]
    # Aggregate evidence must not shrink to the retained recent detail sample.
    from cremore.api.finding_evidence import _used_stage

    aws.usage_snapshot.update(events=[{"outcome": "DENIED"}], summary={
        "events": 10051, "denied": 100, "techniques": {"T1619": 10051},
        "last_success": "2026-09-11T14:36:00+00:00"})
    meta = credential_metadata(aws, [e])
    assert meta["last_observed_use_at"]["at"] == "2026-09-11T14:36:00+00:00"
    used = _used_stage(aws, meta, meta["field_status"])
    assert used["events"] == 10051 and used["denied_events"] == 100
    assert used["techniques"][0]["events"] == 10051
    # the same lookup recorded for another account is not metadata for this key
    aws.usage_snapshot = {**aws.usage_snapshot, "collected_account_id": "999999999999"}
    meta = credential_metadata(aws, [e])
    assert "created_at" not in meta and meta["field_status"]["created_at"] == "NOT_COLLECTED"
    assert "identity_policies" not in meta and meta["field_status"]["identity_policies"] == "NOT_COLLECTED"


@pytest.mark.parametrize("status,expected", [
    ("NO_INFORMATION", "NOT_OBSERVED"), ("DENIED", "NOT_COLLECTED"), ("FAILED", "NOT_COLLECTED"),
    ("NOT_REQUESTED", "NOT_COLLECTED"), (None, "NOT_COLLECTED"),
])
@pytest.mark.parametrize("prior_success", [False, True])
def test_last_used_metadata_requires_current_iam_status(status, expected, prior_success):
    snapshot = {"collected_account_id": "123456789012", "collected_at": (AT + dt.timedelta(days=1)).isoformat()}
    if status:
        snapshot["last_used"] = {"status": status, "observed_at": AT.isoformat()}
    cred = Credential(fingerprint="f", credential_type="AWS_ACCESS_KEY", provider="aws",
                      principal_arn="arn:aws:iam::123456789012:user/test",
                      last_used_at=AT if prior_success else None,
                      last_used_service="sts" if prior_success else None, usage_snapshot=snapshot)
    meta = credential_metadata(cred, [])
    assert meta["field_status"]["last_used_at"] == expected
    assert not {"last_used_at", "last_used_service", "last_used_region"} & meta.keys()
    assert "IAM_GET_ACCESS_KEY_LAST_USED_" + (status or "NOT_COLLECTED") in meta["limitations"]


def test_last_used_metadata_keeps_iam_observation_time_separate_from_cloudtrail():
    native = AT - dt.timedelta(days=2)
    cred = Credential(fingerprint="f", credential_type="AWS_ACCESS_KEY", provider="aws",
                      principal_arn="arn:aws:iam::123456789012:user/test", last_used_at=AT,
                      last_used_service="old-service", usage_snapshot={
                          "collected_account_id": "123456789012", "collected_at": (AT + dt.timedelta(days=1)).isoformat(),
                          "last_used": {"status": "AVAILABLE", "observed_at": AT.isoformat(), "at": native.isoformat(),
                                        "service": "s3", "region": "us-east-1"},
                      })
    meta = credential_metadata(cred, [])
    assert meta["last_used_at"] == {"at": native.isoformat(), "source": "IAM_ACCESS_KEY_METADATA",
                                    "observed_at": AT.isoformat()}
    assert meta["last_used_service"] == "s3" and meta["last_used_region"] == "us-east-1"


def test_access_key_metadata_reads_only_this_key():
    from cremore.api.dashboard import _access_key_metadata

    class IAM:
        def list_access_keys(self, UserName):
            assert UserName == "scanner-test-user"
            return {"AccessKeyMetadata": [{"AccessKeyId": "AKIAOTHER", "Status": "Inactive"},
                                          {"AccessKeyId": "AKIATHIS", "Status": "Active", "CreateDate": AT}]}

    session = type("S", (), {"client": lambda self, service: IAM()})()
    cred = Credential(fingerprint="f", credential_type="AWS_ACCESS_KEY", identifier="AKIATHIS",
                      principal_arn="arn:aws:iam::123456789012:user/scanner-test-user")
    assert _access_key_metadata(session, cred) == {"collection_status": "COMPLETE", "status": "Active", "created_at": AT.isoformat()}
    role = Credential(fingerprint="f", credential_type="AWS_ACCESS_KEY", identifier="ASIA", principal_arn="arn:aws:sts::1:assumed-role/r/s")
    assert _access_key_metadata(session, role) == {"collection_status": "NOT_APPLICABLE"}


def test_overlapping_connections_show_one_location_in_list_detail_and_score():
    from fastapi.testclient import TestClient

    from cremore.api import create_app
    from cremore.config import Settings
    from cremore.db.repository import InMemoryRepository

    repo = InMemoryRepository()
    cred = repo.upsert_credential(Credential(fingerprint="f", credential_type="DB_CONNECTION_STRING", provider="generic"))
    facts = asdict(Facts(provider="generic", credential_type="DB_CONNECTION_STRING",
                         verification=Verification(status="unsupported"), exposure=ExposureFacts(level="internal", occurrences=2)))
    account, single = uuid.uuid4(), uuid.uuid4()
    rows = [repo.upsert_exposure(Exposure(credential_id=cred.id, source_connection_id=c, source_type="github", resource_name="jun/app",
                                          location=".env.example", line_number=10, severity="LOW",
                                          metadata={"exposure": "internal", "risk_facts": facts, "catalog_id": "db"}))
            for c in (single, account)]
    finding = repo.upsert_finding(cred.id, rows[0].id, "LOW")
    token = "t" * 40
    c = TestClient(create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=token, FINGERPRINT_KEY="ab" * 32)))
    headers = {"Authorization": f"Bearer {token}"}
    assert c.get("/api/v1/findings", headers=headers).json()[0]["exposure_count"] == 1
    detail = c.get(f"/api/v1/findings/{finding.id}", headers=headers).json()
    assert len(detail["exposures"]) == 1 and detail["primary_exposure_id"] == detail["exposures"][0]["id"]
    assert detail["exposures"][0]["source_connection_ids"] == sorted([str(account), str(single)])
    # the score is not raised by a second connection finding the same place
    assert not any("multiple_occurrences" in row for row in detail["exposures"][0]["detection_details"]["risk_evidence"])


def test_the_latest_observation_stands_for_a_location():
    from cremore.api.finding_evidence import merged_locations

    stale = exposure("github", "jun/app", ".env")
    removed = stale.model_copy(update={"id": uuid.uuid4(), "status": "REMOVED", "removed_at": AT + dt.timedelta(hours=1)})
    other = exposure("github", "jun/app", "config.py")
    merged = merged_locations([stale, other, removed])
    assert [(e.id, len(rows)) for e, rows in merged] == [(removed.id, 2), (other.id, 1)]

def test_github_source_link_and_verification_host_follow_the_enterprise_host():
    gh = source_location(exposure("github", "team/app", "src/x.py", line=5, commit_sha=SHA, github_host="ghe.example.com"))
    assert gh["original_link"]["url"] == f"https://ghe.example.com/team/app/blob/{SHA}/src/x.py#L5"
    assert gh["provider_instance_id"] == "https://ghe.example.com/api/v3"
    # github.com stays the default
    pub = source_location(exposure("github", "team/app", "src/x.py", line=5, commit_sha=SHA))
    assert pub["original_link"]["url"].startswith("https://github.com/team/app/blob/")
    cred = Credential(id=uuid.uuid4(), fingerprint="f", credential_type="GITHUB_TOKEN", provider="github", identifier_hint="ghp_x")
    meta = credential_metadata(cred, [exposure("github", "team/app", "x", verification_state="verified",
                                              verification_owner_name="octo", verification_host="ghe.example.com")])
    assert meta["verification_host"] == "ghe.example.com"


def _path(cred, rows, **kwargs):
    return {stage["stage"]: stage for stage in exposure_path(
        cred, rows, metadata=credential_metadata(cred, rows), **kwargs)["stages"]}


def test_exposure_path_separates_looked_and_found_nothing_from_never_looked():
    cred = Credential(fingerprint="f", credential_type="AWS_ACCESS_KEY", provider="aws", identifier_hint="AKIA")
    public = exposure("github", "org/app", "app.env", exposure="public")
    internal = exposure("s3", "bucket", "conf.yml", exposure="internal")
    internal.first_seen_at = AT - dt.timedelta(days=3)
    stages = _path(cred, [public, internal])

    assert stages["EXPOSED"]["state"] == "OBSERVED" and stages["EXPOSED"]["locations"] == 2
    assert stages["EXPOSED"]["first_seen_at"].startswith("2026-09-12")
    # The most reachable location decides, and one public location is enough.
    assert stages["REACHABLE"]["state"] == "OBSERVED" and stages["REACHABLE"]["level"] == "PUBLIC"
    assert stages["REACHABLE"]["public_locations"] == 1
    # Nothing was verified, no policy was read and no use was looked up: each
    # stage says it was not collected rather than reading as nothing happened.
    assert stages["USABLE"]["state"] == "NOT_COLLECTED" and stages["USABLE"]["outcome"] == "NOT_ATTEMPTED"
    assert stages["PRIVILEGED"]["state"] == "NOT_COLLECTED"
    assert stages["USED"]["state"] == "NOT_COLLECTED" and stages["USED"]["events"] == 0
    # The locations are still there, which is observed, not uncollected.
    assert stages["REMOVED"]["state"] == "NOT_OBSERVED" and stages["REMOVED"]["outcome"] == "STILL_PRESENT"

    # A location whose reachability could not be read is undetermined, never internal.
    unknown = _path(cred, [exposure("s3", "bucket", "conf.yml")])["REACHABLE"]
    assert unknown["state"] == "UNDETERMINED" and unknown["level"] == "UNKNOWN" and unknown["undetermined_locations"] == 1


def test_exposure_path_carries_quarantine_use_and_removal():
    arn = "arn:aws:iam::123456789012:user/ci"
    cred = Credential(fingerprint="f", credential_type="AWS_ACCESS_KEY", provider="aws", identifier_hint="AKIA",
                      principal_arn=arn, last_used_at=AT, usage_snapshot={
                          "collected_account_id": "123456789012", "collected_at": AT.isoformat(),
                          "access_key": {"status": "Active"},
                          "events": [{"event_name": "CreateAccessKey", "event_time": AT.isoformat(), "outcome": "SUCCEEDED"},
                                     {"event_name": "StopLogging", "event_time": AT.isoformat(), "outcome": "DENIED"},
                                     {"event_name": "PutMetricData", "event_time": AT.isoformat(), "outcome": "SUCCEEDED"}],
                          "identity_policies": {"principal_arn": arn, "collection_status": "COMPLETE", "summary": {
                              "quarantine_policies": ["AWSCompromisedKeyQuarantineV3"],
                              "allow_all_policies": [], "deny_all_policies": []}}})
    row = exposure("github", "org/app", "app.env", exposure="public", verification_state="verified")
    row.removed_at = AT
    finding = Finding(credential_id=uuid.uuid4(), primary_exposure_id=uuid.uuid4(), severity="HIGH",
                      all_locations_removed=True)
    stages = _path(cred, [row], finding=finding)

    assert stages["USABLE"]["state"] == "OBSERVED" and stages["USABLE"]["outcome"] == "VALID"
    # The attached policy is an observed principal policy, not proof this key leaked.
    assert stages["PRIVILEGED"]["quarantine_policies"] == ["AWSCompromisedKeyQuarantineV3"]
    used = stages["USED"]
    assert used["state"] == "OBSERVED" and used["events"] == 3 and used["denied_events"] == 1
    # Only the calls that match a technique are named; PutMetricData is not one.
    assert [t["technique_id"] for t in used["techniques"]] == ["T1098.001", "T1562.008"]
    assert stages["REMOVED"]["state"] == "OBSERVED" and stages["REMOVED"]["removed_locations"] == 1

    # A lookup that ran and found no call is NOT_OBSERVED, never NOT_COLLECTED.
    cred.usage_snapshot = {**cred.usage_snapshot, "collection_status": "COMPLETE", "events": []}
    assert _path(cred, [row])["USED"]["state"] == "NOT_OBSERVED"
    # A snapshot collected in another account establishes nothing about this key.
    cred.usage_snapshot = {**cred.usage_snapshot, "collected_account_id": "999999999999"}
    assert _path(cred, [row])["USED"]["state"] == "NOT_COLLECTED"


def test_attached_quarantine_policy_does_not_prove_key_exposure():
    """The severity the list sorts by is computed here, so the change shows at once."""

    from dataclasses import asdict

    facts = asdict(Facts(provider="aws", credential_type="AWS_ACCESS_KEY",
                         verification=Verification(status="not_attempted"),
                         exposure=ExposureFacts(level="internal", occurrences=1)))
    row = exposure("s3", "bucket", "conf.yml", catalog_id="aws-access-key", exposure="internal", risk_facts=facts)
    arn = "arn:aws:iam::123456789012:user/ci"
    cred = Credential(fingerprint="f", credential_type="AWS_ACCESS_KEY", provider="aws", principal_arn=arn)

    quiet = _risk(row, cred)
    assert quiet["effective_severity"] == "LOW" and quiet["risk_overrides"] == []

    cred.usage_snapshot = {"collected_account_id": "123456789012", "identity_policies": {
        "summary": {"quarantine_policies": ["AWSCompromisedKeyQuarantineV3"]}}}
    flagged = _risk(row, cred)
    assert flagged == quiet

    # A snapshot collected somewhere other than the key's own account establishes
    # nothing about this key, exactly as it does not for observed use.
    cred.usage_snapshot = {**cred.usage_snapshot, "collected_account_id": "999999999999"}
    assert _risk(row, cred)["effective_severity"] == "LOW"


def test_credential_metadata_reports_what_a_sas_signs_without_claiming_validity():
    sas = Credential(id=uuid.uuid4(), fingerprint="f", credential_type="AZURE_SAS_TOKEN", provider="azure")
    service = credential_metadata(sas, [exposure("github", "acme/app", "deploy.env", azure_sas={
        "account": "myaccount", "kind": "service", "permissions": "rw", "resource": "c", "expiry": "2026-12-01T00:00:00Z"})])
    assert service["expires_at"] == {"at": "2026-12-01T00:00:00Z", "source": "SAS_TOKEN_FIELDS", "observed_at": AT.isoformat()}
    assert service["scopes"] == ["sp=rw", "sr=c"] and service["scope_source"] == "SAS_TOKEN_FIELDS"
    assert service["principal_name"] == "myaccount" and service["principal_kind"] == "STORAGE_ACCOUNT"
    assert "expires_at" not in service["field_status"] and "verification_state" not in service
    delegated = credential_metadata(sas, [exposure("github", "acme/app", "deploy.env", azure_sas={
        "kind": "user_delegation", "signer_object_id": "11111111-2222-3333-4444-555555555555"})])
    assert delegated["principal_id"] == "11111111-2222-3333-4444-555555555555"
    assert delegated["principal_kind"] == "ENTRA_PRINCIPAL" and "expires_at" not in delegated


@pytest.mark.parametrize("status,region_status,expected", [
    ("FAILED", "FAILED", "NOT_COLLECTED"), ("PARTIAL", "PENDING", "NOT_COLLECTED"),
    ("PARTIAL", "CAPPED", "NOT_COLLECTED"), ("PARTIAL", "COMPLETE", "NOT_COLLECTED"),
    ("COMPLETE", "FAILED", "NOT_COLLECTED"), (None, "COMPLETE", "NOT_COLLECTED"),
    ("COMPLETE", "COMPLETE", "NOT_OBSERVED"),
])
def test_empty_usage_requires_complete_collection(status, region_status, expected):
    cred = Credential(fingerprint="f", credential_type="AWS_ACCESS_KEY", provider="aws",
                      principal_arn="arn:aws:iam::123456789012:user/ci", usage_snapshot={
                          "collected_account_id": "123456789012", "collection_status": status,
                          "coverage": [{"region": "us-east-1", "status": region_status}],
                          "events": [], "summary": {"events": 0}})
    metadata = credential_metadata(cred, [])
    assert metadata["field_status"]["last_observed_use_at"] == expected
    stage = _path(cred, [])["USED"]
    assert stage["state"] == expected and stage["events"] == 0
    if expected == "NOT_COLLECTED":
        assert stage["reason"] == ("PARTIAL" if status == "COMPLETE" else status or "NOT_COLLECTED")


@pytest.mark.parametrize("outcome", ["SUCCEEDED", "DENIED", "UNKNOWN"])
def test_partial_usage_preserves_positive_events_without_claiming_success(outcome):
    cred = Credential(fingerprint="f", credential_type="AWS_ACCESS_KEY", provider="aws",
                      principal_arn="arn:aws:iam::123456789012:user/ci", usage_snapshot={
                          "collected_account_id": "123456789012", "collection_status": "PARTIAL",
                          "events": [{"event_time": AT.isoformat(), "outcome": outcome}]})
    assert _path(cred, [])["USED"]["state"] == "OBSERVED"
    metadata = credential_metadata(cred, [])
    assert ("last_observed_use_at" in metadata) == (outcome == "SUCCEEDED")
    cred.usage_snapshot["collected_account_id"] = "999999999999"
    assert _path(cred, [])["USED"]["state"] == "NOT_COLLECTED"
