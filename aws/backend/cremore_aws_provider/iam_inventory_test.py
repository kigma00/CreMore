"""Synthetic IAM reads: completeness, identity boundaries and no secret retention."""
import csv
import io
import json
from datetime import UTC, datetime, timedelta

import pytest
from botocore.exceptions import ClientError

from cremore.coverage.collection import CollectionLimit
from cremore.coverage.models import ConnectionSpec
from cremore_aws_provider.iam_inventory import collect_iam
from cremore_aws_provider.investigation.usage import CredentialUsageService, normalize_last_used

ACCOUNT = "123456789012"
USER = f"arn:aws:iam::{ACCOUNT}:user/ci/robot"
ROOT = f"arn:aws:iam::{ACCOUNT}:root"
KEY = "AKIA0123456789ABCDEF"
NOW = datetime(2026, 9, 25, 12, tzinfo=UTC)
SECRET = "ghp_" + "SyntheticRawProviderMaterialNeverStored123"


def spec(**kwargs):
    return ConnectionSpec(name="IAM", provider="aws_iam", account_id=ACCOUNT, **kwargs)


def denied():
    return ClientError({"Error": {"Code": "AccessDenied", "Message": SECRET}}, "GetAccessKeyLastUsed")


def report_bytes(*rows):
    fields = list(dict.fromkeys(key for row in rows for key in row))
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().encode()


def report_row(user="robot", arn=USER, **kwargs):
    return {"user": user, "arn": arn, "user_creation_time": "2024-01-02T03:04:05Z",
            "password_enabled": "true", "mfa_active": "false", "password_last_used": "no_information",
            "password_last_changed": "2025-01-02T03:04:05Z", "password_next_rotation": "not_supported",
            "access_key_1_active": "true", "access_key_1_last_rotated": "2025-02-03T04:05:06Z",
            "access_key_1_last_used_date": "N/A", "access_key_1_last_used_region": "N/A",
            "access_key_1_last_used_service": "N/A", "access_key_2_active": "false",
            "cert_1_active": "true", "cert_1_last_rotated": "2023-01-02T03:04:05Z",
            "cert_2_active": "N/A", **kwargs}


class IAM:
    def __init__(self):
        self.calls = []

    def list_users(self, **kwargs):
        self.calls.append(("users", kwargs))
        return {"Users": [{"UserName": "robot", "Arn": USER}]}

    def list_access_keys(self, **kwargs):
        self.calls.append(("keys", kwargs))
        return {"AccessKeyMetadata": [{"UserName": "robot", "AccessKeyId": KEY,
            "Status": "Active", "CreateDate": NOW - timedelta(days=40)}]}

    def list_service_specific_credentials(self, **kwargs):
        self.calls.append(("service", kwargs))
        second = bool(kwargs.get("Marker"))
        response = {"ServiceSpecificCredentials": [{"UserName": "robot",
            "ServiceSpecificCredentialId": "ACCA" + ("2" if second else "1") * 16,
            "ServiceName": "codecommit.amazonaws.com", "Status": "Active", "ServicePassword": SECRET}]}
        return response if second else response | {"IsTruncated": True, "Marker": "second"}

    def generate_credential_report(self):
        self.calls.append(("generate", {}))
        return {"State": "COMPLETE"}

    def get_credential_report(self):
        self.calls.append(("report", {}))
        return {"GeneratedTime": NOW - timedelta(hours=3),
                "Content": report_bytes(report_row(), report_row("<root_account>", ROOT))}

    def get_access_key_last_used(self, **kwargs):
        self.calls.append(("used", kwargs))
        return {"UserName": "robot", "AccessKeyLastUsed": {"LastUsedDate": NOW - timedelta(hours=2),
                "ServiceName": "s3", "Region": "ap-northeast-2"}, "UnrelatedSecret": SECRET}


def operations(result):
    return {item.operation.name: item.operation for item in result.items if item.evidence == "OPERATION"}


class PolicyIAM(IAM):
    def __init__(self, mode="complete"):
        super().__init__()
        self.mode = mode

    def list_access_keys(self, **kwargs):
        response = super().list_access_keys(**kwargs)
        response["AccessKeyMetadata"].append(response["AccessKeyMetadata"][0] | {"AccessKeyId": "AKIA" + "2" * 16})
        return response

    def __getattr__(self, name):
        def call(**kwargs):
            self.calls.append((name, kwargs))
            if self.mode == "denied" or (self.mode == "partial" and name == "list_groups_for_user"):
                raise denied()
            return {
                "get_user": {"User": {}},
                "list_user_policies": {"PolicyNames": [] if self.mode == "empty" else ["InventoryRead"]},
                "get_user_policy": {"PolicyDocument": {"Statement": [{"Effect": "Allow",
                    "Action": "invalid action" if self.mode == "malformed" else ["s3:GetObject", "aws-portal:ViewBilling"], "Resource": "*",
                    "Condition": {"StringEquals": {"aws:PrincipalTag/private": SECRET}}}]}},
                "list_attached_user_policies": {"AttachedPolicies": []},
                "list_groups_for_user": {"Groups": []},
            }[name]
        return call


@pytest.mark.parametrize("mode,status", [("complete", "COMPLETE"), ("empty", "COMPLETE"),
    ("denied", "DENIED"), ("partial", "PARTIAL"), ("malformed", "FAILED")])
def test_inventory_policy_metadata_is_bounded_sanitized_and_shared_by_a_users_keys(mode, status):
    client = PolicyIAM(mode)
    result = collect_iam(spec(), client, now=NOW, policy_enabled=lambda: True)
    keys = [item for item in result.items if item.evidence == "ISSUED"]
    assert len(keys) == 2 and keys[0].iam_policies == keys[1].iam_policies
    summary = keys[0].iam_policies
    assert summary.status == status
    assert [name for name, _ in client.calls].count("get_user") == 1
    assert result.requests == len(client.calls)
    assert result.status == ("COMPLETE" if status == "COMPLETE" else "PARTIAL")
    if mode in ("complete", "partial"):
        assert summary.allow_actions == ["aws-portal:ViewBilling", "s3:GetObject"] and summary.conditional_statements == 1
        assert summary.policy_names == ["InventoryRead"]
    else:
        assert not summary.allow_actions and not summary.policy_names
    public = json.dumps([item.model_dump() for item in result.items])
    assert SECRET not in public and "PrincipalTag" not in public and "PolicyDocument" not in public


def test_inventory_policy_switch_budget_and_cancellation_stop_requests():
    off = PolicyIAM()
    result = collect_iam(spec(), off, policy_enabled=lambda: False)
    assert result.requests == 2 and all(item.iam_policies is None for item in result.items)
    assert "IAM_IDENTITY_POLICIES" not in operations(result)

    explicit = collect_iam(spec(iam_policy_metadata=True), PolicyIAM(), now=NOW)
    assert operations(explicit)["IAM_IDENTITY_POLICIES"].status == "COMPLETE"
    assert all(i.iam_policies is not None for i in explicit.items if i.evidence == "ISSUED")

    limited = PolicyIAM()
    result = collect_iam(spec(max_requests=3), limited, policy_enabled=lambda: True)
    assert result.requests == len(limited.calls) == 3 and "REQUEST_LIMIT" in result.reasons

    revoked = PolicyIAM()
    result = collect_iam(spec(), revoked, policy_enabled=lambda: len(revoked.calls) < 3)
    assert len(revoked.calls) == 3 and "IAM_POLICY_COLLECTION_DISABLED" in result.reasons

    cancelled = PolicyIAM()
    def checkpoint():
        if len(cancelled.calls) == 3:
            raise RuntimeError("LEASE_LOST")
    with pytest.raises(RuntimeError, match="^LEASE_LOST$"):
        collect_iam(spec(), cancelled, checkpoint=checkpoint, policy_enabled=lambda: True)
    assert len(cancelled.calls) == 3


def test_an_expired_api_key_is_listed_by_its_state_while_an_access_key_status_stays_strict():
    class Expired(IAM):
        def list_service_specific_credentials(self, **kwargs):
            return {"ServiceSpecificCredentials": [{"UserName": "robot", "ServiceSpecificCredentialId": "ACCA" + "3" * 16,
                "ServiceName": "bedrock.amazonaws.com", "Status": "Expired", "ExpirationDate": NOW - timedelta(days=1)}]}

    result = collect_iam(spec(service_credentials=True), Expired(), now=NOW)
    service = next(item for item in result.items if item.credential_type == "AWS_SERVICE_CREDENTIAL")
    assert (service.state, service.service) == ("Expired", "bedrock.amazonaws.com")
    assert operations(result)["LIST_SERVICE_CREDENTIALS"].status == "COMPLETE"

    class Odd(IAM):
        def list_access_keys(self, **kwargs):
            return {"AccessKeyMetadata": [{"UserName": "robot", "AccessKeyId": KEY, "Status": "Expired"}]}

    odd = collect_iam(spec(), Odd(), now=NOW)
    assert odd.status != "COMPLETE" and not any(item.identifier == KEY for item in odd.items)


def test_iam_report_slots_last_used_and_paginated_service_inventory_are_distinct():
    client = IAM()
    result = collect_iam(spec(service_credentials=True, credential_report=True, last_used=True), client, now=NOW)
    assert result.status == "COMPLETE" and not result.reasons
    assert all(op.status == "COMPLETE" for op in operations(result).values())
    assert operations(result)["LIST_SERVICE_CREDENTIALS"].requests == 2
    services = [item for item in result.items if item.credential_type == "AWS_SERVICE_CREDENTIAL"]
    assert len(services) == 2 and len({item.identifier for item in services}) == 2
    key = next(item for item in result.items if item.identifier == KEY)
    assert key.state == "Active" and key.last_used_at == (NOW - timedelta(hours=2)).isoformat()
    assert key.iam_last_used.status == "AVAILABLE" and key.iam_last_used.region == "ap-northeast-2"
    user = next(item for item in result.items if item.evidence == "USER_STATUS")
    assert user.principal_arn == USER and user.password_enabled is True and user.mfa_active is False
    assert not user.identifier and user.iam_report.access_keys[0].slot == 1
    assert user.iam_report.access_keys[0].last_used_at == ""
    assert user.iam_report.access_keys[0].field_status["last_used_at"] == "NOT_APPLICABLE"
    assert user.iam_report.field_status["password_last_used_at"] == "NO_INFORMATION"
    assert user.iam_report.field_status["password_next_rotation_at"] == "NOT_SUPPORTED"
    assert user.iam_report.certificates[0].last_rotated_at == "2023-01-02T03:04:05Z"
    root = next(item for item in result.items if item.evidence == "ROOT_STATUS")
    assert root.created_at == (NOW - timedelta(hours=3)).isoformat()
    assert root.iam_report.generated_at == root.created_at and root.cert_2_active is None
    assert SECRET not in json.dumps([item.model_dump() for item in result.items])
    assert sum(op.requests for op in operations(result).values()) == result.requests == len(client.calls)


def test_empty_account_and_old_options_have_explicit_complete_and_not_requested():
    class Empty:
        def list_users(self, **_):
            return {"Users": []}
    result = collect_iam(spec(), Empty())
    assert result.status == "COMPLETE" and result.requests == 1
    ops = operations(result)
    assert ops["LIST_USERS"].status == ops["LIST_ACCESS_KEYS"].status == "COMPLETE"
    assert ops["LIST_ACCESS_KEYS"].requests == ops["LIST_ACCESS_KEYS"].records == 0
    assert all(ops[name].status == "NOT_REQUESTED" for name in (
        "LIST_SERVICE_CREDENTIALS", "CREDENTIAL_REPORT", "GET_ACCESS_KEY_LAST_USED"))


def test_failed_user_list_can_still_collect_report_but_cannot_claim_key_completeness():
    class DeniedUsers(IAM):
        def list_users(self, **_):
            raise denied()
    result = collect_iam(spec(credential_report=True, last_used=True), DeniedUsers(), now=NOW)
    assert result.status == "PARTIAL"
    ops = operations(result)
    assert ops["LIST_USERS"].status == "FAILED" and ops["LIST_ACCESS_KEYS"].status == "FAILED"
    assert ops["GET_ACCESS_KEY_LAST_USED"].status == "FAILED" and ops["CREDENTIAL_REPORT"].status == "COMPLETE"
    assert "IAM_USER_LIST_DENIED" in result.reasons
    assert SECRET not in json.dumps([item.model_dump() for item in result.items])


@pytest.mark.parametrize("response,expected", [
    ({"AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"}}, "NO_INFORMATION"),
    (denied(), "DENIED"),
    ({"AccessKeyLastUsed": {"LastUsedDate": "bad", "ServiceName": "s3", "Region": "us-east-1"}}, "FAILED"),
])
def test_last_used_missing_denied_or_invalid_preserves_issued_key(response, expected):
    class LastUsed(IAM):
        def get_access_key_last_used(self, **_):
            if isinstance(response, Exception):
                raise response
            return response
    result = collect_iam(spec(last_used=True), LastUsed(), now=NOW)
    key = next(item for item in result.items if item.identifier == KEY)
    assert key.evidence == "ISSUED" and key.state == "Active"
    assert key.iam_last_used.status == expected and key.last_used_at == ""
    assert result.status == ("COMPLETE" if expected == "NO_INFORMATION" else "PARTIAL")


def test_report_pending_only_and_total_record_limit_do_not_claim_complete():
    class Pending(IAM):
        def list_users(self, **_):
            return {"Users": []}
        def generate_credential_report(self):
            return {"State": "INPROGRESS"}
    result = collect_iam(spec(credential_report=True), Pending())
    assert result.status == "FAILED" and "CREDENTIAL_REPORT_PENDING" in result.reasons
    assert operations(result)["CREDENTIAL_REPORT"].status == "FAILED"
    limited = collect_iam(spec(max_records=1), IAM())
    assert len(limited.items) == 1 and limited.status == "PARTIAL"
    assert "OPERATION_REPORT_LIMIT" in limited.reasons


def test_service_truncation_without_marker_and_request_limit_preserve_partial_keys():
    class Truncated(IAM):
        def list_service_specific_credentials(self, **_):
            return {"ServiceSpecificCredentials": [], "IsTruncated": True}
    result = collect_iam(spec(service_credentials=True), Truncated())
    assert result.status == "PARTIAL" and "PAGINATION_INCOMPLETE" in result.reasons
    assert operations(result)["LIST_SERVICE_CREDENTIALS"].status == "FAILED"
    limited = collect_iam(spec(last_used=True, max_requests=2), IAM())
    assert limited.requests == 2 and "REQUEST_LIMIT" in limited.reasons
    assert next(item for item in limited.items if item.identifier == KEY).iam_last_used is None
    assert operations(limited)["GET_ACCESS_KEY_LAST_USED"].status == "FAILED"


def test_bad_report_fields_remain_unknown_and_are_not_false_or_missing_keys():
    class InvalidReport(IAM):
        def get_credential_report(self):
            return {"GeneratedTime": NOW, "Content": report_bytes(
                report_row(password_enabled="invalid", access_key_1_last_used_date="not-a-date"),
                report_row("<root_account>", ROOT))}
    result = collect_iam(spec(credential_report=True), InvalidReport())
    row = next(item for item in result.items if item.evidence == "USER_STATUS")
    assert row.password_enabled is None and not row.identifier
    assert row.iam_report.field_status["password_enabled"] == "INVALID"
    assert row.iam_report.access_keys[0].field_status["last_used_at"] == "INVALID"
    assert "CREDENTIAL_REPORT_INVALID_FIELD" in result.reasons and result.status == "PARTIAL"


def test_foreign_user_and_revoked_checkpoint_never_call_unapproved_user_api():
    class Foreign:
        def list_users(self, **_):
            return {"Users": [{"Arn": USER.replace(ACCOUNT, "999999999999"), "UserName": "robot"}]}
    result = collect_iam(spec(), Foreign())
    assert result.status == "FAILED" and "PROVIDER_SCOPE_MISMATCH" in result.reasons
    client = IAM()
    def stopped():
        raise CollectionLimit("AWS_ACCESS_REVISION_CHANGED")
    cancelled = collect_iam(spec(last_used=True, credential_report=True), client, checkpoint=stopped)
    assert not client.calls and cancelled.status == "FAILED"
    assert all(op.status in ("FAILED", "NOT_REQUESTED") for op in operations(cancelled).values())


def test_investigation_reuses_last_used_normalization_without_claiming_missing_is_unused():
    normalized = normalize_last_used({"ServiceName": "N/A", "Region": "N/A"})
    assert normalized.at is None and normalized.service == normalized.region == ""
    assert normalized.status == "NO_INFORMATION"
    class Invalid:
        def get_access_key_last_used(self, **_):
            return {"AccessKeyLastUsed": {"ServiceName": SECRET, "Region": "us-east-1"}}
    service = CredentialUsageService(lambda _: None, iam_client=Invalid())
    result = service.last_used(KEY)
    assert result.status == "FAILED" and result.error_code == "ValueError" and result.at is None
    assert SECRET not in str(result.snapshot())


def test_user_and_key_pagination_keep_later_users_after_one_user_is_denied():
    class Paged(IAM):
        def list_users(self, **kwargs):
            self.calls.append(("users", kwargs))
            if kwargs.get("Marker"):
                return {"Users": [{"Arn": USER.replace("robot", "denied"), "UserName": "denied"}]}
            return {"Users": [{"Arn": USER, "UserName": "robot"}], "Marker": "users-2", "IsTruncated": True}
        def list_access_keys(self, **kwargs):
            self.calls.append(("keys", kwargs))
            if kwargs["UserName"] == "denied":
                raise denied()
            response = {"AccessKeyMetadata": [{"AccessKeyId": KEY if not kwargs.get("Marker") else "AKIAFEDCBA9876543210", "Status": "Active"}]}
            return response if kwargs.get("Marker") else response | {"Marker": "keys-2", "IsTruncated": True}
    result = collect_iam(spec(), Paged())
    assert len([item for item in result.items if item.evidence == "ISSUED"]) == 2
    ops = operations(result)
    assert ops["LIST_USERS"].status == "COMPLETE" and ops["LIST_USERS"].requests == 2
    assert ops["LIST_ACCESS_KEYS"].status == "PARTIAL" and ops["LIST_ACCESS_KEYS"].requests == 3
    assert "IAM_KEY_LIST_DENIED" in result.reasons


@pytest.mark.parametrize("payload", [{}, {"Users": None}, {"Users": [], "IsTruncated": "false"}])
def test_malformed_listing_is_failed_not_an_empty_complete_inventory(payload):
    class Invalid:
        def list_users(self, **_):
            return payload
    result = collect_iam(spec(), Invalid())
    assert result.status == "FAILED" and operations(result)["LIST_USERS"].status == "FAILED"


def test_report_outside_account_and_invalid_csv_never_emit_user_evidence():
    class InvalidReport(IAM):
        def get_credential_report(self):
            return {"GeneratedTime": NOW, "Content": report_bytes(
                report_row(arn=USER.replace(ACCOUNT, "999999999999")), report_row("<root_account>", ROOT))}
    result = collect_iam(spec(credential_report=True), InvalidReport())
    assert not any(item.evidence == "USER_STATUS" for item in result.items)
    assert "CREDENTIAL_REPORT_INVALID_ROW" in result.reasons


def test_cyclic_service_page_stops_at_shared_request_boundary():
    class Cyclic(IAM):
        def list_service_specific_credentials(self, **_):
            return {"ServiceSpecificCredentials": [], "Marker": "repeat", "IsTruncated": True}
    result = collect_iam(spec(service_credentials=True), Cyclic())
    assert "PAGINATION_LOOP" in result.reasons
    assert operations(result)["LIST_SERVICE_CREDENTIALS"].requests == 2
    assert result.requests == 4


def test_policy_summary_rejects_raw_documents_and_non_issuance_evidence():
    from pydantic import ValidationError

    from cremore.coverage.models import IAMPolicySummary, Observation

    with pytest.raises(ValidationError):
        IAMPolicySummary(status="COMPLETE", checked_at=NOW.isoformat(), PolicyDocument=SECRET)
    with pytest.raises(ValidationError):
        IAMPolicySummary(status="COMPLETE", checked_at=NOW.isoformat(), policy_names=["x"] * 101)
    with pytest.raises(ValidationError, match="IAM_POLICIES_REQUIRE_ISSUED_ACCESS_KEY"):
        Observation(reference=USER, account_id=ACCOUNT, evidence="USER_STATUS",
                    iam_policies=IAMPolicySummary(status="COMPLETE", checked_at=NOW.isoformat()))
