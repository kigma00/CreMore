import datetime as dt

import pytest

from cremore_aws_provider.investigation.secret_metadata import (
    SecretMetadataError,
    SecretMetadataService,
    reference_name,
)

ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:app/db-AbCdEf"
NOW = dt.datetime(2026, 9, 14, tzinfo=dt.UTC)


class Fake:
    def __init__(self, fail=None):
        self.fail = fail

    def describe_secret(self, SecretId):
        if self.fail:
            raise self.fail
        return {"ARN": SecretId, "Name": "app/db", "RotationEnabled": True,
                "RotationLambdaARN": "arn:aws:lambda:us-east-1:123456789012:function:rotate",
                "RotationRules": {"AutomaticallyAfterDays": 30, "ScheduleExpression": "rate(30 days)"},
                "KmsKeyId": "alias/aws/secretsmanager", "CreatedDate": NOW, "LastAccessedDate": NOW,
                "Description": "sensitive text", "Tags": [{"Key": "owner", "Value": "sensitive"}],
                "VersionIdsToStages": {"11111111-1111-4111-8111-111111111111": ["AWSCURRENT"],
                                       "22222222-2222-4222-8222-222222222222": ["AWSPREVIOUS", "LEGACY"]}}

    def list_secret_version_ids(self, SecretId, IncludeDeprecated=True, MaxResults=100, NextToken=None):
        return {"Versions": [{"VersionId": "11111111-1111-4111-8111-111111111111", "VersionStages": ["AWSCURRENT"], "CreatedDate": NOW},
                             {"VersionId": "22222222-2222-4222-8222-222222222222", "VersionStages": ["AWSPREVIOUS", "LEGACY"]}]}


def test_metadata_omits_sensitive_fields_and_never_the_value():
    m = SecretMetadataService(Fake()).describe(ARN)
    assert m["region"] == "us-east-1" and m["account_id"] == "123456789012" and m["reference_name"] == "app/db"
    assert m["current_version_id"] == "11111111-1111-4111-8111-111111111111" and m["rotation_enabled"] is True
    assert m["rotation_rules"]["automatically_after_days"] == 30 and m["rotation_configured"] is True
    assert "description" not in m and "tags" not in m and "SecretString" not in str(m)
    assert m["field_status"]["tags"] == "OMITTED_BY_SECURITY_POLICY" and m["field_status"]["provenance"] == "NOT_COLLECTED"
    assert [v["stages"] for v in m["versions"]] == [["AWSCURRENT"], ["AWSPREVIOUS"]]  # unknown stage labels dropped


def test_describe_failure_is_a_safe_code():
    class Err(Exception):
        def __init__(self):
            super().__init__("synthetic access denial")
            self.response = {"Error": {"Code": "AccessDeniedException"}}

    with pytest.raises(SecretMetadataError) as info:
        SecretMetadataService(Fake(fail=Err())).describe(ARN)
    assert info.value.code == "AccessDeniedException"
    assert reference_name("arn:aws:secretsmanager:us-east-1:123456789012:secret:plain") == "plain"


def test_version_limit_and_cyclic_pages_are_explicitly_incomplete():
    class Incomplete(Fake):
        def list_secret_version_ids(self, **kwargs):
            return {"Versions": [{"VersionId": str(i)} for i in range(100)], "NextToken": "same"}

    with pytest.raises(SecretMetadataError, match="SECRET_VERSION_LIST_INCOMPLETE"):
        SecretMetadataService(Incomplete()).describe(ARN)
