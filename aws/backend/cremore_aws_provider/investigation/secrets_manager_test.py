"""Secrets Manager inventory tests with a fake boto3 client."""

from __future__ import annotations

import datetime as _dt

from cremore_aws_provider.investigation import SecretsManagerService


class FakeSM:
    def __init__(self, pages: list[list[dict]]):
        self.pages = pages
        self.calls = 0
        self.get_value_calls = 0

    def list_secrets(self, MaxResults=100, NextToken=None):
        idx = self.calls
        self.calls += 1
        secrets = self.pages[idx]
        token = "more" if idx + 1 < len(self.pages) else None
        return {"SecretList": secrets, "NextToken": token}

    def get_secret_value(self, **kwargs):  # must never be called by the inventory
        self.get_value_calls += 1
        return {"SecretString": "should-not-be-read"}


class BoomSM:
    def list_secrets(self, **kwargs):
        raise RuntimeError("AccessDenied")


def test_inventory_summarises_without_reading_values():
    now = _dt.datetime(2026, 1, 1, tzinfo=_dt.UTC)
    sm = FakeSM([[
        {"ARN": "arn:aws:secretsmanager:...:secret:db", "Name": "db",
         "RotationEnabled": True, "LastRotatedDate": now,
         "Tags": [{"Key": "team", "Value": "payments"}]},
        {"ARN": "arn:aws:secretsmanager:...:secret:legacy", "Name": "legacy",
         "RotationEnabled": False, "CreatedDate": now},
    ]])
    inv = SecretsManagerService(sm, region="us-east-1").collect()

    assert inv.collection_status == "COMPLETE"
    assert [s.name for s in inv.secrets] == ["db", "legacy"]  # sorted
    db = next(s for s in inv.secrets if s.name == "db")
    assert db.rotation_enabled and db.last_rotated_at == now.isoformat()
    assert db.tag_keys == ("team",)  # key only, never the value
    assert [s.name for s in inv.without_rotation] == ["legacy"]
    assert inv.secrets[1].stale  # legacy has no rotation
    assert sm.get_value_calls == 0  # the inventory never reads a secret's value


def test_pagination_is_followed():
    sm = FakeSM([
        [{"ARN": "a", "Name": "a"}],
        [{"ARN": "b", "Name": "b"}],
    ])
    inv = SecretsManagerService(sm).collect()
    assert sm.calls == 2
    assert {s.name for s in inv.secrets} == {"a", "b"}


def test_failure_is_reported_not_raised():
    inv = SecretsManagerService(BoomSM()).collect()
    assert inv.collection_status == "FAILED"
    assert inv.secrets == []


def test_max_secrets_cap():
    sm = FakeSM([[{"ARN": f"a{i}", "Name": f"a{i}"} for i in range(10)]])
    inv = SecretsManagerService(sm).collect(max_secrets=3)
    assert len(inv.secrets) == 3
    assert inv.collection_status == "PARTIAL" and inv.error_code == "SECRET_LIMIT"


def test_exact_limit_is_complete_only_without_more_pages():
    sm = FakeSM([[{"ARN": "a", "Name": "a"}]])
    assert SecretsManagerService(sm).collect(max_secrets=1).collection_status == "COMPLETE"
    sm = FakeSM([[{"ARN": "a", "Name": "a"}], [{"ARN": "b", "Name": "b"}]])
    assert SecretsManagerService(sm).collect(max_secrets=1).collection_status == "PARTIAL"
