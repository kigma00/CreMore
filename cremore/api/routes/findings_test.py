"""Synthetic IAM responses through the synchronous usage persistence boundary."""

import copy
import datetime as dt
import json

import pytest
from cremore_aws_provider.investigation.usage import CredentialUsageService, empty_usage
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.credential_governance import credential_governance
from cremore.api.dashboard_test import (
    TOKEN,
    FakeSessions,
    _aws_key_credential,
    auth,
    switch_investigation_on,
)
from cremore.api.finding_evidence import credential_metadata
from cremore.config import Settings
from cremore.db.repository import InMemoryRepository

OBSERVED = dt.datetime(2026, 10, 2, tzinfo=dt.UTC)
NATIVE = OBSERVED - dt.timedelta(days=1)


@pytest.mark.parametrize("outcome,status,error", [
    ("success", "AVAILABLE", ""), ("no_information", "NO_INFORMATION", ""),
    ("AccessDenied", "DENIED", "AccessDenied"), ("ThrottlingException", "FAILED", "ThrottlingException"),
    ("NoSuchEntity", "FAILED", "NoSuchEntity"), ("malformed", "FAILED", "ValueError"),
    ("not_requested", "NOT_REQUESTED", ""), ("ExpiredToken", "LOGIN", ""),
])
def test_refresh_last_used_preserves_status_and_prior_success(outcome, status, error):
    selected = ["success"]

    class ProviderError(Exception):
        def __init__(self, code):
            self.response = {"Error": {"Code": code, "Message": "RAW_MESSAGE_MUST_NOT_BE_SAVED"}}

    class IAM:
        def get_access_key_last_used(self, **_):
            if selected[0] == "success":
                return {"AccessKeyLastUsed": {"LastUsedDate": NATIVE, "ServiceName": "s3", "Region": "us-east-1"}}
            if selected[0] == "no_information":
                return {"AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"}}
            if selected[0] == "malformed":
                return {"AccessKeyLastUsed": {"LastUsedDate": "RAW_MESSAGE_MUST_NOT_BE_SAVED"}}
            raise ProviderError(selected[0])

    class Usage(CredentialUsageService):
        def collect(self, key_id, principal_arn=""):
            return {**empty_usage(key_id), "collected_at": (OBSERVED + dt.timedelta(days=1)).isoformat()}

    repo = InMemoryRepository()
    switch_investigation_on(repo, "aws_usage_lookup")
    cred = _aws_key_credential(repo)
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32),
                     aws_sessions=FakeSessions("123456789012"), usage_service_factory=lambda _: Usage(
                         lambda _: None, iam_client=None if selected[0] == "not_requested" else IAM(), now=lambda: OBSERVED))
    client = TestClient(app)
    path = f"/api/v1/credentials/{cred.id}/usage"
    first = client.post(path + "/refresh", headers=auth())
    assert first.status_code == 200, first.json()
    assert first.json()["last_used"] == {"status": "AVAILABLE", "observed_at": OBSERVED.isoformat(),
                                         "at": NATIVE.isoformat(), "service": "s3", "region": "us-east-1"}
    previous = copy.deepcopy(repo.get_credential(cred.id).usage_snapshot)
    selected[0] = outcome
    response = client.post(path + "/refresh", headers=auth())
    stored = repo.get_credential(cred.id)
    assert stored.last_used_at == NATIVE and stored.last_used_service == "s3" and stored.last_used_region == "us-east-1"
    if status == "LOGIN":
        assert response.status_code == 409 and "AWS_LOGIN_REQUIRED" in response.json()["error"]
        assert stored.usage_snapshot == previous
        return
    assert response.status_code == 200, response.json()
    expected = {"status": status, "observed_at": OBSERVED.isoformat()}
    if error:
        expected["error_code"] = error
    if status == "AVAILABLE":
        expected.update(at=NATIVE.isoformat(), service="s3", region="us-east-1")
    assert response.json()["last_used"] == stored.usage_snapshot["last_used"] == expected
    assert client.get(path, headers=auth()).json()["last_used"] == expected
    assert "RAW_MESSAGE_MUST_NOT_BE_SAVED" not in json.dumps(stored.usage_snapshot)
    meta = credential_metadata(stored, [])
    fact = next(f for f in credential_governance(stored, [])["metadata"] if f["key"] == "last_used_at")
    if status == "AVAILABLE":
        assert meta["last_used_at"]["at"] == fact["value"] == NATIVE.isoformat()
        assert meta["last_used_at"]["observed_at"] == fact["observed_at"] == OBSERVED.isoformat()
    else:
        expected_availability = "NOT_OBSERVED" if status == "NO_INFORMATION" else "NOT_COLLECTED"
        assert meta["field_status"]["last_used_at"] == fact["availability"] == expected_availability
        assert fact["value"] is None and "last_used_at" not in meta
        assert "last_used_service" not in meta and "last_used_region" not in meta
