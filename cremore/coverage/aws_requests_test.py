"""The isolated API queues narrow reads; only the collector calls AWS."""
import datetime as dt
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.collectors.base import CollectorError
from cremore.config import Settings
from cremore.coverage import aws_requests
from cremore.coverage.coverage_test import approved_aws
from cremore.coverage.coverage_test import repo as repo  # noqa: PLC0414
from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414
from cremore.db.task_store import TaskStore
from cremore.domain.models import Credential, ScanJob
from cremore.onboarding.session_store import SessionStore
from cremore.worker import JobWorker
from cremore.worker.isolation_test import admission_policy as admission_policy  # noqa: PLC0414

ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:app/key-AbCdEf"
TOKEN = "synthetic-aws-read-" + "a" * 32


class Secrets:
    def __init__(self):
        self.calls = []
        self.before = lambda: None

    def list_secrets(self, **kwargs):
        self.before()
        self.calls.append(("list", kwargs))
        return {"SecretList": [{"ARN": ARN, "Name": "app/key", "Tags": [{"Key": "team", "Value": "omitted"}]}]}

    def describe_secret(self, **kwargs):
        self.before()
        self.calls.append(("describe", kwargs))
        return {"ARN": ARN, "Name": "app/key", "VersionIdsToStages": {}, "Description": "omitted"}

    def list_secret_version_ids(self, **kwargs):
        self.calls.append(("versions", kwargs))
        return {"Versions": []}


@pytest.fixture
def setup(repo, admission_policy):
    account = approved_aws(repo)
    settings = Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32,
                        SECRET_MANAGER_ALLOWED_REFERENCES=ARN).model_copy(update={
                            "isolated_deployment": True, "worker_execution_role": "collector",
                            "sealing_public_keys_file": admission_policy})
    # Use the same setting as the existing live inventory endpoints.
    repo.put_setting("aws_secrets_inventory", {"enabled": True}, "admin")
    cloud = Secrets()
    session = SimpleNamespace(account_id=account.account_id, pin="1:1", via="RUNTIME_IDENTITY",
                              client=lambda *args: cloud,
                              evidence=lambda: {"collected_account_id": account.account_id, "collected_via": "RUNTIME_IDENTITY"})
    sessions = SimpleNamespace(open=lambda *args: session)
    worker = JobWorker(repo, settings=settings, aws_sessions=sessions)
    worker.poll_triggers = lambda: None
    def forbidden(*args, **kwargs):
        pytest.fail("API opened a live AWS service")
    app = create_app(repo=repo, settings=settings, secrets_inventory_factory=forbidden,
                     secret_metadata_factory=forbidden, usage_service_factory=forbidden, aws_sessions=sessions,
                     aws_identity_probe=forbidden, aws_discovery_probe=forbidden, aws_discovery_sweep=forbidden)
    client = TestClient(app, headers={"Authorization": "Bearer " + TOKEN})
    return SimpleNamespace(repo=repo, settings=settings, account=account, client=client, worker=worker, cloud=cloud)


@pytest.mark.parametrize("path,compact", [("/api/v1/aws/secrets-inventory", False),
                                          ("/api/v1/secret-managers/aws/inventory", True)])
def test_inventory_is_queued_polled_and_preserves_public_response(setup, path, compact):
    s = setup
    queued = s.client.get(path)
    assert queued.status_code == 202, queued.text
    assert s.cloud.calls == []
    poll = queued.json()["poll_url"]
    assert s.client.get(poll).status_code == 202
    assert s.worker.process_next()
    response = s.client.get(poll)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 1 and body["secrets"][0]["arn"] == ARN
    assert ("error_code" in body) is (not compact)
    assert "omitted" not in response.text


def test_changed_approval_rejects_work_before_any_cloud_read(setup):
    s = setup
    queued = s.client.get("/api/v1/aws/secrets-inventory").json()
    s.repo.update_aws_account(s.account.id, access_revision=2)
    assert s.worker.process_next()
    assert s.cloud.calls == []
    result = s.client.get(queued["poll_url"])
    assert result.status_code == 409


def test_cancel_during_cloud_read_cannot_commit_public_result(setup):
    s = setup
    queued = s.client.get("/api/v1/aws/secrets-inventory").json()
    job = s.repo.list_jobs()[0]
    s.cloud.before = lambda: s.repo.request_job_cancel(job.id)
    assert s.worker.process_next()
    response = s.client.get(queued["poll_url"])
    assert response.status_code == 409
    assert all(not t.get("result") for t in TaskStore(s.repo).list_for_run(job.id))


def test_result_is_bound_to_requesting_actor_and_operation_whitelist(setup):
    s = setup
    job = aws_requests.enqueue(s.repo, s.settings, "secrets-inventory", "alice", {"account_id": None, "compact": True})
    with pytest.raises(CollectorError, match="AWS_REQUEST_NOT_FOUND"):
        aws_requests.result(s.repo, job.id, "bob")
    with pytest.raises(CollectorError, match="AWS_REQUEST_OPERATION_INVALID"):
        aws_requests.enqueue(s.repo, s.settings, "arbitrary-sdk-command", "alice", {})


def test_missing_worker_identity_never_falls_back_to_api_cloud_identity(setup):
    s = setup
    response = s.client.get("/api/v1/aws/scanner-identity")
    assert response.status_code == 200
    assert response.json()["api"]["error_code"] == "WORKER_IDENTITY_UNKNOWN"
    assert s.client.post("/api/v1/aws/sso-login/start").status_code == 409


def test_authentication_draft_for_remediation_routes_to_remediator(repo):
    draft = SessionStore(repo).create("actor", "binding", {"credential_purpose": "remediator"},
                                     dt.datetime.now(dt.UTC) + dt.timedelta(minutes=10))
    job = repo.enqueue_job(ScanJob(kind="provider-check", payload={"onboarding_session_id": str(draft["id"])}))
    tasks = TaskStore(repo)
    assert tasks.seed_next_job(execution_role="collector") is None
    assert tasks.seed_next_job(execution_role="remediator").id == job.id
    assert tasks.claim(execution_role="collector") is None
    assert tasks.claim(execution_role="remediator")["run_id"] == job.id


def test_exact_secret_metadata_uses_current_mapping_and_drops_external_description(setup):
    s = setup
    credential = s.repo.upsert_credential(Credential(fingerprint="metadata-synthetic", provider="aws",
        credential_type="AWS_ACCESS_KEY", management_reference=ARN, management_revision=1))
    response = s.client.get(f"/api/v1/credentials/{credential.id}/management/metadata")
    assert response.status_code == 202, response.text
    assert s.worker.process_next()
    result = s.client.get(response.json()["poll_url"])
    assert result.status_code == 200, result.text
    assert result.json()["credential_id"] == str(credential.id)
    assert result.json()["reference_revision"] == 1
    assert "omitted" not in result.text


class Organization:
    def __init__(self):
        self.calls = []

    def get_paginator(self, name):
        self.calls.append(name)
        assert name == "list_accounts"
        return SimpleNamespace(paginate=lambda **kw: iter([{"Accounts": [
            {"Id": "210987654321", "Name": "Synthetic team", "State": "ACTIVE"}]}]))

    def describe_organization(self):
        # Optional OU context failure must not falsify the complete account list.
        raise RuntimeError("synthetic unavailable")


def test_discovery_read_and_registration_use_existing_reconciler_with_fenced_writes(setup):
    s = setup
    s.repo.put_setting("aws_org_discovery", {"external_id": "synthetic-external-id"}, "admin")
    org = Organization()
    s.worker.org_client_factory = lambda: org
    response = s.client.get("/api/v1/aws/accounts/discoverable?source=org")
    assert response.status_code == 202, response.text
    assert org.calls == []
    assert s.worker.process_next()
    view = s.client.get(response.json()["poll_url"])
    assert view.status_code == 200, view.text
    assert view.json()["accounts"][0]["account_id"] == "210987654321"
    assert view.json()["accounts"][0]["selectable"] is True
    queued = s.client.post("/api/v1/aws/accounts/discover?source=org")
    assert queued.status_code == 202, queued.text
    assert s.worker.process_next()
    result = s.client.get(queued.json()["poll_url"])
    assert result.status_code == 200, result.text
    assert "210987654321" in result.json()["registered"]
    assert any(account.account_id == "210987654321" for account in s.repo.list_aws_accounts())


def test_discovery_preserves_source_and_runtime_identity_guards(setup):
    s = setup
    s.worker.sso_session_factory = lambda: pytest.fail("SSO must require approved Identity Center identity")
    queued = s.client.get("/api/v1/aws/accounts/discoverable?source=sso")
    assert queued.status_code == 202, queued.text
    assert s.worker.process_next()
    result = s.client.get(queued.json()["poll_url"])
    assert result.json()["available"] is False
    assert result.json()["reason"] == "NOT_AN_IDENTITY_CENTER_IDENTITY"
    assert s.client.post("/api/v1/aws/accounts/discover?source=org").status_code == 409
    s.worker.org_client_factory = lambda: pytest.fail("a changed worker identity must not discover accounts")
    s.worker.aws_identity_probe = lambda: {"state": "READY", "match_key": "another-identity"}
    queued = s.client.get("/api/v1/aws/accounts/discoverable?source=org")
    assert queued.status_code == 202, queued.text
    assert s.worker.process_next()
    assert s.client.get(queued.json()["poll_url"]).status_code == 409


def test_isolated_usage_refresh_always_queues_without_opening_api_session(setup):
    s = setup
    s.repo.put_setting("aws_usage_lookup", {"enabled": True}, "admin")
    credential = s.repo.upsert_credential(Credential(fingerprint="usage-synthetic", provider="aws",
        identifier="AKIA" + "A" * 16, credential_type="AWS_ACCESS_KEY",
        principal_arn="arn:aws:iam::123456789012:user/synthetic", principal_arn_source="STS"))
    response = s.client.post(f"/api/v1/credentials/{credential.id}/usage/refresh")
    assert response.status_code == 202, response.text
    assert s.cloud.calls == []
    job = s.repo.list_jobs()[0]
    assert job.kind == "credential-usage" and job.payload["access_pin"] == "1:1"
