"""A server-collected AWS secret store with a value-reader role: every value is read through that
role, which is assumed again before its chained credentials expire. Fake sessions only."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cremore_aws_provider import aws_access
from cremore_aws_provider.aws_identity import AwsLoginRequired
from cremore_aws_provider.aws_readonly import VAULT_OPERATIONS, readonly_client

from cremore.coverage import JOB_KIND
from cremore.coverage.models import ConnectionSpec
from cremore.coverage.store import CoverageStore
from cremore.db.repository import InMemoryRepository
from cremore.detection.engine import EngineConfig
from cremore.domain.models import AwsAccount, ScanJob
from cremore.scanning.orchestrator import Orchestrator
from cremore.worker.worker import JobWorker

KEY = b"k" * 32
ACCOUNT = "123456789012"
FIRST = f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:app/db-Ab12Cd"
SECOND = f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:app/api-Ef34Gh"
GH = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"
NOW = datetime(2026, 10, 8, tzinfo=UTC)
SPECS = {
    "aws_secrets_manager": {"provider": "aws_secrets_manager", "references": [FIRST, SECOND]},
    # Two paths: two requests, the second after the first has taken eleven of the reader's fifteen minutes.
    "aws_ssm": {"provider": "aws_ssm", "prefixes": ["prod", "stage"]},
}


def run(provider="aws_secrets_manager", *, first=None, renew=None, refusal=None):
    """One collection whose first read takes eleven minutes of the reader's fifteen.

    ``first``/``renew``: the first/second value_reader() call raises it (an exception) or reports it as its
    pin (a string). ``refusal``: what the run's checkpoint hears from sessions.refusal()."""
    repo = InMemoryRepository()
    repo.create_aws_account(AwsAccount(account_id=ACCOUNT, name="Synthetic", access="RUNTIME_IDENTITY",
                                       validation_status="VALID", validation_key="1:1"))
    repo.put_setting(aws_access.APPROVAL_KEYS[aws_access.SCANNER], {"revision": 1}, "admin")
    clock, opened, reads = [NOW], [], []

    class Store:
        def __init__(self, creds):
            self.creds = creds

        def get_secret_value(self, **kwargs):
            reads.append((kwargs["SecretId"], self.creds["AccessKeyId"]))
            clock[0] += timedelta(minutes=11)
            return {"ARN": kwargs["SecretId"], "VersionId": "a" * 32, "VersionStages": ["AWSCURRENT"], "SecretString": GH}

        def get_parameters_by_path(self, **kwargs):
            reads.append((kwargs["Path"], self.creds["AccessKeyId"]))
            clock[0] += timedelta(minutes=11)
            name = kwargs["Path"] + "/db"
            return {"Parameters": [{"ARN": f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter{name}", "Version": 1, "Value": GH}]}

    def value_reader(account_id, role, label):
        opened.append((account_id, role, label))
        given = first if len(opened) == 1 else renew if len(opened) == 2 else None
        if isinstance(given, Exception):
            raise given
        creds = {"AccessKeyId": f"reader-{len(opened)}", "Expiration": clock[0] + timedelta(minutes=15)}

        def client(service, region=None, *, operations=None):
            assert operations is VAULT_OPERATIONS
            return readonly_client(Store(creds), service, operations)
        return SimpleNamespace(pin=given if isinstance(given, str) else "1:1", credentials=creds, client=client)

    def scanner_client(*_args, **_kwargs):
        raise AssertionError("the scanner session reads no value")

    account = repo.list_aws_accounts()[0]
    sessions = SimpleNamespace(open=lambda *_: SimpleNamespace(pin="1:1", client=scanner_client),
                               refusal=lambda *_: (refusal, account, {"revision": 1}),
                               value_reader=value_reader, now=lambda: clock[0])
    store = CoverageStore(repo)
    connection, _ = store.create(ConnectionSpec(name="Store", account_id=ACCOUNT, regions=["us-east-1"],
        server_collection=True, value_reader_role="CredentialVaultValueReaderRole", **SPECS[provider]), "admin")
    job = repo.enqueue_job(ScanJob(kind=JOB_KIND, payload={"provider": "aws", "account_id": ACCOUNT,
        "coverage_connection_id": str(connection["id"]), "coverage_revision": 1, "access_pin": "1:1"}))
    worker = JobWorker(repo, orchestrator=Orchestrator(repo, config=EngineConfig(fingerprint_key=KEY)), aws_sessions=sessions)
    assert worker.process_next()
    return repo, repo.get_job(job.id), store.snapshots(connection["id"]), opened, reads, str(connection["id"])


@pytest.mark.parametrize("provider,first,second", [("aws_secrets_manager", FIRST, SECOND), ("aws_ssm", "/prod", "/stage")])
def test_every_value_is_read_as_the_value_reader_which_is_assumed_again_before_it_expires(provider, first, second):
    repo, job, runs, opened, reads, cid = run(provider)
    assert job.status == "SUCCEEDED", job.error
    [snapshot] = runs
    assert snapshot["status"] == "COMPLETE" and [item["evidence"] for item in snapshot["items"]] == ["VALUE", "VALUE"]
    # Listed secrets are whole by the operator's list, never by a listing; the paths were listed through the API.
    assert snapshot["completeness"] == ("OPERATOR_DECLARED" if provider == "aws_secrets_manager" else "API_LISTING")
    # The second read came within five minutes of the first session's expiry: a new session, a new client.
    assert reads == [(first, "reader-1"), (second, "reader-2")]
    assert opened == [(ACCOUNT, "CredentialVaultValueReaderRole", cid)] * 2
    assert GH not in json.dumps(snapshot, default=str) + json.dumps([j.payload for j in repo.list_jobs()], default=str)


def test_a_reader_that_cannot_be_assumed_fails_the_run_with_its_code():
    _repo, job, runs, opened, reads, _cid = run(first=aws_access.AccessBlocked("VALUE_READER_ASSUME_DENIED"))
    [snapshot] = runs
    assert len(opened) == 1 and reads == [] and job.status == "FAILED"
    assert snapshot["status"] == "FAILED" and snapshot["reasons"] == ["VALUE_READER_ASSUME_DENIED"] and snapshot["items"] == []


@pytest.mark.parametrize("renew,reason", [
    (aws_access.AccessBlocked("VALUE_READER_ASSUME_DENIED"), "VALUE_READER_ASSUME_DENIED"),
    (AwsLoginRequired(), "AWS_LOGIN_REQUIRED"),
    ("2:1", "AWS_ACCESS_REVISION_CHANGED"),  # the account's approval moved between the two sessions
])
def test_a_renewal_that_fails_ends_the_run_as_partial_never_as_absence(renew, reason):
    _repo, job, runs, opened, reads, _cid = run(renew=renew)
    [snapshot] = runs
    assert len(opened) == 2 and reads == [(FIRST, "reader-1")]
    assert snapshot["status"] == "PARTIAL" and snapshot["reasons"] == [reason]
    assert [item["reference"] for item in snapshot["items"]] == [FIRST]
    assert job.status == "SUCCEEDED", job.error


def test_the_checkpoint_refuses_before_the_role_is_ever_assumed():
    _repo, job, runs, opened, reads, _cid = run(refusal="AWS_IDENTITY_CHANGED")
    [snapshot] = runs
    assert opened == [] and reads == []  # no AssumeRole, no read
    # A revoked approval aborts the run and publishes nothing (cremore.coverage.job._publish).
    assert snapshot["status"] == "FAILED" and snapshot["items"] == [] and job.status == "FAILED"


@pytest.mark.parametrize("changes,code", [
    ({"server_collection": False}, "VALUE_READER_REQUIRES_AWS_SERVER_COLLECTION"),
    ({"provider": "vault", "endpoint": "https://vault.example.test", "mounts": [{"name": "secret", "prefixes": ["app"]}],
      "account_id": "", "regions": [], "references": []}, "VALUE_READER_REQUIRES_AWS_SERVER_COLLECTION"),
    ({"references": []}, "VALUE_READER_REQUIRES_SECRET_ARNS"),
    ({"value_reader_role": "Reader/Other"}, "value_reader_role"),
])
def test_a_value_reader_is_only_for_an_aws_server_collection_of_named_secrets(changes, code):
    fields = {"name": "x", "provider": "aws_secrets_manager", "account_id": ACCOUNT, "regions": ["us-east-1"],
              "references": [FIRST], "server_collection": True, "value_reader_role": "CredentialVaultValueReaderRole"}
    with pytest.raises(ValueError, match=code):
        ConnectionSpec(**{**fields, **changes})
    parameters = ConnectionSpec(name="x", provider="aws_ssm", account_id=ACCOUNT, regions=["us-east-1"],
                                prefixes=["prod"], server_collection=True, value_reader_role="CredentialVaultValueReaderRole")
    assert parameters.value_reader_role == "CredentialVaultValueReaderRole"
