"""Synthetic end-to-end evidence, authorization and completeness checks."""

import base64
import json
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from cremore.api import create_app
from cremore.config import Settings
from cremore.coverage.collect import collect_aws_vault, collect_gcp, collect_iam, collect_kv
from cremore.coverage.correlation import _attach_key_creators, report, scope_revision
from cremore.coverage.hasher import hash_value
from cremore.coverage.models import Batch, ConnectionSpec, Contract, Finish, Observation, in_scope
from cremore.coverage.store import CoverageError, CoverageStore
from cremore.db.postgres_scan_test import (
    pg as pg,  # noqa: PLC0414 -- explicit pytest fixture re-export
)
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.detection import DetectorInput
from cremore.detection.engine import Engine, EngineConfig
from cremore.scanning.orchestrator import Orchestrator

KEY = b"k" * 32
TOKEN = "coverage-api-" + "z" * 32
GH = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"
ACCOUNT = "123456789012"
ARN = f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:app/db-Ab12Cd"
USER = f"arn:aws:iam::{ACCOUNT}:user/robot"


def approved_aws(repo):
    from cremore_aws_provider import aws_access

    from cremore.domain.models import AwsAccount
    account = repo.create_aws_account(AwsAccount(account_id=ACCOUNT, name="Synthetic",
        access="RUNTIME_IDENTITY", validation_status="VALID", validation_key="1:1"))
    repo.put_setting(aws_access.APPROVAL_KEYS[aws_access.SCANNER], {"revision": 1}, "admin")
    return account


@pytest.fixture(params=["memory", "sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def repo(request):
    if request.param == "memory":
        return InMemoryRepository()
    if request.param == "postgres":
        return request.getfixturevalue("pg")[1]
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


def engine():
    return Engine(EngineConfig(fingerprint_key=KEY))


def spec(**kwargs):
    return ConnectionSpec(name="Synthetic vault", provider="aws_secrets_manager", account_id=ACCOUNT,
                          regions=["us-east-1"], **kwargs)


def contract():
    return Contract(engine_digest=engine().detection_digest).model_dump()


def value(**overrides):
    row = {"reference": ARN, "account_id": ACCOUNT, "region": "us-east-1", "version": "v1",
           "evidence": "VALUE", "credential_type": "GITHUB_TOKEN", "fingerprint": "a" * 64}
    return Observation(**(row | overrides))


def save(store, connection, items, *, status="COMPLETE", reasons=()):
    run = store.start(connection["id"], connection["revision"], str(uuid.uuid4()), contract())
    if items:
        store.append(connection["id"], run["id"], Batch(index=0, items=items))
    return store.finish(connection["id"], run["id"], Finish(batch_count=int(bool(items)), item_count=len(items),
                                                         status=status, reasons=list(reasons)))


def test_legacy_issuer_identifier_is_omitted_from_public_vault_locations(repo, monkeypatch):
    store = CoverageStore(repo)
    owner, _ = store.create(spec(), "admin")
    identifier = "serviceAccountKey:app@sample.iam.gserviceaccount.com:" + "a" * 40
    save(store, owner, [value(credential_type="GCP_SERVICE_ACCOUNT", issuer_identifier=identifier)])
    original = CoverageStore.snapshots

    def legacy(self, *args, **kwargs):
        rows = original(self, *args, **kwargs)
        for row in rows:
            for item in row["items"]:
                item["issuer_identifier"] = "legacy-invalid-issuer-identifier"
        return rows

    monkeypatch.setattr(CoverageStore, "snapshots", legacy)
    result = report(repo, contract())
    assert result["summary"]["vault_only"] == 1
    assert "legacy-invalid-issuer-identifier" not in json.dumps(result, default=str)


def test_atomic_scope_bound_idempotent_submission(repo):
    store = CoverageStore(repo)
    owner, token = store.create(spec(), "admin")
    request_id = str(uuid.uuid4())
    run = store.start(owner["id"], 1, request_id, contract(), token=token)
    assert store.start(owner["id"], 1, request_id, contract(), token=token)["id"] == run["id"]
    batch = Batch(index=0, items=[value()])
    store.append(owner["id"], run["id"], batch, token=token)
    store.append(owner["id"], run["id"], batch, token=token)
    with pytest.raises(CoverageError, match="BATCH_REPLAY_CONFLICT"):
        store.append(owner["id"], run["id"], Batch(index=0, items=[value(fingerprint="b" * 64)]))
    with pytest.raises(CoverageError, match="INCOMPLETE_SUBMISSION"):
        store.finish(owner["id"], run["id"], Finish(batch_count=2, item_count=1, status="COMPLETE"))
    other, other_token = store.create(spec(), "other")
    with pytest.raises(CoverageError, match="COLLECTOR_UNAUTHORIZED"):
        store.append(owner["id"], run["id"], batch, token=other_token)
    with pytest.raises(CoverageError, match="RUN_NOT_FOUND"):
        store.append(other["id"], run["id"], batch, token=other_token)
    outcome = Finish(batch_count=1, item_count=1, status="COMPLETE")
    store.finish(owner["id"], run["id"], outcome)
    store.finish(owner["id"], run["id"], outcome)
    assert store.snapshots(owner["id"])[0]["item_count"] == 1
    assert repo.list_findings() == []
    changed, replacement = store.change(owner["id"], 1, "admin", rotate=True)
    assert replacement != token and changed["revision"] == 2
    with pytest.raises(CoverageError, match="COLLECTOR_UNAUTHORIZED"):
        store.start(owner["id"], 2, str(uuid.uuid4()), contract(), token=token)
    with pytest.raises(CoverageError, match="RUN_SCOPE_REVOKED"):
        store.finish(owner["id"], run["id"], outcome, token=replacement)


def test_submission_limits_partial_and_revisions(repo):
    store = CoverageStore(repo)
    owner, _ = store.create(spec(max_records=1), "admin")
    run = store.start(owner["id"], 1, str(uuid.uuid4()), contract())
    with pytest.raises(CoverageError, match="OBSERVATION_OUTSIDE_SCOPE"):
        store.append(owner["id"], run["id"], Batch(index=0, items=[value(account_id="999999999999")]))
    unresolved = value(evidence="UNRESOLVED", fingerprint=None, reason="VALUE_UNREADABLE")
    store.append(owner["id"], run["id"], Batch(index=0, items=[unresolved]))
    with pytest.raises(CoverageError, match="RUN_ITEM_LIMIT"):
        store.append(owner["id"], run["id"], Batch(index=1, items=[value()]))
    completed = store.finish(owner["id"], run["id"], Finish(batch_count=1, item_count=1, status="COMPLETE"))
    assert completed["status"] == "PARTIAL"
    with pytest.raises(CoverageError, match="CONNECTION_REVISION_CONFLICT"):
        store.change(owner["id"], 2, "stale", enabled=False)


def test_competing_revision_changes_have_one_winner():
    store = CoverageStore(InMemoryRepository())
    owner, _ = store.create(spec(), "admin")
    def change(_):
        try:
            store.change(owner["id"], 1, "admin", enabled=False)
            return True
        except CoverageError:
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(change, range(2))) == 1


@pytest.mark.parametrize("changes", [
    {"reference": f"arn:aws:iam::{ACCOUNT}:user/robot"},
    {"reference": ARN.replace("us-east-1", "eu-west-1")},
    {"reference": ARN.replace(ACCOUNT, "999999999999")},
    {"reference": ARN.replace("arn:aws:", "xyz:aws:")},
])
def test_aws_scope_rejects_foreign_metadata(changes):
    assert not in_scope(spec(), value(**changes))


def test_sm_prefix_and_gcp_scope_validation():
    assert in_scope(spec(prefixes=["app/db"]), value())
    assert not in_scope(spec(prefixes=["app/d"]), value())
    gcp = ConnectionSpec(name="GCP", provider="gcp_secret_manager", project="synthetic-project")
    assert not in_scope(gcp, Observation(reference="projects/synthetic-project/../other", evidence="UNRESOLVED", reason="UNKNOWN"))
    with pytest.raises(ValidationError):
        value(secret=GH)
    with pytest.raises(ValidationError):
        value(created_at="2026-01-01T00:00:00")


def test_passive_hashing_matches_exposure_engine_and_never_serializes_values():
    eng = engine()
    items = hash_value(eng, GH.encode(), {"reference": ARN, "account_id": ACCOUNT, "region": "us-east-1"}, max_bytes=1024)
    detected = eng.scan(DetectorInput(data=GH.encode(), verify=False))
    assert {i.fingerprint for i in items} == {i.fingerprint for i in detected}
    assert GH not in json.dumps([i.model_dump() for i in items])
    assert hash_value(eng, b"\xff\x00", {"reference": ARN}, max_bytes=1024)[0].reason == "UNSUPPORTED_BINARY"
    assert hash_value(eng, b"x" * 20, {"reference": ARN}, max_bytes=10)[0].reason == "VALUE_TOO_LARGE"
    ambiguous = b"AKIA0123456789ABCDEF ASIA0123456789ABCDEF"
    assert hash_value(eng, ambiguous, {"reference": ARN}, max_bytes=1024)[0].reason == "AMBIGUOUS_AWS_PAIRS"
    ids = hash_value(eng, b"AKIA0123456789ABCDEF", {"reference": ARN}, max_bytes=1024)
    assert any(i.evidence == "IDENTIFIER" and not i.fingerprint for i in ids)
    assert any(i.evidence == "UNRESOLVED" for i in ids)


def test_correlation_positive_absence_failure_stale_history_and_no_fake_exposure(repo):
    eng = engine()
    orch = Orchestrator(repo, engine=eng, config=eng.config)
    from cremore.detection import ResourceRef
    orch.scan_resource(GH.encode(), ResourceRef(source_type="inline", resource="synthetic", location="fixture"), verify=False)
    store = CoverageStore(repo)
    vault, _ = store.create(spec(), "admin")
    absent, _ = store.create(spec(), "admin")
    rows = hash_value(eng, GH.encode(), {"reference": ARN, "account_id": ACCOUNT, "region": "us-east-1", "version": "v1"}, max_bytes=1024)
    save(store, vault, rows)
    view = report(repo, contract())
    assert view["summary"]["matched"] == 1 and view["scope_reasons"]
    save(store, vault, [], status="FAILED", reasons=["READ_DENIED"])
    view = report(repo, contract())
    assert view["summary"]["unknown"] == 1 and view["summary"]["matched_percent"] is None
    assert view["items"][0]["history"]
    save(store, vault, [])
    save(store, absent, [])
    repo.put_setting("coverage_scope", {"confirmed": True, "revision": scope_revision(store.list_connections())}, "admin")
    assert report(repo, contract())["summary"]["no_vault_match"] == 1
    save(store, vault, rows)
    assert report(repo, contract(), now=datetime.now(UTC) + timedelta(days=2))["summary"]["unknown"] == 1
    wrong_contract = contract() | {"engine_digest": "0" * 64}
    assert report(repo, wrong_contract)["summary"]["unknown"] == 1
    issuer, _ = store.create(ConnectionSpec(name="IAM", provider="aws_iam", account_id=ACCOUNT), "admin")
    save(store, issuer, [Observation(reference=USER, account_id=ACCOUNT, evidence="ISSUED", credential_type="AWS_ACCESS_KEY", identifier="AKIA0123456789ABCDEF")])
    assert report(repo, contract())["summary"]["issuance_only"] == 1
    assert len(repo.list_findings()) == 1


class IAM:
    def list_users(self, **kwargs):
        if kwargs.get("Marker"):
            return {"Users": [{"Arn": f"arn:aws:iam::{ACCOUNT}:user/denied", "UserName": "denied"}]}
        return {"Users": [{"Arn": USER, "UserName": "robot"}], "Marker": "page2", "IsTruncated": True}

    def list_access_keys(self, **kwargs):
        if kwargs["UserName"] == "denied":
            raise RuntimeError(GH)
        return {"AccessKeyMetadata": [{"AccessKeyId": "AKIA0123456789ABCDEF", "Status": "Active"}]}

    def list_service_specific_credentials(self, **kwargs):
        return {"ServiceSpecificCredentials": [{"ServiceSpecificCredentialId": "ACCA0123456789ABCDEF", "Status": "Active", "ServiceName": "codecommit.amazonaws.com"}]}


def test_iam_lists_unseen_keys_with_partial_and_request_limits():
    cfg = ConnectionSpec(name="IAM", provider="aws_iam", account_id=ACCOUNT, service_credentials=True)
    result = collect_iam(cfg, IAM())
    assert result.status == "PARTIAL" and "IAM_KEY_LIST_FAILED" in result.reasons
    assert sum(i.evidence == "ISSUED" for i in result.items) == 3
    assert all(i.fingerprint is None for i in result.items)
    assert GH not in json.dumps([i.model_dump() for i in result.items])
    limited = collect_iam(cfg.model_copy(update={"max_requests": 1}), IAM())
    assert "REQUEST_LIMIT" in limited.reasons and limited.status != "COMPLETE"


def test_sm_current_previous_binary_and_failure():
    class SM:
        def list_secrets(self, **kwargs):
            return {"SecretList": [{"ARN": ARN}]}
        def get_secret_value(self, **kwargs):
            return {"ARN": ARN, "VersionId": "one", "VersionStages": [kwargs["VersionStage"]], "SecretBinary": GH.encode()}
    current = collect_aws_vault(spec(), lambda *_: SM(), engine())
    assert current.status == "COMPLETE" and current.items[0].version_state == "CURRENT"
    previous = collect_aws_vault(spec(version_selector="AWSPREVIOUS"), lambda *_: SM(), engine())
    assert previous.items[0].version_state == "PREVIOUS"
    class Denied(SM):
        def get_secret_value(self, **kwargs):
            raise RuntimeError(GH)
    failed = collect_aws_vault(spec(), lambda *_: Denied(), engine())
    assert failed.status == "PARTIAL" and failed.items[0].reason == "SECRET_READ_FAILED"


@pytest.mark.parametrize("provider,version", [("vault", 1), ("vault", 2), ("openbao", 2)])
def test_kv_namespaces_versions_and_path_boundaries(provider, version):
    calls = []
    def handle(request):
        calls.append(request)
        assert request.headers["X-Vault-Namespace"] == "tenant-a"
        assert request.headers["X-Vault-Token"] == "synthetic-auth"
        if request.url.params.get("list"):
            return httpx.Response(200, json={"data": {"keys": ["token"]}})
        data = {"value": GH}
        if version == 2:
            data = {"data": data, "metadata": {"version": 7, "destroyed": False, "deletion_time": ""}}
        return httpx.Response(200, json={"data": data})
    cfg = ConnectionSpec(name="KV", provider=provider, endpoint="https://vault.example.test", namespaces=["tenant-a"],
                         mounts=[{"name": "secrets", "kv_version": version, "prefixes": ["app"]}])
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        result = collect_kv(cfg, client, "synthetic-auth", engine())
    assert result.status == "COMPLETE"
    assert result.items[0].version == ("7" if version == 2 else "unversioned")
    assert result.items[0].reference == "app/token"
    assert all("/app" in str(r.url) for r in calls)


def test_gcp_projection_uses_actual_version_and_never_secret_json():
    cfg = ConnectionSpec(name="GCP", provider="gcp_secret_manager", project="synthetic-project")
    name = "projects/synthetic-project/secrets/token"
    def handle(request):
        if request.url.path.endswith("/secrets"):
            return httpx.Response(200, json={"secrets": [{"name": name}]})
        return httpx.Response(200, json={"name": name + "/versions/3", "payload": {"data": base64.b64encode(GH.encode()).decode()}})
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        result = collect_gcp(cfg, client, lambda: "synthetic", engine())
    assert result.status == "COMPLETE" and result.items[0].version == "3"


@pytest.mark.parametrize("partial", [False, True])
def test_ssm_paging_overlapping_paths_and_region_failure(partial):
    calls = []
    arn = f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/app/nested/token"
    class SSM:
        def get_parameters_by_path(self, **kwargs):
            calls.append(kwargs)
            assert kwargs["Recursive"] and kwargs["WithDecryption"]
            return {"Parameters": [{"ARN": arn, "Version": 3, "Value": GH}],
                    **({"NextToken": "next"} if kwargs["Path"] == "/app" and "NextToken" not in kwargs else {})}
    def client(service, region):
        assert service == "ssm"
        if region != "us-east-1":
            raise RuntimeError("synthetic permission denial")
        return SSM()
    cfg = ConnectionSpec(name="Parameters", provider="aws_ssm", account_id=ACCOUNT,
        regions=["us-east-1", "eu-west-1"] if partial else ["us-east-1"], prefixes=["app", "app/nested"])
    result = collect_aws_vault(cfg, client, engine())
    assert result.status == ("PARTIAL" if partial else "COMPLETE")
    assert len(calls) == 3 and len(result.items) == 1
    assert result.items[0].reference == arn and result.items[0].version == "3"
    assert GH not in json.dumps([item.model_dump() for item in result.items])


@pytest.mark.parametrize("state", ["deleted", "destroyed", "denied"])
def test_kv_unavailable_current_version_is_unresolved(state):
    cfg = ConnectionSpec(name="KV", provider="openbao", endpoint="https://bao.example.test",
        mounts=[{"name": "secret", "kv_version": 2, "prefixes": ["app"]}])
    def handle(request):
        if request.url.params.get("list"):
            return httpx.Response(200, json={"data": {"keys": ["token"]}})
        if state == "denied":
            return httpx.Response(403, json={"errors": ["synthetic denial"]})
        return httpx.Response(200, json={"data": {"data": None, "metadata": {
            "version": 4, "destroyed": state == "destroyed", "deletion_time": "2026-09-20T00:00:00Z" if state == "deleted" else ""}}})
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        result = collect_kv(cfg, client, "synthetic", engine())
    assert result.status == "PARTIAL" and len(result.items) == 1
    assert result.items[0].evidence == "UNRESOLVED" and result.items[0].fingerprint is None
    assert result.items[0].reason == ("KV_VALUE_READ_FAILED" if state == "denied" else "VERSION_UNAVAILABLE")


def test_api_scoped_machine_auth_compatibility_and_safe_validation(repo):
    api = TestClient(create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY=KEY.hex())))
    auth = {"Authorization": "Bearer " + TOKEN}
    from fastapi.encoders import jsonable_encoder

    from cremore.onboarding.fixtures_test import collection

    # Connecting is an administrator's; the collection itself is what a provider connection's step 4 creates.
    assert api.post("/api/v1/provider-connections", json={"provider": "vault"}).status_code == 401
    row, token = collection(repo, spec().model_dump())
    owner = {**jsonable_encoder(row), "collector_token": token}
    machine = {"X-Cremore-Collector-Token": owner["collector_token"]}
    base = "/api/v1/coverage/collector/" + owner["id"]
    config = api.get(base, headers=machine).json()
    assert config["contract"] == contract()
    assert api.get("/api/v1/findings", headers=machine).status_code == 401
    payload = {"revision": 1, "request_id": str(uuid.uuid4()), "contract": contract()}
    mismatch = payload | {"contract": contract() | {"engine_digest": "0" * 64}}
    assert api.post(base + "/runs", headers=machine, json=mismatch).status_code == 409
    run = api.post(base + "/runs", headers=machine, json=payload).json()
    path = base + "/runs/" + run["id"]
    invalid = api.put(path + "/batches", headers=machine, json={"index": 0, "items": [value().model_dump() | {"secret": GH}]})
    assert invalid.status_code == 422 and GH not in invalid.text
    assert api.put(path + "/batches", headers=machine, json={"index": 0, "items": [value().model_dump()]}).status_code == 200
    assert api.post(path + "/finish", headers=machine, json={"batch_count": 1, "item_count": 1, "status": "COMPLETE"}).status_code == 200
    shown = api.get("/api/v1/coverage", headers=auth)
    assert owner["collector_token"] not in shown.text and "token_hash" not in shown.text
    assert shown.json()["summary"]["vault_only"] == 1
    assert api.get("/api/v1/findings", headers=auth).json() == []
    # The run the customer-side collector uploaded is listed for the logs, without its batches or contract.
    runs = api.get(f"/api/v1/coverage/connections/{owner['id']}/runs", headers=auth)
    assert runs.status_code == 200
    [listed] = runs.json()["items"]
    assert listed["id"] == run["id"] and listed["status"] == "COMPLETE" and listed["item_count"] == 1 and listed["finished_at"]
    assert "contract" not in listed and "items" not in listed and owner["collector_token"] not in runs.text
    assert api.get(f"/api/v1/coverage/connections/{uuid.uuid4()}/runs", headers=auth).status_code == 404
    assert api.get(f"/api/v1/coverage/connections/{owner['id']}/runs", headers=machine).status_code == 401


@pytest.mark.parametrize("enabled,allowed,selected,expected", [
    (False, True, None, False), (True, True, None, True), (True, False, None, False),
    (False, True, True, True), (True, True, False, False), (False, False, True, False),
])
def test_iam_worker_runs_through_existing_leased_queue(repo, enabled, allowed, selected, expected):
    from types import SimpleNamespace

    from cremore.coverage import JOB_KIND
    from cremore.db.task_store import TaskStore
    from cremore.domain.models import ScanJob
    from cremore.worker.worker import JobWorker
    account = approved_aws(repo)
    session = SimpleNamespace(pin="1:1", client=lambda _: IAM())
    sessions = SimpleNamespace(open=lambda *_: session, refusal=lambda *_: (None, account, {"revision": 1}))
    store = CoverageStore(repo)
    connection, _ = store.create(ConnectionSpec(name="IAM", provider="aws_iam", account_id=ACCOUNT,
                                               iam_policy_metadata=selected), "admin")
    job = repo.enqueue_job(ScanJob(kind=JOB_KIND, payload={"provider": "aws", "account_id": ACCOUNT,
        "coverage_connection_id": str(connection["id"]), "coverage_revision": 1, "access_pin": "1:1"}))
    worker = JobWorker(repo, orchestrator=Orchestrator(repo, config=EngineConfig(fingerprint_key=KEY)), aws_sessions=sessions)
    worker.settings = Settings(IAM_POTENTIAL_ACCESS_MODE="enabled" if allowed else "disabled")
    repo.put_setting("iam_potential_access", {"enabled": enabled}, "admin")
    assert worker.process_next()
    TaskStore(repo).finalize_runs()
    finished = repo.get_job(job.id)
    assert finished.status == "SUCCEEDED"
    assert store.snapshots(connection["id"])[0]["status"] == "PARTIAL"
    # The logs read the collection's own result: its stored status and how many items it committed.
    from cremore.api.source_presenters import present_scan_run
    shown = present_scan_run(finished)
    assert shown["status"] == "PARTIAL" and shown["metadata_items"] == len(store.snapshots(connection["id"])[0]["items"])
    items = store.snapshots(connection["id"])[0]["items"]
    summaries = [item.get("iam_policies") for item in items if item["evidence"] == "ISSUED"]
    assert bool(any(summaries)) == expected
    if expected:
        assert all(summary["status"] == "FAILED" for summary in summaries)  # fake has no policy methods
    assert repo.list_findings() == []


def test_disabled_vault_collect_keeps_public_error_contract(repo):
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY=KEY.hex()))
    api, auth = TestClient(app), {"Authorization": "Bearer " + TOKEN}
    store = CoverageStore(repo)
    owner, _ = store.create(spec(), "admin")
    path = f"/api/v1/coverage/connections/{owner['id']}/collect"
    assert api.post(path, headers=auth).json()["detail"] == "VAULT_COLLECTION_RUNS_IN_CUSTOMER_ENVIRONMENT"
    store.change(owner["id"], 1, "admin", enabled=False)
    response = api.post(path, headers=auth)
    assert response.status_code == 409 and response.json() == {
        "error": "CONNECTION_DISABLED_OR_MISSING", "detail": "CONNECTION_DISABLED_OR_MISSING"}


def test_server_collected_aws_vault_runs_through_the_leased_worker_with_its_own_value_allowlist(repo):
    from types import SimpleNamespace

    from cremore_aws_provider.aws_readonly import (
        READ_OPERATIONS,
        VAULT_OPERATIONS,
        ReadOnlyViolation,
        readonly_client,
    )

    from cremore.worker.worker import JobWorker
    account = approved_aws(repo)

    class SM:
        def list_secrets(self, **kwargs):
            return {"SecretList": [{"ARN": ARN}]}

        def get_secret_value(self, **kwargs):
            return {"ARN": ARN, "VersionId": "one", "VersionStages": ["AWSCURRENT"], "SecretString": GH}

        def put_secret_value(self, **kwargs):
            raise AssertionError("never called")

    requested = []

    def client(service, region=None, *, operations=None):
        requested.append((service, region, operations))
        return readonly_client(SM(), service, operations or READ_OPERATIONS)

    session = SimpleNamespace(pin="1:1", client=client)
    sessions = SimpleNamespace(open=lambda *_: session, refusal=lambda *_: (None, account, {"revision": 1}))
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY=KEY.hex()),
                     aws_sessions=sessions)
    api, auth = TestClient(app), {"Authorization": "Bearer " + TOKEN}
    store = CoverageStore(repo)
    customer, _ = store.create(spec(), "admin")
    server, _ = store.create(spec(server_collection=True), "admin")
    customer_path = f"/api/v1/coverage/connections/{customer['id']}/collect"
    assert api.post(customer_path, headers=auth).json()["detail"] == "VAULT_COLLECTION_RUNS_IN_CUSTOMER_ENVIRONMENT"
    queued = api.post(f"/api/v1/coverage/connections/{server['id']}/collect", headers=auth)
    assert queued.status_code == 202, queued.text
    worker = JobWorker(repo, orchestrator=app.state.orchestrator, aws_sessions=sessions)
    assert worker.process_next()
    assert requested == [("secretsmanager", "us-east-1", VAULT_OPERATIONS)]
    [run] = store.snapshots(server["id"])
    assert run["status"] == "COMPLETE" and run["items"][0]["evidence"] == "VALUE"
    assert GH not in json.dumps(run, default=str) + json.dumps([job.payload for job in repo.list_jobs()], default=str)
    # The value allowlist is used only by this job; scanner sessions still cannot read values.
    with pytest.raises(ReadOnlyViolation):
        readonly_client(SM(), "secretsmanager").get_secret_value(SecretId=ARN)
    with pytest.raises(ReadOnlyViolation):
        readonly_client(SM(), "secretsmanager", VAULT_OPERATIONS).put_secret_value(SecretId=ARN)
    assert READ_OPERATIONS["ssm"] == {"describe_parameters"}
    assert "get_secret_value" not in READ_OPERATIONS["secretsmanager"]
    with pytest.raises(ReadOnlyViolation):
        readonly_client(SM(), "ssm").get_parameters_by_path(Path="/", WithDecryption=True)


@pytest.mark.parametrize("provider", ["aws_iam", "aws_cloudtrail", "gcp_secret_manager"])
def test_server_collection_is_only_for_secret_stores_the_worker_can_reach(provider):
    fields = {"account_id": ACCOUNT, "regions": ["us-east-1"]} if provider.startswith("aws_") else {"project": "synthetic-project"}
    with pytest.raises(ValueError, match="SERVER_COLLECTION_NOT_SUPPORTED"):
        ConnectionSpec(name="x", provider=provider, server_collection=True, **fields)
    with pytest.raises(ValueError, match="INVALID_AWS_INVENTORY_SCHEDULE"):  # a schedule needs the worker to collect
        ConnectionSpec(name="x", provider="vault", endpoint="https://vault.example.test",
                       schedule_minutes=60, mounts=[{"name": "secret", "prefixes": [""]}])


def test_a_scheduled_server_vault_is_queued_once_per_interval_and_only_while_schedules_are_allowed(repo):
    from types import SimpleNamespace

    from cremore.coverage.aws_scheduling import poll_server_vault_schedules

    store = CoverageStore(repo)
    scheduled = vault_connection(store, schedule_minutes=60)
    vault_connection(store, name="Manual only")  # server collection without an interval is never scheduled
    now = datetime.now(UTC)
    assert poll_server_vault_schedules(repo, SimpleNamespace(scan_schedules_allowed=False), now=now)["enqueued"] == 0
    allowed = SimpleNamespace(scan_schedules_allowed=True)
    assert poll_server_vault_schedules(repo, allowed, now=now) == {"enqueued": 1, "skipped": 0}
    [job] = repo.list_jobs()
    assert job.payload["coverage_connection_id"] == str(scheduled["id"]) and job.payload["provider"] == "vault"
    assert poll_server_vault_schedules(repo, allowed, now=now)["skipped"] == 1  # still queued
    repo.fail_job(job.id, "SYNTHETIC")
    assert poll_server_vault_schedules(repo, allowed, now=now + timedelta(minutes=30))["skipped"] == 1  # not due
    assert poll_server_vault_schedules(repo, allowed, now=now + timedelta(minutes=61))["enqueued"] == 1


def vault_stack(repo, monkeypatch, *, store_url="https://vault.example.test"):
    from cremore.worker.worker import JobWorker
    calls = []

    def handle(request):
        calls.append(request)
        assert request.headers["X-Vault-Token"] == "synthetic-platform-token"
        if request.url.params.get("list"):
            return httpx.Response(200, json={"data": {"keys": ["token"]}})
        return httpx.Response(200, json={"data": {"data": {"value": GH}, "metadata": {"version": 3, "destroyed": False,
                                                                                     "deletion_time": ""}}})

    real = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: real(transport=httpx.MockTransport(handle)))
    settings = Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY=KEY.hex(),
                        SECRET_STORE_URL=store_url, SECRET_STORE_TOKEN="synthetic-platform-token")
    app = create_app(repo=repo, settings=settings)
    worker = JobWorker(repo, orchestrator=app.state.orchestrator, settings=settings)
    return TestClient(app), {"Authorization": "Bearer " + TOKEN}, worker, calls


def vault_connection(store, **changes):
    fields = {"name": "Platform Vault", "provider": "vault", "endpoint": "https://vault.example.test",
              "mounts": [{"name": "secret", "kv_version": 2, "prefixes": ["app"]}], "server_collection": True, **changes}
    return store.create(ConnectionSpec(**fields), "admin")[0]


def test_server_collected_vault_uses_the_installation_secret_store_identity(repo, monkeypatch):
    api, auth, worker, calls = vault_stack(repo, monkeypatch)
    store = CoverageStore(repo)
    customer = vault_connection(store, server_collection=False, name="Customer Vault")
    assert api.post(f"/api/v1/coverage/connections/{customer['id']}/collect", headers=auth).json()["detail"] == (
        "VAULT_COLLECTION_RUNS_IN_CUSTOMER_ENVIRONMENT")
    server = vault_connection(store)
    queued = api.post(f"/api/v1/coverage/connections/{server['id']}/collect", headers=auth)
    assert queued.status_code == 202, queued.text
    again = api.post(f"/api/v1/coverage/connections/{server['id']}/collect", headers=auth).json()
    assert again["enqueued"] is False and again["job_id"] == queued.json()["job_id"]
    assert worker.process_next()
    assert repo.get_job(uuid.UUID(queued.json()["job_id"])).status == "SUCCEEDED"
    [run] = store.snapshots(server["id"])
    assert run["status"] == "COMPLETE" and run["items"][0]["evidence"] == "VALUE" and run["items"][0]["version"] == "3"
    assert calls and all(str(request.url).startswith("https://vault.example.test/") for request in calls)
    outputs = json.dumps(run, default=str) + json.dumps([job.payload for job in repo.list_jobs()], default=str)
    assert GH not in outputs and "synthetic-platform-token" not in outputs


def test_server_collected_vault_never_sends_the_installation_identity_elsewhere(repo, monkeypatch):
    api, auth, worker, calls = vault_stack(repo, monkeypatch, store_url="https://other-vault.example.test")
    server = vault_connection(CoverageStore(repo))
    queued = api.post(f"/api/v1/coverage/connections/{server['id']}/collect", headers=auth)
    assert queued.status_code == 202, queued.text
    worker.process_next()
    job = repo.get_job(uuid.UUID(queued.json()["job_id"]))
    assert job.status == "FAILED" and "VAULT_SERVER_IDENTITY_NOT_CONFIGURED" in (job.error or "")
    assert calls == []


def test_worker_revocation_discards_observations_and_closes_failed_run(repo):
    from types import SimpleNamespace

    from cremore.coverage import JOB_KIND
    from cremore.domain.models import ScanJob
    from cremore.worker.worker import JobWorker
    account = approved_aws(repo)
    class RevokedIAM(IAM):
        def list_access_keys(self, **kwargs):
            repo.update_aws_account(account.id, enabled=False)
            return super().list_access_keys(**kwargs)
    session = SimpleNamespace(pin="1:1", client=lambda _: RevokedIAM())
    # The outer probe remains cached; the commit must check the DB itself.
    sessions = SimpleNamespace(open=lambda *_: session, refusal=lambda *_: (None, account, {"revision": 1}))
    store = CoverageStore(repo)
    owner, _ = store.create(ConnectionSpec(name="IAM", provider="aws_iam", account_id=ACCOUNT), "admin")
    repo.enqueue_job(ScanJob(kind=JOB_KIND, payload={"provider": "aws", "account_id": ACCOUNT,
        "coverage_connection_id": str(owner["id"]), "coverage_revision": 1, "access_pin": "1:1"}))
    worker = JobWorker(repo, orchestrator=Orchestrator(repo, config=EngineConfig(fingerprint_key=KEY)), aws_sessions=sessions)
    worker.process_next()
    run = store.snapshots(owner["id"])[0]
    assert run["status"] == "FAILED" and run["items"] == []
    assert not repo.list_findings()


def test_aws_inventory_api_queue_projection_and_stale_scope(repo):
    from types import SimpleNamespace

    from cremore.worker.worker import JobWorker
    account = approved_aws(repo)
    session = SimpleNamespace(pin="1:1", client=lambda _: IAM())
    sessions = SimpleNamespace(open=lambda *_: session, refusal=lambda *_: (None, account, {"revision": 1}))
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY=KEY.hex()), aws_sessions=sessions)
    api, auth = TestClient(app), {"Authorization": "Bearer " + TOKEN}
    path = f"/api/v1/aws/accounts/{account.id}/credential-inventory"
    assert api.get(path, headers=auth).json()["inventory"] is None
    queued = api.post(path + "/refresh", headers=auth)
    assert queued.status_code == 202 and queued.json()["refresh"]["status"] == "QUEUED"
    assert api.post(path + "/refresh", headers=auth).json()["refresh"]["id"] == queued.json()["refresh"]["id"]
    worker = JobWorker(repo, orchestrator=app.state.orchestrator, aws_sessions=sessions)
    assert worker.process_next()
    view = api.get(path, headers=auth).json()
    assert view["refresh"]["status"] == "PARTIAL"
    assert view["inventory"]["records"][0]["match_id"] == "AKIA0123456789ABCDEF"
    store = CoverageStore(repo)
    connection = store.list_connections()[0]
    store.change(connection["id"], 1, "admin", enabled=False)
    stale = api.get(path, headers=auth).json()["inventory"]
    assert stale["collection_status"] == "PARTIAL"
    assert all(row["provider_status"] == "UNKNOWN" for row in stale["records"])
    assert api.post(path + "/refresh", headers=auth).status_code == 409


@pytest.mark.parametrize("boundary", ["start", "commit"])
def test_scheduled_inventory_rechecks_policy_inside_start_and_commit(repo, monkeypatch, boundary):
    from types import SimpleNamespace

    from cremore_aws_provider import aws_inventory_settings

    from cremore.coverage import JOB_KIND
    from cremore.coverage import job as inventory_job
    from cremore.domain.models import ScanJob
    from cremore.worker.worker import JobWorker

    account = approved_aws(repo)
    settings = Settings(FINGERPRINT_KEY=KEY.hex())
    repo.put_setting(aws_inventory_settings.KEY, {"enabled": True}, "admin")
    session = SimpleNamespace(pin="1:1", client=lambda _: IAM())
    sessions = SimpleNamespace(open=lambda *_: session, refusal=lambda *_: (None, account, {"revision": 1}))
    store = CoverageStore(repo)
    owner, _ = store.create(ConnectionSpec(name="IAM", provider="aws_iam", account_id=ACCOUNT), "admin")
    queued = repo.enqueue_job(ScanJob(kind=JOB_KIND, payload={"provider": "aws", "account_id": ACCOUNT,
        "coverage_connection_id": str(owner["id"]), "coverage_revision": 1, "access_pin": "1:1",
        "aws_inventory_scheduled": True}))
    original = inventory_job.require_current_access
    checks = []

    def change_after_outer_check(bound, *args, **kwargs):
        checks.append(True)
        if len(checks) == (1 if boundary == "start" else 2):
            bound.put_setting(aws_inventory_settings.KEY, {"enabled": False}, "admin")
        return original(bound, *args, **kwargs)

    monkeypatch.setattr(inventory_job, "require_current_access", change_after_outer_check)
    worker = JobWorker(repo, settings=settings,
                       orchestrator=Orchestrator(repo, config=EngineConfig(fingerprint_key=KEY)), aws_sessions=sessions)
    monkeypatch.setattr(worker, "poll_triggers", lambda: None)
    assert worker.process_next()
    assert len(checks) == (1 if boundary == "start" else 2)
    runs = store.snapshots(owner["id"])
    assert not runs if boundary == "start" else runs[0]["status"] == "FAILED" and runs[0]["items"] == []
    assert repo.get_job(queued.id).status != "SUCCEEDED"


def test_cloudtrail_projects_only_bounded_used_ids_and_marks_failed_regions():
    from cremore.coverage.collect import collect_usage
    now = datetime.now(UTC)
    calls = []
    class Trail:
        def lookup_events(self, **kwargs):
            calls.append(kwargs)
            return {"Events": [{"EventId": "test-event", "CloudTrailEvent": json.dumps({
                "recipientAccountId": ACCOUNT, "eventTime": now.isoformat(),
                "userIdentity": {"accessKeyId": "ASIA0123456789ABCDEF", "arn": USER},
                "requestParameters": {"secret": GH}})}]}
    def factory(region):
        if region == "eu-west-1":
            raise RuntimeError(GH)
        return Trail()
    cfg = ConnectionSpec(name="Trail", provider="aws_cloudtrail", account_id=ACCOUNT, regions=["us-east-1", "eu-west-1"])
    result = collect_usage(cfg, factory, now=now)
    assert result.status == "PARTIAL" and result.items[0].evidence == "USAGE"
    assert result.items[0].fingerprint is None
    assert calls[0]["StartTime"] == now - timedelta(days=7)
    assert GH not in json.dumps([i.model_dump() for i in result.items])


def test_aws_json_pair_plain_pair_ambiguity_and_split_material():
    identifier = "AKIA0123456789ABCDEF"
    # Synthetic non-placeholder key material avoids the detector's example filter.
    secret = "aB3dE5fG7hJ9kL1mN2pQ" + "4rS6tU8vW0xY2zC4D6eF"
    raw = json.dumps({"aws_access_key_id": identifier, "aws_secret_access_key": secret}).encode()
    location = {"reference": ARN}
    result = hash_value(engine(), raw, location, max_bytes=4096)
    pairs = [row for row in result if row.credential_type == "AWS_ACCESS_KEY" and row.evidence == "VALUE"]
    expected = [row.fingerprint for row in engine().scan(DetectorInput(data=f"{identifier} {secret}".encode(), verify=False)) if row.credential_type == "AWS_ACCESS_KEY"]
    assert pairs and [row.fingerprint for row in pairs] == expected
    assert secret not in json.dumps([row.model_dump() for row in result])
    ambiguous = json.dumps({"id": identifier, "secret": secret, "other_secret": secret[::-1]}).encode()
    assert hash_value(engine(), ambiguous, location, max_bytes=4096)[0].reason == "AMBIGUOUS_AWS_PAIRS"
    assert all(row.evidence != "VALUE" for row in hash_value(engine(), secret.encode(), location, max_bytes=4096))
    split = json.dumps({"first": {"id": identifier}, "second": {"secret": secret}}).encode()
    assert hash_value(engine(), split, location, max_bytes=4096)[0].reason == "UNPAIRED_AWS_MATERIAL"
    plain_ambiguous = f"{identifier} {secret} {secret[::-1]}".encode()
    assert hash_value(engine(), plain_ambiguous, location, max_bytes=4096)[0].reason == "AMBIGUOUS_AWS_PAIRS"


def test_partial_exposure_never_becomes_a_full_vault_match_or_missing_key(repo):
    from cremore.detection.aws_material_test import ID, LABEL, SAK
    from cremore.detection.models import ResourceRef

    eng = engine()
    orch = Orchestrator(repo, engine=eng, config=eng.config)
    for name, content in (("id", ID), ("secret", LABEL + SAK)):
        orch.scan_resource(content.encode(), ResourceRef(source_type="inline", resource="synthetic", location=name), verify=False)
    store = CoverageStore(repo)
    owner, _ = store.create(spec(), "admin")
    location = {"reference": ARN, "account_id": ACCOUNT, "region": "us-east-1"}
    id_rows = hash_value(eng, ID.encode(), location, max_bytes=4096)
    assert all(row.evidence != "VALUE" for row in id_rows)
    assert any(row.evidence == "IDENTIFIER" for row in id_rows)
    secret_rows = hash_value(eng, (LABEL + SAK).encode(), location, max_bytes=4096)
    assert any(row.credential_type == "AWS_SECRET_ACCESS_KEY" and row.evidence == "VALUE" for row in secret_rows)
    save(store, owner, id_rows + secret_rows, status="PARTIAL", reasons=["UNPAIRED_AWS_MATERIAL"])
    view = report(repo, contract())
    exposed = {row["credential_type"]: row for row in view["items"] if row["origin"] == "EXPOSURE"}
    assert exposed["AWS_ACCESS_KEY_ID"]["state"] == "IDENTIFIER_ONLY"
    assert exposed["AWS_SECRET_ACCESS_KEY"]["state"] == "UNKNOWN"
    assert "SECRET_COMPONENT_MATCHED" in exposed["AWS_SECRET_ACCESS_KEY"]["reasons"]
    assert exposed["AWS_SECRET_ACCESS_KEY"]["locations"]
    assert view["summary"]["matched"] == view["summary"]["no_vault_match"] == 0
    assert view["summary"]["unknown"] == 2


def test_postgres_parallel_submission_is_idempotent(pg):
    _, repo = pg
    store = CoverageStore(repo)
    owner, token = store.create(spec(), "admin")
    request_id = str(uuid.uuid4())
    def submit(_):
        run = store.start(owner["id"], 1, request_id, contract(), token=token)
        store.append(owner["id"], run["id"], Batch(index=0, items=[value()]), token=token)
        return run["id"]
    with ThreadPoolExecutor(max_workers=4) as pool:
        ids = set(pool.map(submit, range(4)))
    assert len(ids) == 1
    run = store.finish(owner["id"], ids.pop(), Finish(batch_count=1, item_count=1, status="COMPLETE"), token=token)
    assert run["item_count"] == 1


def test_identifier_only_relation_and_history_survive_repeated_failures(repo):
    store = CoverageStore(repo)
    owner, _ = store.create(spec(), "admin")
    ident = "AKIA0123456789ABCDEF"
    save(store, owner, [value(evidence="IDENTIFIER", fingerprint=None, identifier=ident, credential_type="AWS_ACCESS_KEY")])
    issuer, _ = store.create(ConnectionSpec(name="IAM", provider="aws_iam", account_id=ACCOUNT), "admin")
    save(store, issuer, [Observation(reference=USER, account_id=ACCOUNT, evidence="ISSUED", credential_type="AWS_ACCESS_KEY", identifier=ident)])
    view = report(repo, contract())
    assert view["items"][0]["state"] == "IDENTIFIER_ONLY" and view["summary"]["exposed"] == 0
    for _ in range(3):
        save(store, owner, [], status="FAILED", reasons=["DENIED"])
    row = report(repo, contract())["items"][0]
    assert row["state"] == "UNKNOWN" and row["history"] and not row["locations"]


def test_repeated_partial_runs_keep_complete_baseline_and_operation_failures(repo):
    store = CoverageStore(repo)
    owner, _ = store.create(ConnectionSpec(name="IAM", provider="aws_iam", account_id=ACCOUNT), "admin")
    baseline = save(store, owner, [Observation(reference=USER, account_id=ACCOUNT, evidence="ISSUED",
        credential_type="AWS_ACCESS_KEY", identifier="AKIA0123456789ABCDEF")])
    operation = Observation(reference=f"account/{ACCOUNT}", account_id=ACCOUNT, evidence="OPERATION",
        operation={"name": "LIST_USERS", "status": "FAILED", "reason": "ACCESS_DENIED", "requests": 1, "records": 0})
    for _ in range(3):
        run = save(store, owner, [operation])
        assert run["status"] == "PARTIAL" and "SOURCE_COLLECTION_INCOMPLETE" in run["reasons"]
    snapshots = store.snapshots(owner["id"])
    assert baseline["id"] in {r["id"] for r in snapshots}
    assert store.latest_run(owner["id"], status="COMPLETE")["id"] == baseline["id"]
    duplicate = store.start(owner["id"], 1, str(uuid.uuid4()), contract())
    store.append(owner["id"], duplicate["id"], Batch(index=0, items=[operation, operation]))
    with pytest.raises(CoverageError, match="DUPLICATE_OPERATION_REPORT"):
        store.finish(owner["id"], duplicate["id"], Finish(batch_count=1, item_count=2, status="COMPLETE"))


def test_policy_change_and_false_positive_do_not_imply_missing_storage(repo):
    from cremore.detection import ResourceRef
    eng = engine()
    orch = Orchestrator(repo, engine=eng, config=eng.config)
    resource = ResourceRef(source_type="inline", resource="synthetic", location="test")
    orch.scan_resource(GH.encode(), resource, verify=False)
    store = CoverageStore(repo)
    owner, _ = store.create(spec(), "admin")
    save(store, owner, [])
    repo.put_setting("coverage_scope", {"confirmed": True, "revision": scope_revision(store.list_connections())}, "admin")
    changed = contract() | {"policy_digest": "1" * 64}
    assert report(repo, changed)["summary"]["unknown"] == 1
    finding = repo.list_findings()[0]
    repo.update_finding_status(finding.id, "FALSE_POSITIVE", resolution="Synthetic rejection")
    assert report(repo, contract())["summary"]["exposed"] == 0


def test_customer_cli_submits_hashed_metadata_only(repo):
    from types import SimpleNamespace

    from cremore.cli.coverage import execute
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY=KEY.hex()))
    store = CoverageStore(repo)
    connection, token = store.create(spec(), "admin")
    class SM:
        def list_secrets(self, **kwargs):
            return {"SecretList": [{"ARN": ARN}]}
        def get_secret_value(self, **kwargs):
            return {"ARN": ARN, "VersionId": "v1", "VersionStages": ["AWSCURRENT"], "SecretString": GH}
    session = SimpleNamespace(client=lambda name, **_: SimpleNamespace(get_caller_identity=lambda: {"Account": ACCOUNT}) if name == "sts" else SM())
    client = TestClient(app)
    result = execute("http://localhost", connection["id"], token, KEY, client=client, aws_session=session)
    assert result["status"] == "COMPLETE"
    snapshots = store.snapshots(connection["id"])
    assert snapshots[0]["items"][0]["fingerprint"]
    assert GH not in json.dumps(snapshots, default=str)
    assert repo.list_findings() == []


def test_cross_provider_values_multiple_vaults_count_once_and_finding_api(repo):
    from cremore.detection import ResourceRef
    eng = engine()
    materials = [GH, "glpat-" + "Ab3De5Fg7Hj9Kl1Mn2Pq", "ntn_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4D6eF8gH0iJ"]
    orch = Orchestrator(repo, engine=eng, config=eng.config)
    store = CoverageStore(repo)
    one, _ = store.create(spec(), "admin")
    two, _ = store.create(ConnectionSpec(name="OpenBao", provider="openbao", endpoint="https://bao.example.test",
        namespaces=["team"], mounts=[{"name": "kv", "kv_version": 2, "prefixes": ["app"]}]), "admin")
    first, second = [], []
    for i, material in enumerate(materials):
        orch.scan_resource(material.encode(), ResourceRef(source_type=["github", "bitbucket", "confluence"][i], resource="synthetic", location=f"file-{i}"), verify=False)
        first.extend(hash_value(eng, material.encode(), {"reference": ARN, "account_id": ACCOUNT, "region": "us-east-1"}, max_bytes=4096))
        second.extend(hash_value(eng, material.encode(), {"reference": f"app/token-{i}", "namespace": "team", "mount": "kv"}, max_bytes=4096))
    assert len(repo.list_findings()) == 3 and all(row.evidence == "VALUE" for row in first + second)
    save(store, one, first)
    save(store, two, second)
    repo.put_setting("coverage_scope", {"confirmed": True, "revision": scope_revision(store.list_connections())}, "admin")
    view = report(repo, contract())
    assert view["summary"]["matched"] == 3 and view["summary"]["exposed"] == 3 and view["summary"]["matched_percent"] == 100
    assert all(len(row["locations"]) == 2 for row in view["items"])
    api = TestClient(create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY=KEY.hex())))
    fid = repo.list_findings()[0].id
    url = f"/api/v1/findings/{fid}/coverage"
    assert api.get(url).status_code == 401
    response = api.get(url, headers={"Authorization": "Bearer " + TOKEN})
    assert response.status_code == 200 and response.json()["item"]["state"] == "MATCHED"
    assert "fingerprint" not in response.text and all(raw not in response.text for raw in materials)
    headers = {"Authorization": "Bearer " + TOKEN}
    filtered = api.get("/api/v1/coverage", headers=headers, params={"state": "MATCHED", "source_type": "bitbucket", "vault_provider": "openbao", "limit": 1}).json()
    assert filtered["total"] == len(filtered["items"]) == 1
    assert filtered["items"][0]["source_types"] == ["bitbucket"]
    assert filtered["summary"] == view["summary"]  # List filters do not improve the rate.
    empty = api.get("/api/v1/coverage", headers=headers, params={"state": "UNKNOWN"}).json()
    assert empty["total"] == 0 and empty["summary"] == view["summary"]
    next_page = api.get("/api/v1/coverage", headers=headers, params={"source_type": "bitbucket", "offset": 1}).json()
    assert next_page["total"] == 1 and not next_page["items"]
    assert api.get("/api/v1/coverage", headers=headers, params={"vault_provider": "unknown"}).status_code == 422
    exposures = api.get("/api/v1/coverage", headers=headers, params={"origin": "EXPOSURE"}).json()
    assert exposures["total"] == 3 and exposures["summary"] == view["summary"]
    assert api.get("/api/v1/coverage", headers=headers, params={"origin": "ISSUANCE"}).json()["total"] == 0
    assert api.get("/api/v1/coverage", headers=headers, params={"origin": "unknown"}).status_code == 422


def test_report_limit_and_gcp_alias_block_absence(repo, monkeypatch):
    store = CoverageStore(repo)
    owner, _ = store.create(spec(), "admin")
    save(store, owner, [value(), value(reference=ARN.replace("db-", "api-"))])
    repo.put_setting("coverage_scope", {"confirmed": True, "revision": scope_revision(store.list_connections())}, "admin")
    monkeypatch.setattr("cremore.coverage.correlation.REPORT_LIMIT", 1)
    view = report(repo, contract())
    assert not view["summary"]["complete"] and "REPORT_LIMIT_REACHED" in view["scope_reasons"]
    assert view["summary"]["matched_percent"] is None
    # The store says its rows were cut; its collection, which response evidence and the vault page read, is fine.
    [state] = view["connections"]
    assert state["truncated"] and state["reasons"] == []
    gcp, _ = store.create(ConnectionSpec(name="GCP", provider="gcp_secret_manager", project="synthetic-project", version_selector="production"), "admin")
    save(store, gcp, [])
    assert "CURRENT_VERSION_NOT_CONFIRMED" in report(repo, contract())["scope_reasons"]


def test_a_cut_cloudtrail_snapshot_leaves_a_key_creator_unsettled():
    key = {"evidence": "ISSUED", "credential_type": "AWS_ACCESS_KEY", "account_id": "123456789012",
           "identifier": "AKIAABCDEFGHIJKLMNOP"}
    trail = {"spec": {"provider": "aws_cloudtrail", "account_id": "123456789012"}, "enabled": True,
             "latest": {"status": "COMPLETE"}, "reasons": []}
    for truncated, status in ((False, "NOT_OBSERVED_IN_WINDOW"), (True, "INCOMPLETE")):
        _attach_key_creators([key], [], [{**trail, "truncated": truncated}])
        assert key["creator_status"] == status


def test_root_report_preserves_provider_generated_time_and_unknown_flags():
    generated = datetime.now(UTC) - timedelta(hours=3)
    class RootReport:
        def list_users(self, **_):
            return {"Users": []}
        def generate_credential_report(self):
            return {"State": "COMPLETE"}
        def get_credential_report(self):
            return {"GeneratedTime": generated, "Content": ("user,arn,password_enabled,mfa_active,access_key_1_active,access_key_2_active\n"
                f"<root_account>,arn:aws:iam::{ACCOUNT}:root,true,true,false,N/A\n").encode()}
    out = collect_iam(ConnectionSpec(name="IAM", provider="aws_iam", account_id=ACCOUNT, credential_report=True), RootReport())
    roots = [item for item in out.items if item.evidence == "ROOT_STATUS"]
    assert out.status == "COMPLETE" and len(roots) == 1
    root = roots[0]
    assert root.evidence == "ROOT_STATUS" and root.created_at == generated.isoformat()
    assert root.password_enabled is True and root.mfa_active is True and root.access_key_1_active is False and root.access_key_2_active is None
    assert root.fingerprint is None and not root.identifier


def test_absence_needs_compatibility_and_freshness_on_the_same_exposure():
    from cremore.detection import ResourceRef
    repo = InMemoryRepository()
    orch = Orchestrator(repo, config=EngineConfig(fingerprint_key=KEY))
    for location in ("old-compatible", "fresh-incompatible"):
        orch.scan_resource(GH.encode(), ResourceRef(source_type="inline", resource="synthetic", location=location), verify=False)
    old, fresh = list(repo.exposures.values())
    old.last_seen_at = datetime.now(UTC) - timedelta(days=2)
    fresh.metadata["coverage_policy_digest"] = "0" * 64
    store = CoverageStore(repo)
    owner, _ = store.create(spec(), "admin")
    save(store, owner, [])
    repo.put_setting("coverage_scope", {"confirmed": True, "revision": scope_revision(store.list_connections())}, "admin")
    assert report(repo, contract())["summary"]["unknown"] == 1
    fresh.metadata["coverage_policy_digest"] = contract()["policy_digest"]
    assert report(repo, contract())["summary"]["no_vault_match"] == 1


@pytest.mark.parametrize("environment,mode,expected", [
    ({"AWS_WEB_IDENTITY_TOKEN_FILE": "/synthetic/token"}, "local", "IRSA"),
    ({"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://169.254.170.23/v1/credentials"}, "local", "CONTAINER_ROLE"),
    ({"AWS_EC2_METADATA_DISABLED": "false"}, "local", "EC2_INSTANCE_ROLE"),
    ({}, "oidc", "SERVER_WORKLOAD"),
])
def test_server_onboarding_diagnosis_never_reads_local_credentials(monkeypatch, environment, mode, expected):
    from types import SimpleNamespace

    from cremore.api.dashboard import _sign_in_diagnosis
    for key in ("AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_EC2_METADATA_DISABLED", "AWS_PROFILE"):
        monkeypatch.delenv(key, raising=False)
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr("cremore_aws_provider.aws_identity.local_credential_sources", lambda *_: pytest.fail("Local credentials must not be inspected"))
    result = _sign_in_diagnosis(SimpleNamespace(auth_mode=mode), {"state": "NO_CREDENTIALS"})
    assert result["workload"] == expected and result["reason"] == "WORKLOAD_IDENTITY_UNAVAILABLE"


def test_cli_retries_identical_committed_requests_without_duplicate_observations(repo, monkeypatch):
    from types import SimpleNamespace

    from cremore.cli.coverage import execute
    monkeypatch.setattr("cremore.cli.coverage.time.sleep", lambda _: None)
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY=KEY.hex()))
    api, store, attempts = TestClient(app), CoverageStore(repo), {}
    connection, token = store.create(spec(), "admin")
    class SM:
        def list_secrets(self, **_):
            return {"SecretList": [{"ARN": ARN}]}
        def get_secret_value(self, **_):
            return {"ARN": ARN, "VersionId": "v1", "VersionStages": ["AWSCURRENT"], "SecretString": GH}
    session = SimpleNamespace(client=lambda name, **_: SimpleNamespace(get_caller_identity=lambda: {"Account": ACCOUNT}) if name == "sts" else SM())
    def transport(request):
        response = api.request(request.method, str(request.url), content=request.content, headers=request.headers)
        if request.method != "GET":
            previous = attempts.setdefault(request.url.path, [])
            previous.append(request.content)
            if len(previous) == 1:
                if request.method == "PUT":
                    raise httpx.ReadError("synthetic lost reply", request=request)
                return httpx.Response(503)
            assert len(previous) == 2 and previous[0] == previous[1]
        return httpx.Response(response.status_code, content=response.content, headers=response.headers)
    with httpx.Client(transport=httpx.MockTransport(transport)) as client:
        result = execute("http://localhost", connection["id"], token, KEY, client=client, aws_session=session)
    snapshots = store.snapshots(connection["id"])
    assert result["status"] == "COMPLETE" and len(snapshots) == 1 and len(snapshots[0]["items"]) == 1
    assert snapshots[0]["items"][0]["fingerprint"]
    assert GH not in json.dumps(snapshots, default=str)
    assert repo.list_findings() == []
