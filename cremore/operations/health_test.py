"""Connection health over content, coverage and AWS accounts, on every repository."""

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cremore_aws_provider import aws_access
from cremore_aws_provider.aws_identity import APPROVED_IDENTITY_KEY, WORKER_IDENTITY_KEY
from fastapi.testclient import TestClient
from sqlalchemy import update

from cremore.api import create_app
from cremore.config import Settings
from cremore.coverage.models import ConnectionSpec, Contract, Finish
from cremore.coverage.store import CoverageStore
from cremore.db.postgres_scan_test import (
    pg as pg,  # noqa: PLC0414 -- explicit pytest fixture re-export
)
from cremore.db.repository import InMemoryRepository
from cremore.db.schema import scan_jobs
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import AwsAccount, Connection, ScanJob, ScopeProfile
from cremore.operations import health
from cremore.scanning import changes, trigger_settings
from cremore.scanning.triggers_test import setup, switch_triggers

TOKEN = "health-test-" + "t" * 32
SETTINGS = Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32)
ACCOUNT = "123456789012"
ROLE_KEY = f"role:aws:{ACCOUNT}:CreMoreWorker"


@pytest.fixture(params=["memory", "sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def repo(request):
    if request.param == "memory":
        return InMemoryRepository()
    if request.param == "postgres":
        return request.getfixturevalue("pg")[1]
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


def now():
    return datetime.now(UTC)


def content(repo, *, name="app", provider="github", config=None, **evidence):
    """A content connection; keyword arguments are its last credential-check evidence."""
    c = repo.create_connection(Connection(provider=provider, name=name, status="ACTIVE", config=config or {},
                                          secret_ref="vault://synthetic/token"))
    if evidence:
        repo.update_connection(c.id, credential_evidence=evidence)
    return repo.get_connection(c.id)


def job(repo, c, status, at, error=None, kind="github", coverage=None):
    queued = repo.enqueue_job(ScanJob(kind=kind, connection_id=c.id))
    if isinstance(repo, InMemoryRepository):
        stored = repo.get_job(queued.id)
        stored.status, stored.finished_at, stored.error, stored.coverage = status, at, error, coverage
    else:
        with repo.engine.begin() as conn:
            conn.execute(update(scan_jobs).where(scan_jobs.c.id == queued.id).values(
                status=status, finished_at=at, error=error, coverage=coverage))
    return queued


def schedule(repo, c, minutes=60):
    repo.put_setting(trigger_settings.KEY, {"schedules_enabled": True}, "admin")
    repo.create_scope_profile(ScopeProfile(kind=c.provider, connection_id=c.id, name="daily", state="READY",
                                           schedule_minutes=minutes, approved_by="admin", approved_at=now()))


def one(repo, key_prefix, **kwargs):
    items = [item for item in health.evaluate(repo, SETTINGS, **kwargs) if item["key"].startswith(key_prefix)]
    assert len(items) == 1, items
    return items[0]


def vault(repo, **kwargs):
    store = CoverageStore(repo)
    spec = ConnectionSpec(name="Vault", provider="aws_secrets_manager", account_id=ACCOUNT,
                          regions=["us-east-1"], **kwargs)
    return store, store.create(spec, "admin")[0]


def run(store, owner, status="COMPLETE", reasons=()):
    started = store.start(owner["id"], owner["revision"], str(uuid.uuid4()), Contract(engine_digest="d" * 64).model_dump())
    return store.finish(owner["id"], started["id"], Finish(batch_count=0, item_count=0, status=status,
                                                            reasons=list(reasons)))


def worker_reports(repo, **report):
    repo.put_setting(APPROVED_IDENTITY_KEY, {"revision": 1, "match_key": ROLE_KEY}, "admin")
    repo.put_setting(WORKER_IDENTITY_KEY, {"state": "READY", "kind": "IAM_ROLE", "match_key": ROLE_KEY, **report},
                     "worker")


@pytest.mark.parametrize("code, state", [
    ("SECRET_UNAVAILABLE", "SECRET_UNAVAILABLE"), ("METADATA_SECRET_UNAVAILABLE", "SECRET_UNAVAILABLE"),
    ("SECRET_STORE_AUTH_REJECTED", "SECRET_UNAVAILABLE"), ("SECRET_STORE_FORBIDDEN", "SECRET_UNAVAILABLE"),
    ("GCP_OAUTH_REAUTH_REQUIRED", "REAUTH_REQUIRED"), ("GITHUB_APP_REJECTED", "REAUTH_REQUIRED"),
    ("AZURE_DEVOPS_AUTHENTICATION_FAILED", "REAUTH_REQUIRED"), ("COLLECTOR_UNAUTHORIZED", "REAUTH_REQUIRED"),
    ("VAULT_AUTH_METADATA_REJECTED", "REAUTH_REQUIRED"), ("AWS_LOGIN_REQUIRED", "REAUTH_REQUIRED"),
    ("NO_CREDENTIALS", "REAUTH_REQUIRED"), ("GCP_OAUTH_SCOPE_REQUIRED", "REAUTH_REQUIRED"),
    ("AWS_SCANNER_IDENTITY_CHANGED", "REAUTH_REQUIRED"), ("AUTH_EXPIRED", "REAUTH_REQUIRED"),
    ("PERMISSION_DENIED", "PERMISSION_LIMITED"), ("GCP_PERMISSION_DENIED_OR_API_DISABLED", "PERMISSION_LIMITED"),
    ("ACCESS_DENIED", "PERMISSION_LIMITED"), ("ASSUME_ROLE_DENIED", "PERMISSION_LIMITED"),
    ("IAM_USER_LIST_DENIED", "PERMISSION_LIMITED"), ("INSUFFICIENT_PERMISSION", "PERMISSION_LIMITED"),
    ("NOT_AUTHORIZED", "PERMISSION_LIMITED"), ("AZURE_STORAGE_PERMISSION_DENIED", "PERMISSION_LIMITED"),
    ("SOURCE_HTTP_FAILED", None), ("SOURCE_COLLECTION_INCOMPLETE", None), ("RUN_EXPIRED", None),
    ("METADATA_COLLECTION_PAUSE_EXPIRED", None), ("GCP_OAUTH_TEMPORARILY_UNAVAILABLE", None),
    ("GCP_OAUTH_RATE_LIMITED", None), ("TEMPORARY_CREDENTIAL_NOT_EXPECTED_IN_VAULT", None), ("", None), (None, None),
])
def test_failure_codes_map_onto_one_authentication_vocabulary(code, state):
    assert health.classify(code) == state


def test_the_most_severe_code_wins_and_names_itself():
    assert health.worst(["PERMISSION_DENIED", "SECRET_STORE_AUTH_REJECTED", "RUN_EXPIRED"]) == (
        "SECRET_UNAVAILABLE", "SECRET_STORE_AUTH_REJECTED")
    assert health.worst(["RUN_EXPIRED"]) == (None, None)


def test_expiry_stages_apply_only_to_credentials_that_do_not_renew_themselves():
    t = now()
    stage = health.expiry_stage
    assert [stage(t + timedelta(days=d), "MANUAL", t) for d in (20, 10, 2)] == ["NONE", "D14", "D3"]
    assert stage(t - timedelta(seconds=1), "MANUAL", t) == "EXPIRED"
    assert stage(t + timedelta(days=1), "AUTO", t) == "NONE"
    assert stage(None, "MANUAL", t) == "NONE"


def test_a_scope_on_the_installation_default_full_scan_counts_as_scheduled(repo):
    c = content(repo, status="ACTIVE", checked_at=(now() - timedelta(hours=2)).isoformat())
    schedule(repo, c, minutes=0)  # no cadence of its own: the daily default full scan runs it
    item = one(repo, "content:")
    assert (item["freshness"], item["stale_after_hours"]) == ("NEVER_COLLECTED", 72)
    repo.put_setting(trigger_settings.KEY, {"schedules_enabled": True, "full_scan_default_minutes": 0}, "admin")
    assert one(repo, "content:")["freshness"] == "NOT_SCHEDULED"


def test_content_health_reads_the_check_the_scans_and_the_schedule(repo):
    c = content(repo, status="ACTIVE", checked_at=(now() - timedelta(hours=2)).isoformat())
    item = one(repo, "content:")
    assert (item["auth_state"], item["auth_renewal"], item["freshness"], item["last_status"]) == (
        "READY", "MANUAL", "NOT_SCHEDULED", "NOT_COLLECTED")
    schedule(repo, c, minutes=60)
    item = one(repo, "content:")
    assert (item["freshness"], item["stale_after_hours"]) == ("NEVER_COLLECTED", 24)
    job(repo, c, "SUCCEEDED", now() - timedelta(hours=1))
    assert one(repo, "content:")["freshness"] == "FRESH"
    assert one(repo, "content:", now=now() + timedelta(hours=25))["freshness"] == "STALE"
    job(repo, c, "FAILED", now() - timedelta(minutes=30), error="SOURCE_HTTP_FAILED: 401")
    item = one(repo, "content:")
    assert (item["auth_state"], item["last_status"], item["last_failure_code"]) == (
        "READY", "FAILED", "SOURCE_HTTP_FAILED")
    job(repo, c, "FAILED", now() - timedelta(minutes=10), error="GITHUB_APP_REJECTED: provider text")
    item = one(repo, "content:")
    assert (item["auth_state"], item["auth_reason"]) == ("REAUTH_REQUIRED", "GITHUB_APP_REJECTED")
    assert "provider text" not in str(item)
    job(repo, c, "SUCCEEDED", now())
    item = one(repo, "content:")
    assert (item["auth_state"], item["last_failure_code"], item["last_status"]) == ("READY", None, "COMPLETE")
    repo.update_connection(c.id, status="DISABLED")
    item = one(repo, "content:")
    assert (item["auth_state"], item["freshness"]) == ("DISABLED", "NOT_SCHEDULED")


HELD = {"root_coverage_complete": False, "policy_held": 1}


@pytest.mark.parametrize("coverage, status", [
    ({**HELD, "policy_held_only": True}, "COMPLETE"),  # the upgrade hold alone: the next full scan reads the rest
    ({**HELD, "inspection_gaps": 1}, "PARTIAL"),  # the hold and a gap of the root's own
    ({**HELD, "failed": 1}, "PARTIAL"),  # the hold and an object that could not be read
    ({"root_coverage_complete": False}, "PARTIAL"),  # no hold
])
def test_a_run_partial_only_for_the_upgrade_hold_is_not_a_partial_collection(repo, coverage, status):
    c = content(repo, status="ACTIVE", checked_at=(now() - timedelta(hours=2)).isoformat())
    job(repo, c, "SUCCEEDED", now() - timedelta(minutes=5), coverage=coverage)
    assert one(repo, "content:")["last_status"] == status


def test_an_unchecked_connection_is_ready_once_a_scan_has_read_it(repo):
    c = content(repo)
    assert one(repo, "content:")["auth_state"] == "UNKNOWN"
    job(repo, c, "SUCCEEDED", now())
    assert one(repo, "content:")["auth_state"] == "READY"


def test_expiry_comes_from_the_provider_first_then_the_operator(repo):
    checked = now().isoformat()
    c = content(repo, status="ACTIVE", checked_at=checked, expires_at=(now() + timedelta(days=10)).isoformat())
    item = one(repo, "content:")
    assert (item["auth_state"], item["expiry_stage"], item["expires_source"]) == ("EXPIRING", "D14", "PROVIDER")
    repo.update_connection(c.id, credential_evidence={"status": "ACTIVE", "checked_at": checked,
                                                      "expires_at": (now() + timedelta(days=2)).isoformat()})
    assert one(repo, "content:")["expiry_stage"] == "D3"
    repo.update_connection(c.id, credential_evidence={"status": "ACTIVE", "checked_at": checked,
                                                      "expires_at": (now() - timedelta(hours=1)).isoformat()})
    item = one(repo, "content:")
    assert (item["auth_state"], item["auth_reason"], item["expiry_stage"]) == (
        "REAUTH_REQUIRED", "AUTH_EXPIRED", "EXPIRED")
    repo.update_connection(c.id, credential_evidence={"status": "ACTIVE", "checked_at": checked,
                                                      "refresh_supported": True,
                                                      "expires_at": (now() + timedelta(hours=1)).isoformat()})
    item = one(repo, "content:")
    assert (item["auth_state"], item["auth_renewal"], item["expiry_stage"]) == ("READY", "AUTO", "NONE")
    repo.update_connection(c.id, credential_evidence={"status": "ACTIVE", "checked_at": checked})
    repo.put_setting(health.EXPIRY_PREFIX + f"content:{c.id}",
                     {"expires_at": (now() + timedelta(days=5)).isoformat()}, "admin")
    item = one(repo, "content:")
    assert (item["auth_state"], item["expires_source"], item["expiry_stage"]) == ("EXPIRING", "OPERATOR", "D14")


def test_a_connection_not_read_yet_is_warned_of_an_entered_expiry(repo):
    c = content(repo)
    assert one(repo, "content:")["auth_state"] == "UNKNOWN"
    repo.put_setting(health.EXPIRY_PREFIX + f"content:{c.id}",
                     {"expires_at": (now() + timedelta(days=5)).isoformat()}, "admin")
    item = one(repo, "content:")
    assert (item["auth_state"], item["auth_reason"], item["expiry_stage"]) == ("EXPIRING", "AUTH_EXPIRING", "D14")
    assert {"code": "CONTENT_EXPIRING", "resource_type": "connection", "resource_id": str(c.id)} in health.alerts([item], SETTINGS)
    # A collection never run is warned the same way, and its alert names its own kind.
    _store, owner = vault(repo)
    repo.put_setting(health.EXPIRY_PREFIX + f"coverage:{owner['id']}",
                     {"expires_at": (now() + timedelta(days=2)).isoformat()}, "admin")
    item = one(repo, "coverage:")
    assert (item["auth_state"], item["expiry_stage"], item["last_status"]) == ("EXPIRING", "D3", "NOT_COLLECTED")
    assert f"{item['kind']}_EXPIRING" in {alert["code"] for alert in health.alerts([item], SETTINGS)}


def test_renewal_follows_how_each_content_credential_is_held(repo):
    content(repo, name="app", config={"auth_kind": "GITHUB_APP"})
    assert one(repo, "content:")["auth_renewal"] == "AUTO"
    repo.create_connection(Connection(provider="aws", name="bucket", status="ACTIVE", config={}))
    worker_reports(repo, kind="IDENTITY_CENTER")
    s3 = next(i for i in health.evaluate(repo, SETTINGS) if i["provider"] == "s3")
    assert s3["auth_renewal"] == "HUMAN_SESSION"
    repo.put_setting(WORKER_IDENTITY_KEY, {"state": "LOGIN_REQUIRED", "error_code": "TokenRetrievalError"}, "worker")
    s3 = next(i for i in health.evaluate(repo, SETTINGS) if i["provider"] == "s3")
    assert (s3["auth_state"], s3["auth_reason"], s3["auth_renewal"]) == (
        "REAUTH_REQUIRED", "AWS_LOGIN_REQUIRED", "HUMAN_SESSION")


def test_a_customer_side_vault_is_judged_by_its_uploads(repo):
    store, owner = vault(repo)
    item = one(repo, "coverage:")
    assert (item["kind"], item["auth_state"], item["auth_renewal"], item["freshness"]) == (
        "VAULT", "UNKNOWN", "EXTERNAL", "NEVER_COLLECTED")
    run(store, owner)
    item = one(repo, "coverage:")
    assert (item["auth_state"], item["freshness"], item["stale_after_hours"], item["last_status"]) == (
        "READY", "FRESH", 24, "COMPLETE")
    assert one(repo, "coverage:", now=now() + timedelta(hours=25))["freshness"] == "STALE"
    run(store, owner, "FAILED", ["PERMISSION_DENIED", "SOURCE_COLLECTION_INCOMPLETE"])
    item = one(repo, "coverage:")
    assert (item["auth_state"], item["last_failure_code"], item["last_status"], item["freshness"]) == (
        "PERMISSION_LIMITED", "PERMISSION_DENIED", "FAILED", "FRESH")
    run(store, owner, "FAILED", ["NETWORK_UNAVAILABLE"])
    item = one(repo, "coverage:")
    assert (item["auth_state"], item["last_failure_code"]) == ("READY", "NETWORK_UNAVAILABLE")
    run(store, owner, "PARTIAL", ["ACCESS_DENIED"])
    item = one(repo, "coverage:")
    assert (item["auth_state"], item["last_failure_code"], item["last_status"]) == (
        "PERMISSION_LIMITED", None, "PARTIAL")
    run(store, owner)
    assert one(repo, "coverage:")["auth_state"] == "READY"
    store.change(owner["id"], owner["revision"], "admin", enabled=False)
    item = one(repo, "coverage:")
    assert (item["auth_state"], item["freshness"]) == ("DISABLED", "NOT_SCHEDULED")


def test_a_scheduled_collection_waits_three_intervals_before_it_is_stale(repo):
    store, owner = vault(repo, server_collection=True, schedule_minutes=720)
    run(store, owner)
    worker_reports(repo)
    item = one(repo, "coverage:")
    assert (item["stale_after_hours"], item["auth_renewal"]) == (36, "AUTO")
    assert one(repo, "coverage:", now=now() + timedelta(hours=30))["freshness"] == "FRESH"
    assert one(repo, "coverage:", now=now() + timedelta(hours=37))["freshness"] == "STALE"


def test_schema_two_renewal_and_run_states_use_the_same_rules():
    renewal = health._coverage_renewal
    assert [renewal({"schema_version": 2, "auth_type": kind}, SETTINGS, "UNKNOWN")
            for kind in ("github_app", "adc", "workload_identity", "google_oauth", "token", "bearer")] == [
        "AUTO", "AUTO", "AUTO", "AUTO", "MANUAL", "MANUAL"]
    assert renewal({"schema_version": 2, "auth_type": "bearer", "secret_refs": {"refresh_token": "x"}},
                   SETTINGS, "UNKNOWN") == "AUTO"
    assert renewal({"provider": "vault", "server_collection": True}, SETTINGS, "UNKNOWN") == "MANUAL"
    kube = Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32, SECRET_STORE_AUTH_MODE="kubernetes")
    assert renewal({"provider": "vault", "server_collection": True}, kube, "UNKNOWN") == "AUTO"
    # A connection's own Vault login decides: its token is replaced by an admin, a role logs in by itself.
    assert renewal({"provider": "vault", "server_collection": True, "server_auth": {"method": "token"}}, kube, "UNKNOWN") == "MANUAL"
    assert renewal({"provider": "vault", "server_collection": True, "server_auth": {"method": "kubernetes"}},
                   SETTINGS, "UNKNOWN") == "AUTO"
    t = now()
    row = {"enabled": True, "spec": {"freshness_hours": 24, "schedule_minutes": 0}}
    failed = {"status": "FAILED", "reasons": ["GCP_OAUTH_REAUTH_REQUIRED"], "finished_at": t, "started_at": t}
    part = health._coverage_parts(row, {"finished": failed, "success": None}, t)
    assert (part["state"], part["reason"], part["failure_code"], part["freshness"]) == (
        "REAUTH_REQUIRED", "GCP_OAUTH_REAUTH_REQUIRED", "GCP_OAUTH_REAUTH_REQUIRED", "NEVER_COLLECTED")


def test_an_aws_account_combines_access_sign_in_and_inventory(repo):
    account = repo.create_aws_account(AwsAccount(account_id=ACCOUNT, name="prod", access="RUNTIME_IDENTITY",
                                                 validation_status="VALID", validation_key="1:1"))
    worker_reports(repo)
    item = one(repo, "aws_account:")
    assert (item["auth_state"], item["auth_renewal"], item["freshness"]) == ("READY", "AUTO", "NOT_SCHEDULED")
    store = CoverageStore(repo)
    inventory, _ = store.create(ConnectionSpec(name="IAM", provider="aws_iam", account_id=ACCOUNT), "admin")
    assert not [i for i in health.evaluate(repo, SETTINGS) if i["key"].startswith("coverage:")]
    run(store, inventory)
    assert one(repo, "aws_account:")["freshness"] == "FRESH"
    run(store, inventory, "FAILED", ["IAM_USER_LIST_DENIED"])
    item = one(repo, "aws_account:")
    assert (item["auth_state"], item["auth_reason"], item["last_failure_code"]) == (
        "PERMISSION_LIMITED", "IAM_USER_LIST_DENIED", "IAM_USER_LIST_DENIED")
    repo.put_setting(WORKER_IDENTITY_KEY, {"state": "LOGIN_REQUIRED"}, "worker")
    item = one(repo, "aws_account:")
    assert (item["auth_state"], item["auth_reason"], item["auth_renewal"]) == (
        "REAUTH_REQUIRED", "AWS_LOGIN_REQUIRED", "HUMAN_SESSION")
    worker_reports(repo)
    repo.update_aws_account(account.id, validation_status="INVALID", validation_detail="ASSUME_ROLE_DENIED")
    item = one(repo, "aws_account:")
    assert (item["auth_state"], item["auth_reason"]) == ("PERMISSION_LIMITED", "ASSUME_ROLE_DENIED")
    repo.update_aws_account(account.id, enabled=0)
    item = one(repo, "aws_account:")
    assert (item["auth_state"], item["freshness"]) == ("DISABLED", "NOT_SCHEDULED")
    assert aws_access.SCANNER  # the scanner purpose is the one judged here


def test_repository_reads_used_by_health(repo):
    for key in ("connection-expiry:b", "connection-expiry:a", "connection-expiryX", "a%b", "axb"):
        repo.put_setting(key, {"expires_at": None}, "admin")
    assert [r["key"] for r in repo.list_settings("connection-expiry:")] == ["connection-expiry:a", "connection-expiry:b"]
    assert [r["key"] for r in repo.list_settings("a%")] == ["a%b"]
    assert all(r["updated_at"].tzinfo for r in repo.list_settings("connection-expiry:"))
    c, other = content(repo, name="one"), content(repo, name="two")
    t = now()
    job(repo, c, "SUCCEEDED", t - timedelta(hours=2))
    newest = job(repo, c, "SUCCEEDED", t - timedelta(hours=1))
    failed = job(repo, other, "FAILED", t, error="SOURCE_HTTP_FAILED")
    job(repo, other, "SUCCEEDED", t - timedelta(hours=3), kind="credential-check")
    successes = repo.latest_connection_jobs(("github",), "SUCCEEDED")
    assert set(successes) == {c.id} and successes[c.id].id == newest.id
    assert successes[c.id].finished_at.tzinfo
    assert repo.latest_connection_jobs(("github",), "FAILED")[other.id].id == failed.id


def test_roles_anywhere_certificate_health_is_separate_from_temporary_session_expiry(repo):
    account = repo.create_aws_account(AwsAccount(account_id=ACCOUNT, name="prod", access="RUNTIME_IDENTITY",
                                                 validation_status="VALID", validation_key="1:1"))
    worker_reports(repo, renewal_health={"state": "EXPIRING", "certificate_expires_at": (now() + timedelta(days=10)).isoformat()})
    item = one(repo, "aws_account:")
    assert (item["auth_state"], item["auth_renewal"], item["auth_reason"]) == (
        "EXPIRING", "AUTO", "AWS_ROLES_ANYWHERE_CERTIFICATE_EXPIRING")
    assert health.alerts([item], SETTINGS)[0]["code"] == "AWS_ACCOUNT_EXPIRING"
    worker_reports(repo, renewal_health={"state": "ERROR", "error_code": "AWS_ROLES_ANYWHERE_CERTIFICATE_EXPIRED_OR_NOT_YET_VALID"})
    assert one(repo, "aws_account:")["auth_state"] == "REAUTH_REQUIRED"
    assert health.aws_identity_hold(repo).startswith("AWS_ROLES_ANYWHERE_")
    assert one(repo, "aws_account:", now=now() + timedelta(minutes=6))["auth_state"] == "READY"
    worker_reports(repo, renewal_health={"state": "READY"})
    assert one(repo, "aws_account:")["auth_state"] == "READY"
    repo.update_aws_account(account.id, enabled=0)
    worker_reports(repo, renewal_health={"state": "ERROR", "error_code": "AWS_ROLES_ANYWHERE_HELPER_CHANGED"})
    assert one(repo, "aws_account:")["auth_state"] == "DISABLED"


def test_worker_certificate_does_not_override_external_collectors(repo):
    store, owner = vault(repo)
    run(store, owner)
    worker_reports(repo, renewal_health={"state": "ERROR", "error_code": "AWS_ROLES_ANYWHERE_HELPER_CHANGED"})
    item = one(repo, "coverage:")
    assert item["auth_renewal"] == "EXTERNAL" and item["auth_state"] == "READY"
    assert "renewal_health" not in item


def test_the_api_serves_health_and_records_an_operator_expiry(repo):
    client = TestClient(create_app(repo=repo, settings=SETTINGS))
    auth = {"Authorization": f"Bearer {TOKEN}"}
    c = content(repo, status="ACTIVE", checked_at=now().isoformat())
    store, owner = vault(repo)
    run(store, owner)
    body = client.get("/api/v1/operations/connections", headers=auth).json()
    assert body["summary"]["total"] == 2 and body["summary"]["auth_states"]["READY"] == 2
    key = f"content:{c.id}"
    path = f"/api/v1/operations/connections/{key}/expiry"
    assert client.put("/api/v1/operations/connections/content:" + str(uuid.uuid4()) + "/expiry", headers=auth,
                      json={"expires_at": None}).status_code == 404
    assert client.put(path, headers=auth, json={"expires_at": "2027-01-01T00:00:00"}).status_code == 422
    assert client.put(path, headers=auth, json={"expires_at": "1999-01-01T00:00:00Z"}).status_code == 422
    assert client.put(path, headers=auth, json={}).status_code == 422
    expires = (now() + timedelta(days=7)).replace(microsecond=0)
    item = client.put(path, headers=auth, json={"expires_at": expires.isoformat()}).json()
    assert (item["expires_source"], item["auth_state"], item["expiry_stage"]) == ("OPERATOR", "EXPIRING", "D14")
    item = client.put(path, headers=auth, json={"expires_at": None}).json()
    assert (item["expires_at"], item["auth_state"]) == (None, "READY")
    actions = [row["action"] for row in client.get("/api/v1/audit", headers=auth).json()]
    assert actions[:2] == ["CONNECTION_EXPIRY_CLEARED", "CONNECTION_EXPIRY_DECLARED"]
    status = client.get("/api/v1/operations/status", headers=auth).json()
    assert status["connection_health"]["total"] == 2
    later = health.alerts(health.evaluate(repo, SETTINGS, now=now() + timedelta(hours=25)), SETTINGS)
    assert {"code": "VAULT_STALE", "resource_type": "vault", "resource_id": str(owner["id"])} in later


def test_a_person_sign_in_is_an_alert_on_a_shared_server(repo):
    repo.create_connection(Connection(provider="aws", name="bucket", status="ACTIVE", config={}))
    worker_reports(repo, kind="IDENTITY_CENTER")
    items = health.evaluate(repo, SETTINGS)
    assert not health.alerts(items, SETTINGS)
    oidc = SETTINGS.model_copy(update={"auth_mode": "oidc"})
    assert {"code": "HUMAN_SESSION_IN_SERVER_DEPLOYMENT", "resource_type": "aws_identity",
            "resource_id": "worker"} in health.alerts(items, oidc)


def test_the_installations_own_alerts_lead_and_outlast_the_cap_on_per_job_alerts(repo):
    """A busy team install has a hundred failed jobs to show and still says it leans on a person's sign-in."""
    from cremore.api.conftest import GROUPS, FakeIssuer, oidc_settings

    issuer = FakeIssuer()
    bucket = repo.create_connection(Connection(provider="aws", name="bucket", status="ACTIVE", config={}))
    worker_reports(repo, kind="IDENTITY_CENTER")
    for _ in range(101):
        job(repo, bucket, "FAILED", now(), error="SYNTHETIC_FAILURE")
    client = TestClient(create_app(repo=repo, settings=oidc_settings(FINGERPRINT_KEY="ab" * 32), oidc_http_client=issuer))
    admin = {"Authorization": "Bearer " + issuer.mint(groups=(GROUPS["admin"],))}
    status = client.get("/api/v1/operations/status", headers=admin).json()
    codes = [alert["code"] for alert in status["alerts"]]
    assert status["alerts_truncated"] and codes[0] == "HUMAN_SESSION_IN_SERVER_DEPLOYMENT"
    assert len(codes) == 101 and codes.count("HUMAN_SESSION_IN_SERVER_DEPLOYMENT") == 1 and codes[-1] == "JOB_FAILED"


T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def failing_feed(repo, codes, *, since=T0, looked=T0 + timedelta(minutes=55), name="test"):
    """An approved, event-enabled GitHub scope whose roots' last looks failed with these codes, the n-th root's
    failures starting n minutes before ``since``."""
    _repo, connection, profile, _item, _settings = setup("github", repo=repo, name=name)
    for number, code in enumerate(codes):
        changes.CursorStore(repo).put(f"{connection.id.hex}-{number}", profile.id, connection.id, {
            "cursor": "a" * 40, "error": code, "failing_since": (since - timedelta(minutes=number)).isoformat()}, looked)
    return connection, profile


def feed_alerts(repo, at):
    return health.feed_alerts(repo, SETTINGS, health.evaluate(repo, SETTINGS, now=at), now=at)


@pytest.mark.parametrize("codes, code", [
    (["SOURCE_RATE_LIMITED"], "CHANGE_FEED_RATE_LIMITED"), (["NOTION_RATE_LIMITED"], "CHANGE_FEED_RATE_LIMITED"),
    (["SOURCE_UNAVAILABLE"], "CHANGE_FEED_UNAVAILABLE"), (["SOURCE_HTTP_FAILED"], "CHANGE_FEED_FAILING"),
    (["EVENT_KEY_REFUSED"], "CHANGE_FEED_FAILING"),
    (["SOURCE_RATE_LIMITED", "SOURCE_RATE_LIMITED"], "CHANGE_FEED_RATE_LIMITED"),
    (["SOURCE_RATE_LIMITED", "SOURCE_UNAVAILABLE"], "CHANGE_FEED_FAILING"),
])
def test_a_change_feed_failing_for_over_an_hour_is_an_alert_naming_why(repo, codes, code):
    connection, _profile = failing_feed(repo, codes)
    assert feed_alerts(repo, T0 + timedelta(minutes=59)) == []
    assert feed_alerts(repo, T0 + timedelta(minutes=61)) == [{
        "code": code, "resource_type": "connection", "resource_id": str(connection.id), "provider": "github",
        "failing_roots": len(codes), "failing_since": (T0 - timedelta(minutes=len(codes) - 1)).isoformat(),
        "error_codes": sorted(set(codes))}]


def test_every_connection_s_feed_alert_is_raised_however_many_roots_one_connection_fails(repo):
    """The read is counted per connection and code: a throttle failing a thousand roots of one connection hides no
    other connection's alert, and its count is the whole."""
    big, _profile = failing_feed(repo, ["SOURCE_RATE_LIMITED"] * 1001, name="big")
    small, _profile = failing_feed(repo, ["SOURCE_HTTP_FAILED"], name="small")
    alerts = feed_alerts(repo, T0 + timedelta(minutes=61))
    assert [(alert["resource_id"], alert["code"], alert["failing_roots"]) for alert in alerts] == [
        (str(big.id), "CHANGE_FEED_RATE_LIMITED", 1001), (str(small.id), "CHANGE_FEED_FAILING", 1)]
    assert alerts[0]["failing_since"] == (T0 - timedelta(minutes=1000)).isoformat()


def test_a_change_feed_alert_only_for_a_feed_still_read(repo):
    """A paused or event-off scope, feeds switched off, a stopped connection, a removed scope's cursor and a root the
    feed no longer looks at raise nothing."""
    connection, profile = failing_feed(repo, ["SOURCE_UNAVAILABLE"])
    at = T0 + timedelta(hours=2)
    assert [alert["code"] for alert in feed_alerts(repo, at)] == ["CHANGE_FEED_UNAVAILABLE"]
    switch_triggers(repo, change_feeds_enabled=False)
    assert feed_alerts(repo, at) == []
    switch_triggers(repo, change_feeds_enabled=True)
    for field, off, on in (("event_mode", "DISABLED", "ENABLED"), ("state", "PAUSED", "READY")):
        repo.update_scope_profile(profile.id, **{field: off})
        assert feed_alerts(repo, at) == [], field
        repo.update_scope_profile(profile.id, **{field: on})
    assert len(feed_alerts(repo, at)) == 1
    repo.update_connection(connection.id, status="DISABLED")
    assert feed_alerts(repo, at) == []
    other, _profile = failing_feed(repo, [], name="other")
    changes.CursorStore(repo).put("removed", uuid.uuid4(), other.id, {"error": "SOURCE_UNAVAILABLE",
                                  "failing_since": T0.isoformat()}, at - timedelta(minutes=1))
    assert feed_alerts(repo, at) == []
    # Its last look 55 minutes in: GitHub's interval (5 minutes) and an hour after it, it is not being read.
    repo.update_connection(connection.id, status="ACTIVE")
    assert len(feed_alerts(repo, T0 + timedelta(minutes=55 + 65))) == 1
    assert feed_alerts(repo, T0 + timedelta(minutes=55 + 66)) == []
    # Each root by its own provider's interval: a long Notion interval keeps no GitHub root, a longer GitHub one does.
    switch_triggers(repo, change_feed_minutes={"notion": 1440})
    assert feed_alerts(repo, T0 + timedelta(minutes=55 + 66)) == []
    switch_triggers(repo, change_feed_minutes={"github": 30})
    assert len(feed_alerts(repo, T0 + timedelta(minutes=55 + 90))) == 1
    assert feed_alerts(repo, T0 + timedelta(minutes=55 + 91)) == []


def test_the_operations_status_lists_a_failing_change_feed_before_the_per_job_alerts(repo):
    """A hundred failed jobs fill the status's cap on per-connection and per-job alerts; the feed's alert is still in it."""
    connection, _profile = failing_feed(repo, ["SOURCE_RATE_LIMITED"], since=now() - timedelta(hours=3),
                                        looked=now() - timedelta(minutes=1))
    for _ in range(101):
        job(repo, connection, "FAILED", now(), error="SYNTHETIC_FAILURE")
    client = TestClient(create_app(repo=repo, settings=SETTINGS))
    status = client.get("/api/v1/operations/status", headers={"Authorization": f"Bearer {TOKEN}"}).json()
    assert status["alerts_truncated"]
    [alert] = [alert for alert in status["alerts"] if alert["code"].startswith("CHANGE_FEED_")]
    assert (alert["code"], alert["resource_type"], alert["resource_id"], alert["failing_roots"]) == (
        "CHANGE_FEED_RATE_LIMITED", "connection", str(connection.id), 1)
