"""Saved synthetic AWS evidence, never provider calls or credential validation."""

import json
import re
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.config import Settings
from cremore.coverage import JOB_KIND
from cremore.coverage.models import MAX_BATCH, Batch, ConnectionSpec, Contract, Finish, Observation
from cremore.coverage.store import CoverageError, CoverageStore, utc
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import AwsAccount, ScanJob
from cremore_aws_provider import aws_access, aws_inventory_settings, inventory_view

ACCOUNT = "123456789012"
OTHER = "210987654321"
USER = f"arn:aws:iam::{ACCOUNT}:user/robot"
ROOT = f"arn:aws:iam::{ACCOUNT}:root"
ROLE = f"arn:aws:iam::{OTHER}:role/application"
SESSION = f"arn:aws:sts::{OTHER}:assumed-role/application/build"
KEY = "AKIA" + "A" * 16
TEMP = "ASIA" + "B" * 16
NOW = datetime.now(UTC)
SETTINGS = SimpleNamespace(scan_schedules_allowed=True)


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


def setup(repo, account_id=ACCOUNT, **changes):
    account = repo.create_aws_account(AwsAccount(**{
        "account_id": account_id, "name": "Synthetic", "access": "RUNTIME_IDENTITY",
        "validation_status": "VALID", "validation_key": "1:1", **changes,
    }))
    repo.put_setting(aws_access.APPROVAL_KEYS[aws_access.SCANNER], {"revision": 1}, "admin")
    repo.put_setting(aws_inventory_settings.KEY, {"enabled": True}, "admin")
    return account


def connection(repo, provider="aws_iam", account_id=ACCOUNT, **changes):
    options = {"regions": ["us-east-1", "eu-west-1"]} if provider == "aws_cloudtrail" else {}
    return CoverageStore(repo).create(ConnectionSpec(
        name="Synthetic evidence", provider=provider, account_id=account_id, **(options | changes)), "admin")[0]


def save(repo, row, items, *, status="COMPLETE", reasons=(), request_id=None):
    store = CoverageStore(repo)
    run = store.start(row["id"], row["revision"], request_id or str(uuid.uuid4()),
                      Contract(engine_digest="a" * 64).model_dump())
    batches = [items[start:start + MAX_BATCH] for start in range(0, len(items), MAX_BATCH)]
    for index, batch in enumerate(batches):
        store.append(row["id"], run["id"], Batch(index=index, items=batch))
    return store.finish(row["id"], run["id"], Finish(
        batch_count=len(batches), item_count=len(items), status=status, reasons=list(reasons)))


def issued(identifier=KEY, account_id=ACCOUNT, **changes):
    principal = f"arn:aws:iam::{account_id}:user/robot"
    return Observation(**{
        "reference": principal, "principal_arn": principal, "account_id": account_id,
        "evidence": "ISSUED", "credential_type": "AWS_ACCESS_KEY", "identifier": identifier,
        "state": "Active", "created_at": (NOW - timedelta(days=30)).isoformat(), **changes,
    })


def session(event_id, *, identifier=TEMP, evidence="USAGE", at=None, expires_at="", outcome="SUCCEEDED",
            region="us-east-1", account_id=ACCOUNT):
    at = at or NOW - timedelta(minutes=10)
    issuance = evidence == "SESSION_ISSUED"
    return Observation(
        reference="event-history/" + event_id, account_id=account_id, region=region,
        evidence=evidence, credential_type="AWS_ACCESS_KEY", identifier=identifier,
        principal_arn=SESSION, created_at=at.isoformat() if issuance else "",
        last_used_at=at.isoformat() if not issuance and outcome == "SUCCEEDED" else "",
        session={"issuer_account_id": OTHER, "recipient_account_id": account_id,
                 "issuer_arn": ROLE, "session_arn": SESSION, "caller_arn": USER if issuance else SESSION,
                 "caller_access_key_id": KEY if issuance else identifier, "source_identity": "builder",
                 "issued_at": (NOW - timedelta(hours=1)).isoformat(), "expires_at": expires_at,
                 "first_used_at": "" if issuance else at.isoformat(),
                 "last_used_at": "" if issuance else at.isoformat(), "event_id": event_id,
                 "event_name": "AssumeRole" if issuance else "GetObject", "event_source": "sts.amazonaws.com",
                 "event_category": "Management", "evidence_source": "EVENT_HISTORY", "outcome": outcome})


def principal(arn=USER):
    return Observation(reference=arn, principal_arn=arn, account_id=ACCOUNT,
        evidence="ROOT_STATUS" if arn == ROOT else "USER_STATUS", created_at=NOW.isoformat(),
        password_enabled=True, mfa_active=False, access_key_1_active=True, cert_1_active=True,
        iam_report={"generated_at": NOW.isoformat(), "user_created_at": "2020-01-02T00:00:00Z",
                    "field_status": {"password_last_used_at": "NO_INFORMATION"},
                    "access_keys": [{"slot": 1, "active": True, "last_rotated_at": "2025-01-02T00:00:00Z",
                                     "field_status": {"last_used_at": "NOT_APPLICABLE"}}],
                    "certificates": [{"slot": 1, "active": True, "last_rotated_at": "2024-01-02T00:00:00Z"}]})


def response(repo, account, **changes):
    return inventory_view.inventory_response(repo, account, settings=SETTINGS,
                                             now=datetime.now(UTC), **changes)


def test_usage_owner_uses_exact_saved_inventory_across_accounts(repo):
    setup(repo)
    setup(repo, OTHER)
    save(repo, connection(repo, account_id=OTHER), [issued("AKIA" + "C" * 16, account_id=OTHER)])
    row = connection(repo)
    run = save(repo, row, [issued()])
    owner, evidence = inventory_view.key_owner(repo, KEY, settings=SETTINGS)
    assert (owner.account_id, owner.principal_arn, owner.user_name) == (ACCOUNT, USER, "robot")
    assert evidence == {"source": "IAM_INVENTORY", "connection_id": str(row["id"]),
                        "run_id": str(run["id"]), "observed_at": inventory_view._stamp(run["finished_at"])}
    assert inventory_view.key_owner(repo, "AKIA" + "Z" * 16, settings=SETTINGS) is None
    assert inventory_view.key_owner(repo, TEMP, settings=SETTINGS) is None


@pytest.mark.parametrize("change", ["stale", "disabled", "revision", "access", "partial", "running", "ambiguous"])
def test_usage_owner_refuses_incomplete_or_conflicting_inventory(repo, change):
    account = setup(repo)
    row = connection(repo)
    save(repo, row, [issued()])
    now = datetime.now(UTC)
    store = CoverageStore(repo)
    if change == "stale":
        now += timedelta(days=8)
    elif change == "disabled":
        store.change(row["id"], row["revision"], "admin", enabled=False)
    elif change == "revision":
        store.change(row["id"], row["revision"], "admin", rotate=True)
    elif change == "access":
        repo.update_aws_account(account.id, validation_status="INVALID")
    elif change == "running":
        store.start(row["id"], row["revision"], str(uuid.uuid4()), Contract(engine_digest="a" * 64).model_dump())
    else:
        setup(repo, OTHER)
        other = connection(repo, account_id=OTHER)
        save(repo, other, [issued(account_id=OTHER)], status="PARTIAL" if change == "partial" else "COMPLETE",
             reasons=["REQUEST_LIMIT"] if change == "partial" else [])
    assert inventory_view.key_owner(repo, KEY, settings=SETTINGS, now=now) is None


@pytest.mark.parametrize("field,value", [
    ("account_id", OTHER), ("principal_arn", f"arn:aws:iam::{OTHER}:user/robot"),
    ("credential_type", "AWS_SERVICE_CREDENTIAL"), ("evidence", "IDENTIFIER"),
    ("version_state", "PREVIOUS"), ("extra_field", "invalid"),
])
def test_usage_owner_does_not_trust_invalid_or_out_of_scope_saved_rows(repo, monkeypatch, field, value):
    setup(repo)
    save(repo, connection(repo), [issued()])
    original = CoverageStore.snapshots

    def snapshots(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        result[0]["items"][0][field] = value
        return result

    monkeypatch.setattr(CoverageStore, "snapshots", snapshots)
    assert inventory_view.key_owner(repo, KEY, settings=SETTINGS) is None


def test_usage_owner_limit_is_aggregate_and_cannot_hide_a_conflict(repo, monkeypatch):
    setup(repo)
    setup(repo, OTHER)
    save(repo, connection(repo), [issued()])
    save(repo, connection(repo, account_id=OTHER), [issued(account_id=OTHER)])
    monkeypatch.setattr(inventory_view, "MAX_OBSERVATIONS", 1)
    assert inventory_view.key_owner(repo, KEY, settings=SETTINGS) is None


def test_account_isolation_and_rich_report_operation_session_response(repo):
    account = setup(repo)
    setup(repo, OTHER)
    iam = connection(repo)
    trail = connection(repo, "aws_cloudtrail")
    foreign = connection(repo, account_id=OTHER)
    save(repo, foreign, [issued(account_id=OTHER, state="Inactive")])
    key = issued(last_used_at=(NOW - timedelta(days=1)).isoformat(), iam_last_used={
        "status": "AVAILABLE", "checked_at": NOW.isoformat(), "service": "s3", "region": "eu-west-1"})
    operation = Observation(reference="account/" + ACCOUNT, account_id=ACCOUNT, evidence="OPERATION",
        operation={"name": "CREDENTIAL_REPORT", "status": "COMPLETE", "requests": 2, "records": 2})
    service = issued("ACCA" + "C" * 16, credential_type="AWS_SERVICE_CREDENTIAL", service="codecommit.amazonaws.com")
    save(repo, iam, [key, service, principal(), principal(ROOT), operation])
    save(repo, trail, [session("key-use", identifier=KEY),
                      session("issue", evidence="SESSION_ISSUED", expires_at=(NOW + timedelta(hours=1)).isoformat())])

    result = response(repo, account)
    inventory = result["inventory"]
    records = {record["match_id"]: record for record in inventory["records"]}
    assert inventory["account_id"] == ACCOUNT and inventory["total"] == 3
    assert inventory["iam_user_total"] == 1 and len(inventory["root_status"]) == 1
    assert all(record["account_id"] == ACCOUNT for record in records.values())
    assert records[KEY]["provider_status"] == "Active" and records[KEY]["current_evidence"]
    assert records[KEY]["iam_last_used"]["region"] == "eu-west-1"
    assert records[KEY]["last_used_service"] == "s3"
    assert records[KEY]["first_observed_use_at"] == (NOW - timedelta(minutes=10)).isoformat()
    assert records[service.identifier]["credential_class"] == "SERVICE_SPECIFIC"
    temporary = records[TEMP]
    assert temporary["credential_class"] == "TEMPORARY_STS"
    assert temporary["issuer_account_id"] == OTHER and temporary["recipient_account_id"] == ACCOUNT
    assert temporary["issuer_arn"] == USER and temporary["session_issuer_arn"] == ROLE
    assert temporary["source_identity"] == "builder"
    assert temporary["expiry_status"] == "NOT_EXPIRED"
    assert temporary["provider_status"] == "OBSERVED_ISSUANCE"
    assert temporary["field_status"]["current_validity"] == "NOT_VERIFIABLE"
    user = inventory["iam_users"][0]
    assert user["password_enabled"] is True and user["mfa_active"] is False
    assert user["iam_report"]["access_keys"][0]["field_status"]["last_used_at"] == "NOT_APPLICABLE"
    assert user["iam_report"]["certificates"][0]["last_rotated_at"] == "2024-01-02T00:00:00Z"
    assert inventory["root_status"][0]["created_at"] == "2020-01-02T00:00:00Z"
    assert any(row.get("operation") == "CREDENTIAL_REPORT" and row["status"] == "COMPLETE"
               and row["records_observed"] == 2 for row in inventory["coverage"])
    encoded = json.dumps(result)
    assert "fingerprint" not in encoded and "session_token" not in encoded and "token_hash" not in encoded


def test_last_complete_survives_several_failed_runs_without_claiming_current(repo):
    account = setup(repo)
    row = connection(repo)
    first = save(repo, row, [issued(), principal()])
    for _ in range(4):
        save(repo, row, [], status="FAILED", reasons=["IAM_USER_LIST_DENIED"])
    inventory = response(repo, account)["inventory"]
    assert inventory["total"] == 1 and inventory["iam_user_total"] == 1
    assert inventory["records"][0]["match_id"] == KEY
    assert not inventory["records"][0]["current_evidence"]
    assert not inventory["iam_users"][0]["current_evidence"]
    assert inventory["collection_status"] == "FAILED"
    assert datetime.fromisoformat(inventory["collected_at"]) == utc(first["finished_at"])
    summary = inventory_view.inventory_summary(repo, account, settings=SETTINGS)
    assert datetime.fromisoformat(summary["last_success_at"]) == utc(first["finished_at"])
    assert "IAM_USER_LIST_DENIED" in summary["reasons"]


def test_repeated_partial_runs_do_not_displace_last_complete_baseline(repo):
    account = setup(repo)
    row = connection(repo)
    save(repo, row, [issued(), principal()])
    for index in range(4):
        save(repo, row, [issued("AKIA" + f"{index:016d}")], status="PARTIAL", reasons=["REQUEST_LIMIT"])
    inventory = response(repo, account)["inventory"]
    assert KEY in {record["match_id"] for record in inventory["records"]}
    assert inventory["iam_user_total"] == 1 and not inventory["iam_users"][0]["current_evidence"]
    assert inventory["collection_status"] == "PARTIAL"
    assert all(not record["current_evidence"] for record in inventory["records"])


@pytest.mark.parametrize("change", ["stale", "connection_disabled", "revision", "account_disabled", "access_invalid", "partial"])
def test_old_facts_are_retained_but_current_evidence_requires_all_conditions(repo, change):
    account = setup(repo)
    row = connection(repo)
    save(repo, row, [issued()])
    original_revision = response(repo, account)["inventory"]["snapshot_revision"]
    now = datetime.now(UTC)
    if change == "stale":
        now += timedelta(days=8)
    elif change == "connection_disabled":
        CoverageStore(repo).change(row["id"], row["revision"], "admin", enabled=False)
    elif change == "revision":
        CoverageStore(repo).change(row["id"], row["revision"], "admin", rotate=True)
    elif change == "account_disabled":
        account = repo.update_aws_account(account.id, enabled=False)
    elif change == "access_invalid":
        account = repo.update_aws_account(account.id, validation_status="INVALID")
    else:
        save(repo, row, [issued()], status="PARTIAL", reasons=["REQUEST_LIMIT"])
    inventory = inventory_view.inventory_response(repo, account, settings=SETTINGS, now=now)["inventory"]
    assert inventory["total"] == 1 and not inventory["records"][0]["current_evidence"]
    if change != "stale":
        assert inventory["snapshot_revision"] != original_revision
    if change in ("connection_disabled", "account_disabled"):
        assert inventory["collection_status"] == "PARTIAL"


@pytest.mark.parametrize("conflicting_field", ["principal", "status"])
def test_conflicting_latest_iam_key_facts_never_claim_a_current_status(repo, conflicting_field):
    account = setup(repo)
    row = connection(repo)
    other_principal = f"arn:aws:iam::{ACCOUNT}:user/other-robot"
    conflicting = (issued(reference=other_principal, principal_arn=other_principal)
                   if conflicting_field == "principal" else issued(state="Inactive"))
    save(repo, row, [issued(), conflicting])
    inventory = response(repo, account)["inventory"]
    assert inventory["total"] == 1
    record = inventory["records"][0]
    assert record["current_evidence"] is False and record["provider_status"] == "UNKNOWN"
    assert record["field_status"]["provider_status"] == "STALE_OR_CONFLICTING"


@pytest.mark.parametrize("state", ["Active", "Inactive", "Expired"])
def test_a_status_the_latest_collection_no_longer_reports_is_not_current(repo, state):
    account = setup(repo)
    row = connection(repo)
    save(repo, row, [issued(state=state)])
    save(repo, row, [])
    record = response(repo, account)["inventory"]["records"][0]
    # An expired API key is no exception: stale evidence says nothing about what IAM reports now.
    assert record["current_evidence"] is False and record["provider_status"] == "UNKNOWN"


def test_new_complete_iam_status_supersedes_historical_status_without_false_conflict(repo):
    account = setup(repo)
    row = connection(repo)
    save(repo, row, [issued()])
    save(repo, row, [issued(state="Inactive")])
    record = response(repo, account)["inventory"]["records"][0]
    assert record["current_evidence"] is True and record["provider_status"] == "Inactive"


@pytest.mark.parametrize("reverse", [False, True])
def test_sts_merging_is_order_independent_and_denied_events_are_not_successful_use(repo, reverse):
    account = setup(repo)
    row = connection(repo, "aws_cloudtrail")
    expires = (NOW + timedelta(hours=1)).isoformat()
    items = [session("issue", evidence="SESSION_ISSUED", expires_at=expires),
             session("use", at=NOW - timedelta(minutes=5)),
             session("denied", at=NOW - timedelta(minutes=1), outcome="DENIED")]
    save(repo, row, list(reversed(items)) if reverse else items)
    record = response(repo, account)["inventory"]["records"][0]
    assert record["expires_at"] == expires and record["expiry_status"] == "NOT_EXPIRED"
    assert record["first_observed_use_at"] == record["last_observed_use_at"] == (NOW - timedelta(minutes=5)).isoformat()
    assert set(record["evidence_event_ids"]) == {"issue", "use", "denied"}
    assert record["issuer_arn"] == USER and record["session_issuer_arn"] == ROLE
    assert record["provider_status"] == "OBSERVED_ISSUANCE"


@pytest.mark.parametrize("kind", ["conflict", "missing", "expired"])
def test_sts_expiration_requires_consistent_observed_expiration(repo, kind):
    account = setup(repo)
    row = connection(repo, "aws_cloudtrail")
    items = [session("use")]
    if kind != "missing":
        expiration = NOW + timedelta(hours=1) if kind == "conflict" else NOW - timedelta(minutes=1)
        items.append(session("issue", evidence="SESSION_ISSUED", expires_at=expiration.isoformat()))
    if kind == "conflict":
        items.append(session("conflicting-issue", evidence="SESSION_ISSUED", expires_at=(NOW + timedelta(hours=2)).isoformat()))
    save(repo, row, items)
    record = response(repo, account)["inventory"]["records"][0]
    assert record["expiry_status"] == ("EXPIRED" if kind == "expired" else "UNKNOWN")
    assert record["provider_status"] != "Active"
    assert record["field_status"]["current_validity"] == "NOT_VERIFIABLE"
    if kind != "expired":
        assert not record["expires_at"]


@pytest.mark.parametrize("conflicting_field", ["account", "issuer_arn", "principal"])
def test_conflicting_sts_identity_facts_remove_current_and_expiry_claims(repo, conflicting_field):
    account = setup(repo)
    row = connection(repo, "aws_cloudtrail")
    expiration = (NOW + timedelta(hours=1)).isoformat()
    first = session("issue", evidence="SESSION_ISSUED", expires_at=expiration)
    conflicting = session("another-issue", evidence="SESSION_ISSUED", expires_at=expiration)
    if conflicting_field == "account":
        conflicting.session.issuer_account_id = ACCOUNT
        conflicting.session.issuer_arn = ROLE.replace(OTHER, ACCOUNT)
        conflicting.session.session_arn = SESSION.replace(OTHER, ACCOUNT)
        conflicting.principal_arn = conflicting.session.session_arn
    elif conflicting_field == "issuer_arn":
        conflicting.session.issuer_arn = ROLE.replace("application", "different-role")
    else:
        conflicting.principal_arn = SESSION.replace("/build", "/different-session")
    save(repo, row, [first, conflicting])
    record = response(repo, account)["inventory"]["records"][0]
    assert record["current_evidence"] is False
    assert record["expiry_status"] == "UNKNOWN" and not record["expires_at"]
    assert record["field_status"]["expires_at"] == "STALE_OR_CONFLICTING"


def test_sts_issuer_account_must_agree_with_its_saved_issuer_and_session_arns(repo):
    account = setup(repo)
    row = connection(repo, "aws_cloudtrail")
    item = session("issue", evidence="SESSION_ISSUED", expires_at=(NOW + timedelta(hours=1)).isoformat())
    item.session.issuer_account_id = ACCOUNT  # Both saved identity ARNs still identify OTHER.
    save(repo, row, [item])
    record = response(repo, account)["inventory"]["records"][0]
    assert record["current_evidence"] is False and record["expiry_status"] == "UNKNOWN"
    assert not record["expires_at"]


def test_pages_cover_keys_and_users_with_one_revision_and_do_not_duplicate_roots(repo):
    account = setup(repo)
    row = connection(repo)
    keys = [issued("AKIA" + f"{index:016d}") for index in range(3)]
    users = [principal(f"arn:aws:iam::{ACCOUNT}:user/user-{index}") for index in range(5)]
    save(repo, row, keys + users + [principal(ROOT)])
    first = response(repo, account, limit=2)["inventory"]
    revision = first["snapshot_revision"]
    assert re.fullmatch("[0-9a-f]{64}", revision)
    pages = [first] + [response(repo, account, offset=offset, limit=2, snapshot_revision=revision)["inventory"]
                       for offset in (2, 4)]
    assert [len(page["records"]) for page in pages] == [2, 1, 0]
    assert [len(page["iam_users"]) for page in pages] == [2, 2, 1]
    assert [page["next_offset"] for page in pages] == [2, 4, None]
    assert all(page["total"] == 3 and page["iam_user_total"] == 5 for page in pages)
    assert all(page["snapshot_revision"] == revision and len(page["root_status"]) == 1 for page in pages)
    assert len({record["match_id"] for page in pages for record in page["records"]}) == 3
    save(repo, row, keys + users)
    with pytest.raises(CoverageError, match="INVENTORY_SNAPSHOT_CHANGED"):
        response(repo, account, offset=2, limit=2, snapshot_revision=revision)


def test_http_inventory_pages_are_account_scoped_and_changed_revision_returns_409(repo):
    account = setup(repo)
    other = setup(repo, OTHER)
    row = connection(repo)
    foreign = connection(repo, account_id=OTHER)
    keys = [issued(), issued("AKIA" + "0" * 16), issued("AKIA" + "1" * 16)]
    foreign_key = "AKIA" + "9" * 16
    save(repo, row, keys + [principal(), principal(ROOT)])
    save(repo, foreign, [issued(account_id=OTHER, state="Inactive"), issued(foreign_key, account_id=OTHER)])
    token = "synthetic-inventory-admin-" + "x" * 32
    api = TestClient(create_app(repo=repo,
        settings=Settings(AUTH_MODE="local", API_TOKEN=token, FINGERPRINT_KEY="ab" * 32),
        aws_identity_probe=lambda **kwargs: {"state": "NO_CREDENTIALS"}))
    path = f"/api/v1/aws/accounts/{account.id}/credential-inventory"
    headers = {"Authorization": "Bearer " + token}
    assert api.get(path).status_code == 401
    first_response = api.get(path, headers=headers, params={"limit": 2})
    assert first_response.status_code == 200
    first = first_response.json()["inventory"]
    assert first["total"] == 3 and first["iam_user_total"] == 1 and first["next_offset"] == 2
    second_response = api.get(path, headers=headers,
        params={"limit": 2, "offset": 2, "snapshot_revision": first["snapshot_revision"]})
    assert second_response.status_code == 200
    second = second_response.json()["inventory"]
    records = {record["match_id"]: record for page in (first, second) for record in page["records"]}
    assert len(records) == 3 and foreign_key not in records
    assert records[KEY]["provider_status"] == "Active"
    assert all(record["account_id"] == ACCOUNT for record in records.values())
    assert second["next_offset"] is None and len(second["records"]) == 1 and not second["iam_users"]
    assert second["snapshot_revision"] == first["snapshot_revision"]
    assert second["root_status"] == first["root_status"]
    other_response = api.get(f"/api/v1/aws/accounts/{other.id}/credential-inventory", headers=headers)
    assert other_response.status_code == 200
    assert other_response.json()["inventory"]["account_id"] == OTHER
    assert {record["match_id"] for record in other_response.json()["inventory"]["records"]} == {KEY, foreign_key}
    save(repo, row, keys + [issued("AKIA" + "2" * 16)])
    changed = api.get(path, headers=headers,
        params={"offset": 2, "limit": 2, "snapshot_revision": first["snapshot_revision"]})
    assert changed.status_code == 409 and changed.json()["error"] == "INVENTORY_SNAPSHOT_CHANGED"


def test_summary_reads_run_metadata_without_observation_batches(repo, monkeypatch):
    account = setup(repo)
    row = connection(repo, schedule_minutes=60)
    saved = save(repo, row, [issued()])

    def no_batches(*args, **kwargs):
        pytest.fail("summary must not load saved observations")

    monkeypatch.setattr(CoverageStore, "_batches", no_batches)
    monkeypatch.setattr(CoverageStore, "snapshots", no_batches)
    summary = inventory_view.inventory_summary(repo, account, settings=SETTINGS)
    assert summary["status"] == "COMPLETE" and summary["schedule_minutes"] == 60
    assert datetime.fromisoformat(summary["last_success_at"]) == utc(saved["finished_at"])
    assert summary["last_attempt_at"] and summary["reasons"] == []


@pytest.mark.parametrize("source,minutes,enabled,allowed,expected", [
    ("connection", 60, False, True, 60),
    ("connection", 0, True, True, 0),
    ("connection", 60, True, False, 0),
    ("installation", 0, True, True, 1440),
    ("installation", 0, False, True, 0),
    ("installation", 60, True, True, 60),
])
def test_summary_uses_the_connection_schedule_source(repo, source, minutes, enabled, allowed, expected):
    account = setup(repo)
    repo.put_setting(aws_inventory_settings.KEY, {"enabled": enabled}, "admin")
    connection(repo, schedule_source=source, schedule_minutes=minutes)
    summary = inventory_view.inventory_summary(
        repo, account, settings=SimpleNamespace(scan_schedules_allowed=allowed), now=NOW)
    assert summary["schedule_minutes"] == expected


def test_summary_ignores_manual_connections_when_another_is_scheduled(repo):
    account = setup(repo)
    connection(repo, schedule_source="connection", schedule_minutes=0)
    connection(repo, schedule_source="connection", schedule_minutes=60)
    summary = inventory_view.inventory_summary(repo, account, settings=SETTINGS, now=NOW)
    assert summary["schedule_minutes"] == 60


def test_inventory_has_no_hidden_5000_observation_cap(repo):
    account = setup(repo)
    row = connection(repo)
    save(repo, row, [issued("AKIA" + f"{index:016d}") for index in range(5002)])
    first = response(repo, account)["inventory"]
    assert first["total"] == 5002 and len(first["records"]) == 5000 and first["next_offset"] == 5000
    last = response(repo, account, offset=5000, snapshot_revision=first["snapshot_revision"])["inventory"]
    assert last["total"] == 5002 and len(last["records"]) == 2 and last["next_offset"] is None
    assert not ({record["match_id"] for record in first["records"]}
                & {record["match_id"] for record in last["records"]})


def test_refresh_prefers_active_job_across_connections_and_beyond_500_newer_jobs(repo):
    account = setup(repo)
    iam = connection(repo)
    trail = connection(repo, "aws_cloudtrail")
    active = repo.enqueue_job(ScanJob(kind=JOB_KIND, payload={"coverage_connection_id": str(iam["id"])}))
    for _ in range(501):
        repo.enqueue_job(ScanJob(kind="irrelevant"))
    terminal = repo.enqueue_job(ScanJob(kind=JOB_KIND, payload={"coverage_connection_id": str(trail["id"])}))
    repo.fail_job(terminal.id, "synthetic-private-provider-error")
    result = response(repo, account)
    assert result["refresh"]["id"] == str(active.id) and result["refresh"]["status"] == "QUEUED"
    assert "synthetic-private-provider-error" not in json.dumps(result)
    repo.complete_job(active.id, objects=0, findings=0)
    terminal_result = response(repo, account)
    assert terminal_result["refresh"]["status"] == "FAILED"
    assert "synthetic-private-provider-error" not in json.dumps(terminal_result)


@pytest.mark.parametrize(("older_status", "newer_status", "expected"), [
    ("FAILED", "COMPLETE", "FAILED"),
    ("PARTIAL", "COMPLETE", "PARTIAL"),
    ("FAILED", "PARTIAL", "FAILED"),
    ("COMPLETE", "COMPLETE", "COMPLETE"),
])
def test_terminal_refresh_aggregates_each_connection_before_claiming_completion(repo, older_status, newer_status, expected):
    account = setup(repo)
    iam = connection(repo)
    trail = connection(repo, "aws_cloudtrail")
    for row, status in ((iam, older_status), (trail, newer_status)):
        job = repo.enqueue_job(ScanJob(kind=JOB_KIND, payload={"coverage_connection_id": str(row["id"])}))
        items = [issued()] if row == iam else [session("trail-use")]
        save(repo, row, items if status != "FAILED" else [], status=status,
             reasons=["REQUEST_LIMIT"] if status == "PARTIAL" else [], request_id=str(job.id))
        if status == "FAILED":
            repo.fail_job(job.id, "synthetic-private-provider-error")
        else:
            repo.complete_job(job.id, objects=len(items), findings=0)
    result = response(repo, account)
    assert result["refresh"]["status"] == expected
    assert "synthetic-private-provider-error" not in json.dumps(result)
    active = repo.enqueue_job(ScanJob(kind=JOB_KIND, payload={"coverage_connection_id": str(iam["id"])}))
    refreshed = response(repo, account)["refresh"]
    assert refreshed["status"] == "QUEUED" and refreshed["id"] == str(active.id)


def test_successful_job_without_saved_run_cannot_claim_complete_evidence(repo):
    account = setup(repo)
    row = connection(repo)
    job = repo.enqueue_job(ScanJob(kind=JOB_KIND, payload={"coverage_connection_id": str(row["id"])}))
    repo.complete_job(job.id, objects=0, findings=0)
    assert response(repo, account)["refresh"]["status"] != "COMPLETE"


def test_observation_budget_is_global_and_explicitly_removes_current_claims(repo, monkeypatch):
    account = setup(repo)
    for index in range(3):
        row = connection(repo)
        save(repo, row, [issued("AKIA" + f"{index * 3 + offset:016d}") for offset in range(3)])
    monkeypatch.setattr(inventory_view, "MAX_OBSERVATIONS", 4)
    loaded = []
    original = CoverageStore.snapshots

    def bounded(self, cid, *args, **kwargs):
        assert kwargs.get("max_items") is not None
        snapshots = original(self, cid, *args, **kwargs)
        loaded.append(sum(len(row["items"]) for row in snapshots))
        return snapshots

    monkeypatch.setattr(CoverageStore, "snapshots", bounded)
    inventory = response(repo, account)["inventory"]
    assert sum(loaded) <= 4 and inventory["total"] <= 4
    assert inventory["limitations"] and all(not record["current_evidence"] for record in inventory["records"])


def test_session_evidence_event_arrays_are_bounded(repo, monkeypatch):
    account = setup(repo)
    row = connection(repo, "aws_cloudtrail")
    save(repo, row, [session("use-" + str(index)) for index in range(5)])
    monkeypatch.setattr(inventory_view, "MAX_EVIDENCE_ITEMS", 2)
    record = response(repo, account)["inventory"]["records"][0]
    assert len(record["evidence_event_ids"]) == 2
    assert set(record["evidence_event_ids"]) <= {"use-" + str(index) for index in range(5)}


def test_legacy_observations_without_optional_fields_still_render(repo, monkeypatch):
    account = setup(repo)
    row = connection(repo)
    save(repo, row, [issued()])
    original = CoverageStore.snapshots

    def legacy(self, cid, *args, **kwargs):
        snapshots = original(self, cid, *args, **kwargs)
        for saved in snapshots:
            for item in saved["items"]:
                for name in ("iam_report", "iam_last_used", "operation", "session", "session_fingerprint"):
                    item.pop(name, None)
        return snapshots

    monkeypatch.setattr(CoverageStore, "snapshots", legacy)
    record = response(repo, account)["inventory"]["records"][0]
    assert record["match_id"] == KEY and record["credential_class"] == "LONG_LIVED"
    assert record["current_evidence"] is True
