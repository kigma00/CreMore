import ast
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from threading import Event, local
from types import SimpleNamespace

import pytest

from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414 -- fixture re-export
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import AwsAccount
from cremore_aws_provider import aws_controltower as ct
from cremore_aws_provider import aws_org_context, aws_org_settings
from cremore_aws_provider.aws_org_context import account_context, refresh_org_context

ACCOUNT = "111111111111"
MANAGEMENT = "999999999999"
REGION = "us-east-1"
OU = "ou-abcd-12345678"
QUEUE = f"https://sqs.{REGION}.amazonaws.com/{MANAGEMENT}/cremore-controltower"
SETTINGS = SimpleNamespace(org_discovery_allowed=True, scan_sqs_allowed=True)


@pytest.fixture(params=["memory", "sqlite", "postgres"])
def repo(request, tmp_path):
    engine = None
    if request.param == "memory":
        repo = InMemoryRepository()
    elif request.param == "postgres":
        repo = request.getfixturevalue("pg")[1]
    else:
        engine = make_engine("sqlite:///" + (tmp_path / "contexts.db").as_posix())
        create_all(engine)
        repo = SqlRepository(engine)
    repo.create_aws_account(AwsAccount(account_id=ACCOUNT, name="Synthetic"))
    repo.put_setting(aws_org_settings.KEY, {"enabled": True, "external_id": "synthetic-external-id",
        "control_tower_enabled": True, "control_tower_region": REGION, "lifecycle_queue_url": QUEUE,
        "lifecycle_queue_acknowledged": True}, "admin")
    try:
        yield repo
    finally:
        if engine is not None:
            engine.dispose()


class Org:
    def describe_organization(self):
        return {"Organization": {"Id": "o-synthetic", "ManagementAccountId": MANAGEMENT}}

    def list_roots(self, **kwargs):
        return {"Roots": [{"Id": "r-abcd", "Name": "Root"}]}

    def list_accounts_for_parent(self, ParentId):
        return {"Accounts": [{"Id": ACCOUNT}] if ParentId == OU else []}

    def list_organizational_units_for_parent(self, ParentId):
        return {"OrganizationalUnits": [{"Id": OU, "Name": "Engineering"}] if ParentId == "r-abcd" else []}


class ControlTower:
    def __init__(self):
        self.calls = []
        self.rows = [self.row("ou", OU, "parent"), self.row("account", ACCOUNT, "child")]
        self.rows[1]["parentIdentifier"] = "parent"

    def row(self, kind, target, arn):
        return {"arn": arn, "baselineIdentifier": "baseline", "baselineVersion": "4.0",
                "targetIdentifier": f"arn:aws:organizations::{MANAGEMENT}:{kind}/o-synthetic/{target}",
                "statusSummary": {"status": "SUCCEEDED"},
                "driftStatusSummary": {"types": {"inheritance": {"status": "IN_SYNC"}}},
                "parameters": [{"key": "ignored", "value": "MUST_NOT_STORE_RAW_PARAMETERS"}]}

    def list_baselines(self, **kwargs):
        return {"baselines": [{"name": "AWSControlTowerBaseline", "arn": "baseline"},
                              {"name": "ConfigBaseline", "arn": "other"}]}

    def list_enabled_baselines(self, **kwargs):
        self.calls.append(kwargs)
        assert kwargs["includeChildren"] is True
        assert kwargs["filter"] == {"baselineIdentifiers": ["baseline"]}
        return {"enabledBaselines": self.rows}

    def get_enabled_baseline(self, enabledBaselineIdentifier):
        return {"enabledBaselineDetails": next(row for row in self.rows if row["arn"] == enabledBaselineIdentifier)}


def test_topology_and_child_baseline_are_distinct_account_context(repo):
    refresh_org_context(repo, Org())
    ct.collect_context(repo, Org(), ControlTower())
    context = account_context(repo, ACCOUNT)
    assert context["organization"]["parent_id"] == OU
    assert [node["name"] for node in context["organization"]["path"]] == ["Root", "Engineering"]
    assert context["control_tower"]["registered_ou_id"] == OU
    assert context["control_tower"]["account_status"] == "SUCCEEDED"
    assert "MUST_NOT_STORE_RAW_PARAMETERS" not in json.dumps(context)
    client = ControlTower()
    client.rows = client.rows[:1]
    ct.collect_context(repo, Org(), client)
    assert account_context(repo, ACCOUNT)["control_tower"]["account_status"] == "NOT_OBSERVED"


def test_partial_topology_or_ct_failure_preserves_last_successful_facts(repo):
    refresh_org_context(repo, Org())
    ct.collect_context(repo, Org(), ControlTower())
    before = account_context(repo, ACCOUNT)
    refresh_org_context(repo, object())
    ct.collect_context(repo, Org(), object())
    after = account_context(repo, ACCOUNT)
    assert after["organization"]["status"] == after["control_tower"]["status"] == "PARTIAL"
    assert after["organization"]["path"] == before["organization"]["path"]
    assert after["control_tower"]["baseline_arn"] == before["control_tower"]["baseline_arn"]
    assert after["control_tower"]["last_successful_at"] == before["control_tower"]["last_successful_at"]


def test_concurrent_organization_and_control_tower_updates_preserve_both_sections(repo, monkeypatch):
    first_read, release, second_started, second_read = Event(), Event(), Event(), Event()
    thread = local()
    original = aws_org_context.account_context

    def read(bound, account_id):
        current = original(bound, account_id)
        if getattr(thread, "section", "") == "organization":
            first_read.set()
            assert release.wait(5)
        elif getattr(thread, "section", "") == "control_tower":
            second_read.set()
        return current

    def write(section):
        thread.section = section
        if section == "control_tower":
            second_started.set()
        aws_org_context.put_account_context(repo, ACCOUNT, section, {"status": "COMPLETE", "proof": section})

    monkeypatch.setattr(aws_org_context, "account_context", read)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(write, "organization")
        try:
            assert first_read.wait(5)
            second = pool.submit(write, "control_tower")
            assert second_started.wait(5)
            # Without the transaction lock, the second read/write can race the
            # held first snapshot; release also lets a correctly locked writer finish.
            assert not second_read.wait(0.1)
        finally:
            release.set()
        first.result(timeout=5)
        second.result(timeout=5)
    context = original(repo, ACCOUNT)
    assert context["organization"]["proof"] == "organization"
    assert context["control_tower"]["proof"] == "control_tower"


def event(name="CreateManagedAccount"):
    status = {"state": "SUCCEEDED", "secret": "MUST_NOT_STORE_RAW_EVENT"}
    if "Baseline" in name:
        status = {"enabledBaselineDetails": {"statusSummary": {"status": "SUCCEEDED"}}}
    return {"id": str(uuid.uuid4()), "source": "aws.controltower", "account": MANAGEMENT,
            "region": REGION, "detail-type": "AWS Service Event via CloudTrail", "detail": {
                "eventSource": "controltower.amazonaws.com", "eventType": "AwsServiceEvent", "awsRegion": REGION,
                "eventName": name, "serviceEventDetails": {ct._EVENTS[name]: status}}}


class Queue:
    def __init__(self, body):
        self.body, self.deleted = body, []

    def receive_message(self, **kwargs):
        assert kwargs["QueueUrl"] == QUEUE and kwargs["WaitTimeSeconds"] == 0
        return {"Messages": [{"Body": json.dumps(self.body), "ReceiptHandle": "receipt"}]}

    def delete_message(self, **kwargs):
        self.deleted.append(kwargs)


def test_lifecycle_ack_after_durable_request_deduplicates_and_preserves_newer_event(repo):
    refresh_org_context(repo, Org())
    queue = Queue(event())
    factory = lambda region: queue
    assert ct.poll_lifecycle_events(repo, SETTINGS, factory)["requested"] == 1
    pending = ct.rediscovery_pending(repo)
    assert pending["event"] == "CreateManagedAccount" and queue.deleted
    assert "MUST_NOT_STORE_RAW_EVENT" not in json.dumps(repo.get_setting(ct.EVENT_KEY)["value"])
    assert ct.poll_lifecycle_events(repo, SETTINGS, factory)["requested"] == 0
    queue.body = event("UpdateManagedAccount")
    ct.poll_lifecycle_events(repo, SETTINGS, factory)
    ct.complete_rediscovery(repo, pending["id"])
    assert ct.rediscovery_pending(repo)["id"] == queue.body["id"]
    ct.complete_rediscovery(repo, queue.body["id"])
    assert ct.rediscovery_pending(repo) is None


def test_concurrent_lifecycle_events_create_one_durable_request(repo, monkeypatch):
    refresh_org_context(repo, Org())
    body = event()
    first_read, release, second_started, second_read = Event(), Event(), Event(), Event()
    thread = local()
    original = ct._locked

    def locked(repo, operation):
        def held(bound, state):
            if thread.first:
                first_read.set()
                assert release.wait(5)
            else:
                second_read.set()
            return operation(bound, state)
        return original(repo, held)

    def poll(first):
        thread.first = first
        if not first:
            second_started.set()
        return ct.poll_lifecycle_events(repo, SETTINGS, lambda _: Queue(body))

    monkeypatch.setattr(ct, "_locked", locked)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(poll, True)
        try:
            assert first_read.wait(5)
            second = pool.submit(poll, False)
            assert second_started.wait(5)
            assert not second_read.wait(0.1)
        finally:
            release.set()
        results = [first.result(timeout=5), second.result(timeout=5)]
    assert sum(result["requested"] for result in results) == 1
    assert sum(result["acknowledged"] for result in results) == 2
    assert repo.get_setting(ct.EVENT_KEY)["value"]["recent_ids"] == [body["id"]]


def test_provider_context_storage_uses_public_platform_boundary():
    for module in (aws_org_context, ct):
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                name = node.module or ""
                assert not name.startswith("sqlalchemy")
                assert not name.startswith("cremore.db.") or name == "cremore.db.settings_store"
            if isinstance(node, ast.Import):
                assert not any(alias.name.startswith(("sqlalchemy", "cremore.db.")) for alias in node.names)
            if isinstance(node, ast.Attribute):
                assert node.attr not in {"_bound", "with_for_update", "exec_driver_sql"}


def test_lifecycle_durable_write_failure_leaves_message_unacknowledged(repo, monkeypatch):
    refresh_org_context(repo, Org())
    queue = Queue(event())
    original = type(repo).put_setting

    def put_setting(self, key, value, actor):
        if key == ct.EVENT_KEY:
            raise RuntimeError("synthetic storage failure")
        return original(self, key, value, actor)

    monkeypatch.setattr(type(repo), "put_setting", put_setting)
    assert ct.poll_lifecycle_events(repo, SETTINGS, lambda _: queue)["failed"] == 1
    assert queue.deleted == [] and ct.rediscovery_pending(repo) is None


@pytest.mark.parametrize("name", ["EnableBaseline", "ResetEnabledBaseline", "UpdateEnabledBaseline", "DisableBaseline"])
def test_baseline_completion_uses_nested_status_summary(name):
    body = event(name)
    assert ct._lifecycle_event(body, MANAGEMENT, REGION)["event"] == name
    body["detail"]["serviceEventDetails"][ct._EVENTS[name]]["enabledBaselineDetails"]["statusSummary"]["status"] = "FAILED"
    with pytest.raises(ValueError):
        ct._lifecycle_event(body, MANAGEMENT, REGION)


def test_out_of_scope_unacknowledged_and_shared_content_queue_is_never_consumed(repo):
    refresh_org_context(repo, Org())
    original = event()
    for fields in ({"account": ACCOUNT}, {"region": "eu-west-1"}, {"source": "aws.s3"}):
        queue = Queue({**deepcopy(original), **fields})
        assert ct.poll_lifecycle_events(repo, SETTINGS, lambda region, queue=queue: queue)["failed"] == 1
        assert not queue.deleted and ct.rediscovery_pending(repo) is None
    repo.put_setting("scan_triggers", {"sqs_queue_url": QUEUE}, "admin")
    def forbidden(_region):
        raise AssertionError("must not consume the content queue")
    assert ct.poll_lifecycle_events(repo, SETTINGS, forbidden)["reason"] == "AWS_CONTROL_TOWER_SEPARATE_QUEUE_REQUIRED"


def test_context_settings_reject_missing_home_region_and_mismatched_queue():
    for body in ({"control_tower_enabled": True}, {"control_tower_region": "localhost"},
                 {"lifecycle_queue_url": QUEUE, "control_tower_region": "eu-west-1"},
                 {"lifecycle_queue_url": "http://127.0.0.1/queue", "control_tower_region": REGION}):
        with pytest.raises(ValueError):
            aws_org_settings.normalize_context(body)
