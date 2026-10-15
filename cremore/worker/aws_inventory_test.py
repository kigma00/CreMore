"""Offline orchestration proof: discovery -> validation -> per-account schedule."""

import time
from types import SimpleNamespace

from cremore_aws_provider import (
    aws_access,
    aws_controltower,
    aws_inventory_settings,
    aws_org_settings,
)
from cremore_aws_provider.aws_identity import ROLE_CHECK_JOB
from cremore_aws_provider.aws_org_context import SUMMARY_KEY, account_context

from cremore.config import Settings
from cremore.coverage import JOB_KIND
from cremore.coverage.store import CoverageStore
from cremore.db.repository import InMemoryRepository
from cremore.worker import JobWorker

ACCOUNT = "111111111111"


class Organizations:
    def __init__(self):
        self.calls = 0
        self.failed = False

    def get_paginator(self, operation):
        assert operation == "list_accounts"
        return self

    def paginate(self):
        self.calls += 1
        if self.failed:
            raise PermissionError("synthetic refusal")
        return [{"Accounts": [{"Id": ACCOUNT, "Name": "Synthetic", "State": "ACTIVE"}]}]

    def describe_organization(self):
        return {"Organization": {"Id": "o-synthetic", "ManagementAccountId": "999999999999"}}

    def list_roots(self):
        return {"Roots": [{"Id": "r-abcd", "Name": "Root"}]}

    def list_accounts_for_parent(self, **kwargs):
        return {"Accounts": [{"Id": ACCOUNT}]}

    def list_organizational_units_for_parent(self, **kwargs):
        return {"OrganizationalUnits": []}


class Sessions:
    def __init__(self, repo):
        self.repo = repo

    def refusal(self, account_id, purpose):
        account = next(a for a in self.repo.list_aws_accounts() if a.account_id == account_id)
        approved = aws_access.approval(self.repo, purpose)
        return aws_access.use_refusal(account, purpose, approved), account, approved


def worker(repo, org, **kwargs):
    settings = Settings(FINGERPRINT_KEY="ab" * 32)
    repo.put_setting(aws_access.APPROVAL_KEYS[aws_access.SCANNER], {"revision": 1, "match_key": "synthetic"}, "admin")
    repo.put_setting(aws_org_settings.KEY, {"enabled": True, "external_id": "synthetic-external",
                                           "auto_validate": True}, "admin")
    repo.put_setting(aws_inventory_settings.KEY, {"enabled": True}, "admin")
    return JobWorker(repo, settings=settings, org_client_factory=lambda: org, aws_sessions=Sessions(repo),
        aws_identity_probe=lambda: {"state": "READY", "match_key": "synthetic"},
        aws_role_checker=lambda a: SimpleNamespace(status="VALID", code="SCANNER_ROLE_ASSUMED"), **kwargs)


def test_worker_discovers_validates_and_automatically_schedules_account_inventory():
    repo, org = InMemoryRepository(), Organizations()
    w = worker(repo, org)
    w._maybe_discover_org_accounts()
    assert len(repo.list_aws_accounts()) == 1
    assert [j.kind for j in repo.list_jobs()] == [ROLE_CHECK_JOB]
    assert CoverageStore(repo).list_connections() == []
    assert w.process_next()
    assert repo.list_aws_accounts()[0].validation_status == "VALID"
    w._last_trigger_poll = 0
    w.poll_triggers()
    jobs = [j for j in repo.list_jobs() if j.kind == JOB_KIND]
    assert len(jobs) == 1 and jobs[0].payload["account_id"] == ACCOUNT
    assert jobs[0].payload["aws_inventory_scheduled"] is True
    assert jobs[0].payload["access_pin"] == "1:1"
    w._last_trigger_poll = 0
    w.poll_triggers()
    assert len([j for j in repo.list_jobs() if j.kind == JOB_KIND]) == 1


def test_worker_event_accelerates_discovery_and_keeps_failed_request_for_retry():
    repo, org = InMemoryRepository(), Organizations()
    w = worker(repo, org)
    w._maybe_discover_org_accounts()
    before = org.calls
    w._maybe_discover_org_accounts()
    assert org.calls == before
    aws_controltower.request_rediscovery(repo)
    pending = aws_controltower.rediscovery_pending(repo)
    org.failed = True
    w._maybe_discover_org_accounts()
    assert org.calls == before + 1 and aws_controltower.rediscovery_pending(repo) == pending
    w._maybe_discover_org_accounts()
    assert org.calls == before + 1  # failed event attempts are bounded
    org.failed = False
    w._last_org_event_attempt = (pending["id"], time.monotonic() - 61)
    w._maybe_discover_org_accounts()
    assert org.calls == before + 2 and aws_controltower.rediscovery_pending(repo) is None
    # A lost event still gets picked up by the normal periodic sweep.
    w._last_org_discovery = time.monotonic() - 3601
    w._maybe_discover_org_accounts()
    assert org.calls == before + 3


def test_worker_ct_access_failure_is_context_only_and_does_not_block_account_discovery():
    repo, org = InMemoryRepository(), Organizations()
    called = []
    def ct_factory(account_id, region):
        called.append((account_id, region))
        raise aws_access.AccessBlocked("ACCOUNT_NOT_CONNECTED")
    w = worker(repo, org, control_tower_client_factory=ct_factory)
    value = repo.get_setting(aws_org_settings.KEY)["value"]
    repo.put_setting(aws_org_settings.KEY, {**value, "control_tower_enabled": True,
                                           "control_tower_region": "us-east-1"}, "admin")
    w._maybe_discover_org_accounts()
    assert called == [("999999999999", "us-east-1")]
    assert len(repo.list_aws_accounts()) == 1
    assert account_context(repo, ACCOUNT)["control_tower"]["reason"] == "ACCOUNT_NOT_CONNECTED"
    assert repo.get_setting(SUMMARY_KEY)["value"]["status"] == "COMPLETE"


def test_cli_uses_approved_management_session_for_ct_and_home_region_queue(monkeypatch):
    import boto3

    from cremore.cli.worker import build_worker

    w = build_worker(Settings(FINGERPRINT_KEY="ab" * 32), InMemoryRepository())
    calls = []
    class Session:
        def client(self, service, region):
            calls.append((service, region))
            return "ct-client"
    def open_session(account_id, purpose):
        calls.append((account_id, purpose))
        return Session()
    monkeypatch.setattr(w.aws_sessions, "open", open_session)
    monkeypatch.setattr(boto3, "client", lambda service, **kwargs: calls.append((service, kwargs)) or "queue-client")
    assert w.control_tower_client_factory("999999999999", "eu-west-1") == "ct-client"
    assert calls[:2] == [("999999999999", "scanner"), ("controltower", "eu-west-1")]
    assert w.lifecycle_sqs_client_factory("eu-west-1") == "queue-client"
    assert calls[-1] == ("sqs", {"region_name": "eu-west-1"})
    assert len(calls) == 3
