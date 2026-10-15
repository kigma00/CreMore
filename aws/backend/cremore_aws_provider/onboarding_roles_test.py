"""Server-role drafts use fake AWS only; no accounts exist until atomic approval."""

import datetime as dt
import json
import uuid
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError

from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414
from cremore.onboarding import check, service, sessions
from cremore.onboarding.onboarding_test import approve_aws
from cremore.onboarding.session_store import SessionStore
from cremore.onboarding.sessions_test import KEY, SETTINGS, body
from cremore.onboarding.sessions_test import repo as repo  # noqa: PLC0414
from cremore.onboarding.store import ProviderConnectionStore
from cremore_aws_provider import aws_access, aws_org_settings

A, B = "222222222222", "333333333333"
EXTERNAL = "synthetic-stackset-external-id"
SECRET = "synthetic-sts-secret-never-persist"


class World:
    def __init__(self, repo):
        self.repo, self.calls = repo, []
        self.deny, self.mismatch = None, False
        self.accepted_external = {EXTERNAL, "old-account-external"}
        self.listed = [{"Id": A, "Name": "Engineering", "State": "ACTIVE"},
                       {"Id": B, "Name": "Operations", "State": "ACTIVE"}]
        self.page = None
        self.identity_value = {"state": "READY", "account_id": "111111111111", "match_key": "iam-role:cremore",
                               "kind": "IAM_ROLE", "credential_source": "iam-role"}
        approve_aws(repo)
        repo.put_setting(aws_org_settings.KEY, {"external_id": EXTERNAL}, "admin")

    def identity(self, *_):
        return self.identity_value

    def client_factory(self, purpose, service_name, region, creds):
        world = self
        assert purpose == aws_access.SCANNER

        class Client:
            def __getattr__(self, call):
                def request(**kwargs):
                    world.calls.append((service_name, call, kwargs, creds))
                    if world.deny == call:
                        raise ClientError({"Error": {"Code": "AccessDenied", "Message": SECRET}}, call)
                    if call == "list_accounts":
                        assert service_name == "organizations" and creds is None
                        return world.page(kwargs) if world.page else {"Accounts": world.listed}
                    if call == "assume_role":
                        assert service_name == "sts" and creds is None
                        aid = kwargs["RoleArn"].split(":")[4]
                        if kwargs["ExternalId"] not in world.accepted_external:
                            raise ClientError({"Error": {"Code": "AccessDenied", "Message": SECRET}}, call)
                        return {"AssumedRoleUser": {"Arn": f"arn:aws:sts::{A if world.mismatch else aid}:assumed-role/scanner/run"},
                            "Credentials": {"AccessKeyId": aid, "SecretAccessKey": SECRET, "SessionToken": SECRET,
                                            "Expiration": dt.datetime.now(dt.UTC) + dt.timedelta(minutes=15)}}
                    assert creds and creds["AccessKeyId"] in {A, B, "111111111111"}, "never read targets with the server's own credentials"
                    if call == "list_users":
                        return {"Users": [{"Arn": f"arn:aws:iam::{creds['AccessKeyId']}:user/robot", "UserName": "robot"}]}
                    if call == "get_user":
                        return {"User": {}}
                    if call == "list_user_policies":
                        return {"PolicyNames": []}
                    if call == "list_attached_user_policies":
                        return {"AttachedPolicies": []}
                    if call == "list_groups_for_user":
                        return {"Groups": []}
                    if call == "list_buckets":
                        return {"Buckets": [{"Name": "synthetic-bucket-" + creds["AccessKeyId"]}]}
                    pytest.fail("Unexpected AWS operation " + call)
                return request
        return Client()

    def run(self, view):
        # No secret is resolved: AWS lists its scope through the scanner session (list_onboarding_scope).
        worker = SimpleNamespace(repo=self.repo, settings=SETTINGS, aws_sessions=self, metadata_secret_resolver=None,
                                 http_client_factory=lambda: pytest.fail("No HTTP or live clients"))
        check.run(worker, self.repo.get_job(uuid.UUID(view["job_id"])))
        return sessions.read(self.repo, view["id"], body(view), "admin")

    def listed_view(self):
        view = self.run(sessions.create(self.repo, SETTINGS,
            {"provider": "aws", "auth_method": "role", "browser_key": KEY}, "admin"))
        assert view["state"] == "AUTHENTICATED", view
        assert not self.calls, "Authentication must precede target/service reads"
        return self.run(sessions.discover(self.repo, view["id"], body(view, purposes=["exposure", "inventory"]), "admin"))

    def inspected(self):
        view = self.listed_view()
        assert view["state"] == "LISTED", view
        return self.run(sessions.inspect(self.repo, view["id"], body(view,
            target_ids=[r["id"] for r in view["roots"]], plans={"exposure": {}, "inventory": {}}), "admin"))


def selected(repo, view):
    return sessions.select(repo, view["id"], body(view, snapshot_id=view["snapshot_id"],
        resource_ids=[r["id"] for r in view.get("resources", [])]), "admin")


def test_multi_account_server_role_lifecycle(repo):
    world = World(repo)
    view = world.inspected()
    assert view["state"] == "CHECKED" and not view["blockers"], view
    assert len(view["roots"]) == 2 and len(view["resources"]) == 2
    assert not repo.list_aws_accounts() and not ProviderConnectionStore(repo).list()
    assert len([call for call in world.calls if call[1] == "assume_role"]) == 2
    assert SECRET not in json.dumps(SessionStore(repo).get(view["id"])["data"])
    view = selected(repo, view)
    result = sessions.complete(repo, SETTINGS, view["id"], body(view, name="Server AWS"), "admin")
    accounts = repo.list_aws_accounts()
    assert {a.account_id for a in accounts} == {A, B}
    for account in accounts:
        assert account.access == aws_access.ROLE and account.external_id == EXTERNAL
        assert account.source == "ORGANIZATION" and account.org_state == "ACTIVE" and account.org_present
        assert aws_access.use_refusal(account, aws_access.SCANNER, aws_access.approval(repo, aws_access.SCANNER)) is None
        profile = repo.list_scope_profiles("aws", account.id)[0]
        assert len(profile.selected_roots) == 1 and profile.state == "READY"
    again = sessions.complete(repo, SETTINGS, view["id"], body(view, name="retry"), "admin")
    assert again["id"] == result["id"] and len(repo.list_aws_accounts()) == 2
    assert not any(j.kind in {"scan", "scope"} for j in repo.list_jobs(100))
    # Draft pins must not make an established owner's ordinary feature editing fail.
    current = service.get(repo, result["id"])
    assert service.update_purposes(repo, SETTINGS, result["id"],
        {"expected_revision": current["revision"], "purposes": current["purposes"]}, "admin")["id"] == result["id"]


def test_review_investigations_commit_with_connection_and_roll_back_together(repo, monkeypatch):
    from cremore_aws_provider.investigation import investigation_switches as switches

    world = World(repo)
    view = selected(repo, world.inspected())
    changes = {"changes": {"usage_lookup": True, "potential_access": True},
               "expected": {"usage_lookup": False, "potential_access": False}}
    request = body(view, name="AWS investigations", aws_investigations=changes)
    with monkeypatch.context() as patch:
        def fail(bound, *_args, **_kwargs):
            assert switches.switch(bound, switches.USAGE_LOOKUP)["enabled"]
            raise ValueError("scope write failed")
        patch.setattr(sessions, "_save_scopes", fail)
        with pytest.raises(ValueError, match="scope write failed"):
            sessions.complete(repo, SETTINGS, view["id"], request, "admin")
    assert not switches.switch(repo, switches.USAGE_LOOKUP)["enabled"]
    assert not ProviderConnectionStore(repo).list()
    assert not any(e.event_type == "INSTALLATION_SETTING_CHANGED" for e in repo.list_events(100))
    result = sessions.complete(repo, SETTINGS, view["id"], request, "admin")
    assert switches.effective(SETTINGS, repo, switches.USAGE_LOOKUP)
    assert switches.effective(SETTINGS, repo, switches.POTENTIAL_ACCESS)
    assert not switches.switch(repo, switches.SECRETS_INVENTORY)["enabled"]
    assert sessions.complete(repo, SETTINGS, view["id"], request, "admin")["id"] == result["id"]
    assert [e.note for e in repo.list_events(100) if e.event_type == "INSTALLATION_SETTING_CHANGED"] == [
        "aws_investigations usage_lookup=on potential_access=on"]
    # A completed-session retry must not reapply old choices after another admin's edit.
    switches.save(repo, SETTINGS, {"usage_lookup": False}, "other-admin")
    sessions.complete(repo, SETTINGS, view["id"], request, "admin")
    assert not switches.switch(repo, switches.USAGE_LOOKUP)["enabled"]


@pytest.mark.parametrize("case", ["hidden", "bad_type", "missing_expected", "locked", "stale", "cancel"])
def test_review_investigations_reject_hidden_invalid_locked_and_stale_changes(repo, case):
    from cremore_aws_provider.investigation import investigation_switches as switches

    world = World(repo)
    view = selected(repo, world.inspected())
    options = {"changes": {"usage_lookup": True}, "expected": {"usage_lookup": False}}
    settings, code = SETTINGS, "AWS_INVESTIGATIONS_INVALID"
    if case == "hidden":
        options = {"changes": {"secrets_inventory": True}, "expected": {"secrets_inventory": False}}
    elif case == "bad_type":
        options["changes"]["usage_lookup"] = 1
    elif case == "missing_expected":
        options["expected"] = {}
    elif case == "locked":
        settings = SETTINGS.model_copy(update={"aws_usage_lookup_mode": "disabled"})
        code = "INVESTIGATION_LOCKED"
    elif case == "stale":
        switches.save(repo, SETTINGS, {"usage_lookup": True}, "other-admin")
        code = "SETTING_CHANGED_MEANWHILE"
    elif case == "cancel":
        sessions.cancel(repo, view["id"], body(view), "admin")
        assert not switches.switch(repo, switches.USAGE_LOOKUP)["enabled"]
        return
    with pytest.raises(service.OnboardingError, match=code):
        sessions.complete(repo, settings, view["id"], body(view, name="AWS", aws_investigations=options), "admin")
    assert not ProviderConnectionStore(repo).list()
    assert switches.switch(repo, switches.USAGE_LOOKUP)["enabled"] == (case == "stale")


@pytest.mark.parametrize("failure", ["assume_role", "list_users", "list_user_policies", "mismatch", "missing_external"])
def test_role_refusal_prevents_completion_without_storing_provider_text(repo, failure):
    world = World(repo)
    world.deny = failure
    world.mismatch = failure == "mismatch"
    if failure == "missing_external":
        repo.put_setting(aws_org_settings.KEY, {}, "admin")
    view = world.inspected()
    assert view["blockers"], view
    assert SECRET not in json.dumps(view)
    with pytest.raises(service.OnboardingError):
        selected(repo, view)
    assert not repo.list_aws_accounts()


def test_role_entry_failure_keeps_account_and_does_not_claim_service_permissions_missing(repo):
    world = World(repo)
    world.deny = "assume_role"
    view = world.inspected()
    for purpose, permission in (("exposure", "list_buckets"), ("inventory", "iam_read")):
        items = view["checks"]["results"][purpose]["items"]
        for account in (A, B):
            assert any(i["permission"] == "scanner_access" and i["subject"] == account
                       and i["status"] == "MISSING" and i["detail"] == "ASSUME_ROLE_DENIED" for i in items)
            assert any(i["permission"] == permission and i["subject"] == account
                       and i["status"] == "NOT_REPORTED" and i["detail"] == "SCANNER_ACCESS_REQUIRED" for i in items)
    assert not any(call[0] in {"s3", "iam"} for call in world.calls)
    assert view["blockers"] and SECRET not in json.dumps(view)


def test_organization_denial_is_not_an_empty_complete_list(repo):
    world = World(repo)
    world.deny = "list_accounts"
    view = world.listed_view()
    assert view["state"] == "LISTED" and view["completeness"] == "PARTIAL"
    assert view["discovery_notice"] == "AWS_ORGANIZATIONS_NOT_AVAILABLE"
    assert [r["target"]["accounts"] for r in view["roots"]] == [["111111111111"]]
    assert not repo.list_aws_accounts() and SECRET not in json.dumps(view)
    view = world.run(sessions.inspect(repo, view["id"], body(view, target_ids=[view["roots"][0]["id"]],
        plans={"exposure": {}, "inventory": {}}), "admin"))
    assert not view["blockers"]
    view = selected(repo, view)
    sessions.complete(repo, SETTINGS, view["id"], body(view, name="Independent"), "admin")
    [account] = repo.list_aws_accounts()
    assert account.source == "MANUAL" and account.validation_status == "VALID"


def test_draft_role_setup_pins_generated_external_id_until_access_is_granted(repo):
    world = World(repo)
    repo.put_setting(aws_org_settings.KEY, {}, "admin")
    view = world.listed_view()
    generated = view["generated"]["aws_roles"]
    assert len(generated) == 2
    external_ids = {item["parameters"]["ExternalId"] for item in generated}
    assert len(external_ids) == 2 and not repo.list_aws_accounts()
    again = world.run(sessions.discover(repo, view["id"], body(view, purposes=["inventory"]), "admin"))
    assert {item["parameters"]["ExternalId"] for item in again["generated"]["aws_roles"]} == external_ids
    blocked = world.run(sessions.inspect(repo, again["id"], body(again,
        target_ids=[r["id"] for r in again["roots"]], plans={"inventory": {}}), "admin"))
    assert blocked["blockers"] and SECRET not in json.dumps(blocked)
    world.accepted_external.update(external_ids)
    checked = world.run(sessions.inspect(repo, blocked["id"], body(blocked,
        target_ids=[r["id"] for r in blocked["roots"]], plans={"inventory": {}}), "admin"))
    assert not checked["blockers"]


def test_org_denial_keeps_exclusions_and_never_falls_back_outside_an_ou(repo):
    world = World(repo)
    world.deny = "list_accounts"
    repo.put_setting(aws_org_settings.KEY, {"excludes": ["111111111111"]}, "admin")
    view = world.listed_view()
    assert view["state"] == "FAILED" and not view.get("roots")
    repo.put_setting(aws_org_settings.KEY, {"ou_ids": ["ou-abcd-12345678"]}, "admin")
    world.deny = "list_accounts_for_parent"
    world.calls.clear()
    view = world.listed_view()
    assert view["state"] == "FAILED" and not view.get("roots")
    assert not repo.list_aws_accounts()


@pytest.mark.parametrize("change", ["config", "approval", "concurrent_account"])
def test_changes_after_check_abort_atomic_completion(repo, change):
    from cremore.domain.models import AwsAccount

    world = World(repo)
    view = selected(repo, world.inspected())
    if change == "config":
        repo.put_setting(aws_org_settings.KEY, {"external_id": "changed-external-id"}, "admin")
    elif change == "approval":
        approve_aws(repo)
    else:
        repo.create_aws_account(AwsAccount(account_id=A, name="concurrent", access="RUNTIME_IDENTITY"))
    before = len(repo.list_aws_accounts())
    with pytest.raises(ValueError) as failure:
        sessions.complete(repo, SETTINGS, view["id"], body(view, name="must fail"), "admin")
    assert getattr(failure.value, "code", "") in {"AWS_ACCOUNT_SETTINGS_CHANGED", "AWS_SCANNER_IDENTITY_CHANGED"}
    assert len(repo.list_aws_accounts()) == before and not ProviderConnectionStore(repo).list()


def test_paginated_org_listing_preserves_private_cursor_and_filters_inactive(repo):
    world = World(repo)
    world.page = lambda kwargs: {"Accounts": [{"Id": A, "Name": "Active", "State": "ACTIVE"},
        {"Id": B, "Name": "Closed", "State": "CLOSED"}],
        **({"NextToken": str(int(kwargs.get("NextToken", "0")) + 1)} if kwargs.get("NextToken") != "10" else {})}
    view = world.listed_view()
    assert view["completeness"] == "PARTIAL" and view["has_more"] and len(view["roots"]) == 1
    assert "next_token" not in json.dumps(view)
    view = world.run(sessions.discover(repo, view["id"], body(view, more=True), "admin"))
    assert view["completeness"] == "COMPLETE" and not view["has_more"]
    assert len([c for c in world.calls if c[1] == "list_accounts"]) == 11


def test_existing_custom_role_is_preserved_and_wrong_access_is_not_converted(repo):
    from cremore.domain.models import AwsAccount

    world = World(repo)
    old = repo.create_aws_account(AwsAccount(account_id=A, name="old", external_id="old-account-external",
        scanner_role_arn=f"arn:aws:iam::{A}:role/custom-scanner", access="ROLE"))
    repo.create_aws_account(AwsAccount(account_id=B, name="runtime", access="RUNTIME_IDENTITY"))
    view = world.inspected()
    assert any(b["detail"] == "ACCOUNT_REGISTERED_WITH_ANOTHER_ACCESS" for b in view["blockers"])
    assert repo.get_aws_account(old.id).external_id == "old-account-external"
    assert any(c[1] == "assume_role" and c[2]["RoleArn"].endswith("/custom-scanner") for c in world.calls)
    assert not ProviderConnectionStore(repo).list()


def test_existing_role_can_transfer_without_changing_its_trust(repo):
    from cremore.domain.models import AwsAccount

    world = World(repo)
    world.listed = world.listed[:1]
    old = repo.create_aws_account(AwsAccount(account_id=A, name="old", external_id="old-account-external",
        scanner_role_arn=f"arn:aws:iam::{A}:role/custom-scanner", access="ROLE"))
    view = selected(repo, world.inspected())
    sessions.complete(repo, SETTINGS, view["id"], body(view, name="Transferred"), "admin")
    saved = repo.get_aws_account(old.id)
    assert saved.external_id == old.external_id and saved.scanner_role_arn == old.scanner_role_arn
    assert len(repo.list_aws_accounts()) == 1 and saved.validation_status == "VALID"


def test_concurrent_disable_cannot_be_undone_by_onboarding_completion(repo):
    from cremore.domain.models import AwsAccount

    world = World(repo)
    world.listed = world.listed[:1]
    old = repo.create_aws_account(AwsAccount(account_id=A, name="old", external_id="old-account-external",
        scanner_role_arn=f"arn:aws:iam::{A}:role/custom-scanner", access="ROLE"))
    view = selected(repo, world.inspected())
    repo.update_aws_account(old.id, enabled=False)
    with pytest.raises(ValueError, match="AWS_ACCOUNT_SETTINGS_CHANGED"):
        sessions.complete(repo, SETTINGS, view["id"], body(view, name="must not resume"), "admin")
    assert repo.get_aws_account(old.id).enabled is False
    assert not ProviderConnectionStore(repo).list()


def test_excluded_accounts_are_not_offered_or_assumed(repo):
    world = World(repo)
    repo.put_setting(aws_org_settings.KEY, {"external_id": EXTERNAL, "excludes": [B]}, "admin")
    view = world.inspected()
    assert len(view["roots"]) == 1 and not view["blockers"]
    assert all(B not in call[2].get("RoleArn", "") for call in world.calls)


def test_postgres_role_completion(pg):
    test_multi_account_server_role_lifecycle(pg[1])


def test_postgres_role_completion_rolls_back_when_configuration_changed(pg):
    test_changes_after_check_abort_atomic_completion(pg[1], "config")


def test_postgres_completion_serializes_a_later_administrator_disable(pg, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    from sqlalchemy import update
    from sqlalchemy.exc import OperationalError

    from cremore.db.schema import aws_accounts
    from cremore.domain.models import AwsAccount
    from cremore.onboarding import children

    engine, repo = pg
    world = World(repo)
    world.listed = world.listed[:1]
    old = repo.create_aws_account(AwsAccount(account_id=A, name="old", external_id="old-account-external",
        scanner_role_arn=f"arn:aws:iam::{A}:role/custom-scanner", access="ROLE"))
    view = selected(repo, world.inspected())
    original = children._aws_account_taken

    def administrator_disable():
        with engine.begin() as conn:
            conn.exec_driver_sql("SET LOCAL lock_timeout = '250ms'")
            conn.execute(update(aws_accounts).where(aws_accounts.c.id == old.id).values(enabled=False))

    def after_snapshot(bound, connection, account, payload):
        # A second real transaction reaches the row after the snapshot check.
        # Without the held row lock it commits here and completion overwrites it.
        with ThreadPoolExecutor(max_workers=1) as pool, pytest.raises(OperationalError) as denied:
            pool.submit(administrator_disable).result(timeout=10)
        assert getattr(denied.value.orig, "sqlstate", None) == "55P03"
        return original(bound, connection, account, payload)

    monkeypatch.setattr(children, "_aws_account_taken", after_snapshot)
    sessions.complete(repo, SETTINGS, view["id"], body(view, name="Transferred"), "admin")
    # After completion commits, the administrator's retried decision wins.
    administrator_disable()
    assert repo.get_aws_account(old.id).enabled is False
    assert len(ProviderConnectionStore(repo).list()) == 1


@pytest.mark.parametrize("method", ["role", "runtime"])
@pytest.mark.parametrize("identity", [
    {"kind": "IDENTITY_CENTER", "credential_source": "sso"},
    {"kind": "IAM_USER", "credential_source": "env"},
    {"kind": "IAM_ROLE", "credential_source": None},
])
def test_new_connections_require_proven_server_workload(repo, method, identity):
    world = World(repo)
    world.identity_value.update(identity)
    view = world.run(sessions.create(repo, SETTINGS,
        {"provider": "aws", "auth_method": method, "browser_key": KEY}, "admin"))
    assert view["state"] == "FAILED" and view["error"] == "AWS_SERVER_WORKLOAD_IDENTITY_REQUIRED"
    assert not world.calls and not repo.list_aws_accounts()
    approved = aws_access.approval(repo, aws_access.SCANNER)
    repo.put_setting(aws_access.APPROVAL_KEYS[aws_access.SCANNER], {**approved, **identity}, "admin")
    with pytest.raises(service.OnboardingError) as failure:
        service.create(repo, SETTINGS, {"provider": "aws", "auth_method": method,
            "purposes": ["exposure"], "target": {"accounts": ["111111111111"]}}, "admin")
    assert failure.value.code == "AWS_SERVER_WORKLOAD_IDENTITY_REQUIRED"
