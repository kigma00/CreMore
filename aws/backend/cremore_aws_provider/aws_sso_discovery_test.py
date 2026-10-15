from types import SimpleNamespace

from cremore.db.repository import InMemoryRepository
from cremore.domain.models import AwsAccount
from cremore_aws_provider import aws_access
from cremore_aws_provider.aws_sso_discovery import reconcile_sso_accounts

SET = "CreMoreScanner"


class FakeSso:
    """Paginated sso:ListAccounts / ListAccountRoles over a plain mapping."""

    def __init__(self, assigned):
        # assigned: {account_id: (name, [role names] or Exception)}
        self.assigned = assigned

    def get_paginator(self, operation):
        return _Paginator(self, operation)


class _Paginator:
    def __init__(self, client, operation):
        self.client, self.operation = client, operation

    def paginate(self, **kwargs):
        if self.operation == "list_accounts":
            return iter([{"accountList": [{"accountId": a, "accountName": n}
                                          for a, (n, _r) in self.client.assigned.items()]}])
        if self.operation == "list_account_roles":
            roles = self.client.assigned[kwargs["accountId"]][1]
            if isinstance(roles, Exception):
                raise roles
            return iter([{"roleList": [{"roleName": r} for r in roles]}])
        raise AssertionError(self.operation)


def _settings(excludes=frozenset()):
    return SimpleNamespace(aws_sso_discovery_exclude_set=excludes)


def _run(assigned, permission_set=SET, settings=None, repo=None, queue=None):
    """The permission set is passed in: an Admin chooses it, not this module."""
    repo = repo or InMemoryRepository()
    result = reconcile_sso_accounts(repo, settings or _settings(), FakeSso(assigned), "tok", permission_set,
                                    queue_validation=queue)
    return repo, result, {a.account_id: a for a in repo.list_aws_accounts()}


def test_assigned_accounts_carrying_the_permission_set_are_registered_for_sso_access():
    queued = []
    _repo, result, accounts = _run({"1" * 12: ("alpha", [SET]), "2" * 12: ("beta", [SET, "AdministratorAccess"])},
                                  queue=queued.append)
    assert sorted(result["registered"]) == ["1" * 12, "2" * 12]
    for account in accounts.values():
        assert account.access == aws_access.SSO_PERMISSION_SET
        assert account.sso_role_name == SET and account.source == "SSO" and account.org_present is True
        # Nothing is deployed for this mode, so no role or ExternalId is invented.
        assert account.scanner_role_arn is None and account.external_id is None
        assert aws_access.configured(account, aws_access.SCANNER) is True
        # Key actions keep their own approved identity and member role.
        assert aws_access.configured(account, aws_access.REMEDIATION) is False
    assert [a.account_id for a in queued] == sorted(a.account_id for a in queued)
    assert len(queued) == 2


def test_an_account_without_the_configured_permission_set_is_never_registered():
    """The operator commonly also holds AdministratorAccess; discovering through
    it would hand CreMore far more than scanning needs."""
    _repo, result, accounts = _run({"1" * 12: ("alpha", ["AdministratorAccess", "ReadOnlyAccess"])})
    assert result["registered"] == [] and result["skipped"] == 1 and accounts == {}


def test_discovery_without_a_chosen_permission_set_writes_nothing():
    """Nothing is guessed: an operator usually also holds AdministratorAccess."""
    for permission_set in ("", "   ", None, "not a permission set", "x" * 33):
        _repo, result, accounts = _run({"1" * 12: ("alpha", [SET])}, permission_set=permission_set)
        assert result["registered"] == [] and accounts == {}
        assert result["error"] in ("no_permission_set", "bad_permission_set")


def test_excluded_accounts_are_skipped():
    _repo, result, accounts = _run({"1" * 12: ("alpha", [SET]), "2" * 12: ("beta", [SET])},
                                   settings=_settings(excludes=frozenset({"1" * 12})))
    assert result["registered"] == ["2" * 12] and result["skipped"] == 1
    assert set(accounts) == {"2" * 12}


def test_accounts_from_other_sources_are_never_stomped():
    repo = InMemoryRepository()
    repo.create_aws_account(AwsAccount(account_id="1" * 12, name="hand-made", source="MANUAL",
                                       scanner_role_arn="arn:aws:iam::111111111111:role/R",
                                       external_id="x" * 20))
    repo.create_aws_account(AwsAccount(account_id="2" * 12, name="from-org", source="ORGANIZATION",
                                       org_state="ACTIVE", org_present=True))
    _repo, result, accounts = _run({"1" * 12: ("alpha", [SET]), "2" * 12: ("beta", [SET])}, repo=repo)
    assert result["registered"] == [] and result["changed"] == []
    assert accounts["1" * 12].access == aws_access.ROLE and accounts["1" * 12].source == "MANUAL"
    assert accounts["2" * 12].source == "ORGANIZATION" and accounts["2" * 12].sso_role_name is None


def test_an_account_that_is_no_longer_assigned_is_blocked_but_never_deleted():
    repo = InMemoryRepository()
    repo.create_aws_account(AwsAccount(account_id="9" * 12, name="gone", source="SSO", org_present=True,
                                       access=aws_access.SSO_PERMISSION_SET, sso_role_name=SET))
    _repo, result, accounts = _run({"1" * 12: ("alpha", [SET])}, repo=repo)
    assert "9" * 12 in result["changed"]
    account = accounts["9" * 12]
    assert account.org_present is False
    assert aws_access.org_blocks(account) == ["SSO_ASSIGNMENT_REMOVED"]
    assert aws_access.use_refusal(account, aws_access.SCANNER, {"revision": 1}) == "SSO_ASSIGNMENT_REMOVED"
    assert aws_access.validation_refusal(account, aws_access.SCANNER, {"revision": 1}) == "SSO_ASSIGNMENT_GONE"


def test_a_listed_account_whose_permission_set_vanished_is_not_treated_as_unassigned():
    """The two fail differently and are handled at different layers: presence here,
    the assignment itself by validation. Reading one account's role list can fail
    on its own, so an empty list must never look like a removed account."""
    repo = InMemoryRepository()
    repo.create_aws_account(AwsAccount(account_id="1" * 12, name="alpha", source="SSO", org_present=True,
                                       access=aws_access.SSO_PERMISSION_SET, sso_role_name=SET))
    for roles in ([], ["AdministratorAccess"], RuntimeError("AccessDeniedException")):
        _repo, _result, accounts = _run({"1" * 12: ("alpha", roles)}, repo=repo)
        account = accounts["1" * 12]
        assert account.org_present is True, roles
        assert aws_access.org_blocks(account) == [], roles
        # Still the recorded permission set: only validation may say it is gone.
        assert account.sso_role_name == SET


def test_changing_the_configured_permission_set_forces_revalidation():
    repo = InMemoryRepository()
    created = repo.create_aws_account(AwsAccount(account_id="1" * 12, name="alpha", source="SSO", org_present=True,
                                                 access=aws_access.SSO_PERMISSION_SET, sso_role_name=SET))
    aws_access.record_validation(repo, created, aws_access.SCANNER, access_revision=created.access_revision,
                                 approval_revision=1, current_approval_revision=1, status="VALID", detail="OK")
    before = repo.get_aws_account(created.id)
    assert aws_access.effective_validation(before, aws_access.SCANNER, {"revision": 1})["status"] == "VALID"
    # An int, not the record: the in-memory repo hands back live objects.
    before_revision = before.access_revision

    _repo, result, accounts = _run({"1" * 12: ("alpha", ["CreMoreReader"])}, repo=repo,
                                   permission_set="CreMoreReader")
    after = accounts["1" * 12]
    assert "1" * 12 in result["changed"] and after.sso_role_name == "CreMoreReader"
    # sso_role_name is in ACCESS_FIELDS, so the stored VALID stops counting.
    assert after.access_revision == before_revision + 1
    assert aws_access.effective_validation(after, aws_access.SCANNER, {"revision": 1}) == {
        "status": "PENDING", "detail": "REVALIDATION_REQUIRED", "validated_at": None}


def test_one_account_that_cannot_be_registered_never_stops_the_sweep():
    class HalfBrokenRepo(InMemoryRepository):
        def create_aws_account(self, account):
            if account.account_id == "1" * 12:
                raise RuntimeError("constraint")
            return super().create_aws_account(account)

    _repo, result, accounts = _run({"1" * 12: ("alpha", [SET]), "2" * 12: ("beta", [SET])},
                                   repo=HalfBrokenRepo())
    assert result["registered"] == ["2" * 12] and set(accounts) == {"2" * 12}


def test_a_validator_that_throws_never_loses_the_registration():
    def explode(_account):
        raise RuntimeError("queue is down")

    _repo, result, accounts = _run({"1" * 12: ("alpha", [SET])}, queue=explode)
    assert result["registered"] == ["1" * 12] and set(accounts) == {"1" * 12}


def test_a_repeat_sweep_changes_nothing():
    repo = InMemoryRepository()
    assigned = {"1" * 12: ("alpha", [SET])}
    _run(assigned, repo=repo)
    _repo, result, accounts = _run(assigned, repo=repo)
    assert result == {"registered": [], "changed": [], "skipped": 0}
    assert len(accounts) == 1 and accounts["1" * 12].access_revision == 1
