from types import SimpleNamespace

from cremore.db.repository import InMemoryRepository
from cremore.domain.models import AwsAccount
from cremore_aws_provider import aws_access
from cremore_aws_provider.aws_org_discovery import accounts_under_ous, reconcile_org_accounts


class FakeOrgClient:
    """Stands in for boto3 organizations with paginated list operations.

    ``accounts`` are the whole-org ListAccounts pages; ``tree`` maps a parent id
    to ``{"accounts": [...ids], "ous": [...ids]}`` for the OU-scoped walk.
    """

    def __init__(self, accounts, tree=None):
        self._accounts = accounts
        self._tree = tree or {}

    def get_paginator(self, operation):
        return _Paginator(self, operation)


class _Paginator:
    def __init__(self, client, operation):
        self.client, self.operation = client, operation

    def paginate(self, **kwargs):
        if self.operation == "list_accounts":
            return iter([{"Accounts": self.client._accounts}])
        node = self.client._tree.get(kwargs["ParentId"], {})
        if self.operation == "list_accounts_for_parent":
            return iter([{"Accounts": [{"Id": i} for i in node.get("accounts", [])]}])
        if self.operation == "list_organizational_units_for_parent":
            return iter([{"OrganizationalUnits": [{"Id": i} for i in node.get("ous", [])]}])
        raise AssertionError(self.operation)


def _acct(account_id, name, state):
    """Current response shape: the richer ``State`` field."""
    return {"Id": account_id, "Name": name, "State": state}


def _acct_legacy(account_id, name, status):
    """Older response shape: only the narrower ``Status`` field, no ``State``."""
    return {"Id": account_id, "Name": name, "Status": status}


def _settings(external_id="ext-shared-0123456789", excludes=frozenset(), ou_ids=frozenset(), principal=""):
    return SimpleNamespace(
        aws_org_discovery_external_id=external_id,
        aws_org_discovery_exclude_set=excludes,
        aws_org_discovery_ou_id_set=ou_ids,
        scanner_principal_arn=principal,
    )


def _sweep(repo, settings, client, *, queue_validation=None):
    """Run the sweep with the configuration these settings describe.

    reconcile_org_accounts now takes it explicitly, because an administrator
    sets it in the dashboard (cremore/aws_org_settings.py) rather than the
    environment. These tests are about what the sweep does with it.
    """
    config = {"external_id": settings.aws_org_discovery_external_id,
              "excludes": sorted(settings.aws_org_discovery_exclude_set),
              "ou_ids": sorted(settings.aws_org_discovery_ou_id_set)}
    return reconcile_org_accounts(repo, settings, client, config, queue_validation=queue_validation)


def _by_id(repo):
    return {a.account_id: a for a in repo.list_aws_accounts()}


def test_new_active_accounts_are_registered_with_org_facts_and_shared_external_id():
    repo = InMemoryRepository()
    client = FakeOrgClient([_acct("111111111111", "prod", "ACTIVE"),
                            _acct("222222222222", "dev", "ACTIVE")])
    result = _sweep(repo, _settings(), client)

    assert set(result["registered"]) == {"111111111111", "222222222222"}
    prod = _by_id(repo)["111111111111"]
    assert prod.external_id == "ext-shared-0123456789"
    assert prod.scanner_role_arn == "arn:aws:iam::111111111111:role/CredentialExposureScannerRole"
    assert prod.source == "ORGANIZATION"
    assert prod.org_state == "ACTIVE" and prod.org_present is True
    assert prod.in_deployment_scope is None  # no OU limit configured


def test_discovery_is_idempotent():
    repo = InMemoryRepository()
    _sweep(repo, _settings(), FakeOrgClient([_acct("111111111111", "prod", "ACTIVE")]))
    again = _sweep(repo, _settings(), FakeOrgClient([_acct("111111111111", "prod", "ACTIVE")]))

    assert again == {"registered": [], "changed": [], "skipped": 0}
    assert len(repo.list_aws_accounts()) == 1


def test_excluded_accounts_are_never_registered():
    repo = InMemoryRepository()
    client = FakeOrgClient([_acct("111111111111", "mgmt", "ACTIVE"), _acct("222222222222", "dev", "ACTIVE")])
    result = _sweep(repo, _settings(excludes=frozenset({"111111111111"})), client)

    assert result["registered"] == ["222222222222"]
    assert result["skipped"] == 1
    assert list(_by_id(repo)) == ["222222222222"]


def test_without_the_shared_external_id_nothing_is_registered():
    repo = InMemoryRepository()
    result = _sweep(repo, _settings(external_id=""),
                                    FakeOrgClient([_acct("111111111111", "prod", "ACTIVE")]))

    assert result["error"] == "no_external_id"
    assert repo.list_aws_accounts() == []


def test_a_suspended_known_org_account_is_blocked_not_deleted():
    repo = InMemoryRepository()
    _sweep(repo, _settings(), FakeOrgClient([_acct("111111111111", "prod", "ACTIVE")]))
    result = _sweep(repo, _settings(), FakeOrgClient([_acct("111111111111", "prod", "SUSPENDED")]))

    assert result["changed"] == ["111111111111"]
    acct = _by_id(repo)["111111111111"]
    assert acct.org_state == "SUSPENDED" and acct.enabled is True
    assert "ORG_ACCOUNT_SUSPENDED" in aws_access.org_blocks(acct)


def test_an_account_that_left_the_org_is_marked_absent():
    repo = InMemoryRepository()
    _sweep(repo, _settings(), FakeOrgClient([_acct("111111111111", "prod", "ACTIVE")]))
    result = _sweep(repo, _settings(), FakeOrgClient([]))  # no longer listed

    assert result["changed"] == ["111111111111"]
    acct = _by_id(repo)["111111111111"]
    assert acct.org_present is False
    assert "ORG_ACCOUNT_REMOVED" in aws_access.org_blocks(acct)


def test_manual_accounts_are_never_overwritten_by_discovery():
    repo = InMemoryRepository()
    manual = repo.create_aws_account(AwsAccount(
        account_id="111111111111", name="hand", source="MANUAL",
        scanner_role_arn="arn:aws:iam::111111111111:role/Custom", external_id="manual-ext-000000"))
    _sweep(repo, _settings(), FakeOrgClient([_acct("111111111111", "prod", "SUSPENDED")]))

    kept = _by_id(repo)["111111111111"]
    assert kept.source == "MANUAL"
    assert kept.scanner_role_arn == manual.scanner_role_arn
    assert kept.org_state is None  # untouched


def test_ou_filter_includes_nested_ous_and_excludes_the_rest():
    repo = InMemoryRepository()
    # Org has three accounts; only the two under ou-top (incl. nested ou-child) are in scope.
    client = FakeOrgClient(
        accounts=[_acct("111111111111", "in", "ACTIVE"),
                  _acct("222222222222", "nested", "ACTIVE"),
                  _acct("333333333333", "out", "ACTIVE")],
        tree={"ou-top": {"accounts": ["111111111111"], "ous": ["ou-child"]},
              "ou-child": {"accounts": ["222222222222"], "ous": []}})
    result = _sweep(repo, _settings(ou_ids=frozenset({"ou-top"})), client)

    assert set(result["registered"]) == {"111111111111", "222222222222"}
    registered = _by_id(repo)
    assert "333333333333" not in registered
    assert registered["111111111111"].in_deployment_scope is True


def test_an_account_moving_out_of_scope_is_marked_out_of_deployment_scope():
    repo = InMemoryRepository()
    client_in = FakeOrgClient([_acct("111111111111", "svc", "ACTIVE")],
                              tree={"ou-top": {"accounts": ["111111111111"], "ous": []}})
    _sweep(repo, _settings(ou_ids=frozenset({"ou-top"})), client_in)
    assert _by_id(repo)["111111111111"].in_deployment_scope is True

    # Same account still in the org but no longer under the scoped OU.
    client_out = FakeOrgClient([_acct("111111111111", "svc", "ACTIVE")],
                               tree={"ou-top": {"accounts": [], "ous": []}})
    result = _sweep(repo, _settings(ou_ids=frozenset({"ou-top"})), client_out)

    assert result["changed"] == ["111111111111"]
    acct = _by_id(repo)["111111111111"]
    assert acct.in_deployment_scope is False and acct.org_present is True
    assert "OUT_OF_DEPLOYMENT_SCOPE" in aws_access.org_blocks(acct)


def test_auto_validate_callback_runs_for_each_newly_registered_account():
    repo = InMemoryRepository()
    validated = []
    _sweep(repo, _settings(), FakeOrgClient([_acct("111111111111", "prod", "ACTIVE")]),
                           queue_validation=lambda account: validated.append(account.account_id))

    assert validated == ["111111111111"]


def test_partition_follows_the_scanner_principal():
    repo = InMemoryRepository()
    _sweep(repo, _settings(principal="arn:aws-us-gov:iam::999999999999:role/central"),
                           FakeOrgClient([_acct("111111111111", "prod", "ACTIVE")]))

    stored = repo.list_aws_accounts()[0]
    assert stored.scanner_role_arn.startswith("arn:aws-us-gov:iam::111111111111:role/")


def test_accounts_under_ous_walks_the_tree_without_looping():
    client = FakeOrgClient([], tree={"ou-a": {"accounts": ["1"], "ous": ["ou-b"]},
                                     "ou-b": {"accounts": ["2"], "ous": ["ou-a"]}})  # cycle
    assert accounts_under_ous(client, ["ou-a"]) == {"1", "2"}


# --- account lifecycle from State (with Status fallback) -------------------

def test_state_active_registers_even_without_the_legacy_status_field():
    repo = InMemoryRepository()
    result = _sweep(repo, _settings(), FakeOrgClient([_acct("111111111111", "prod", "ACTIVE")]))
    assert result["registered"] == ["111111111111"]
    assert _by_id(repo)["111111111111"].org_state == "ACTIVE"


def test_legacy_status_only_response_still_registers():
    repo = InMemoryRepository()
    result = _sweep(repo, _settings(), FakeOrgClient([_acct_legacy("111111111111", "prod", "ACTIVE")]))
    assert result["registered"] == ["111111111111"]


def test_state_wins_over_status_when_they_disagree():
    repo = InMemoryRepository()
    # State says SUSPENDED, the older Status still says ACTIVE: State must win.
    account = {"Id": "111111111111", "Name": "prod", "State": "SUSPENDED", "Status": "ACTIVE"}
    result = _sweep(repo, _settings(), FakeOrgClient([account]))
    assert result["registered"] == []
    assert repo.list_aws_accounts() == []


def test_closed_and_pending_activation_accounts_are_not_registered():
    repo = InMemoryRepository()
    result = _sweep(repo, _settings(), FakeOrgClient([
        _acct("111111111111", "closed", "CLOSED"),
        _acct("222222222222", "warming", "PENDING_ACTIVATION")]))
    assert result["registered"] == []
    assert repo.list_aws_accounts() == []


def test_a_known_account_going_closed_is_blocked():
    repo = InMemoryRepository()
    _sweep(repo, _settings(), FakeOrgClient([_acct("111111111111", "prod", "ACTIVE")]))
    result = _sweep(repo, _settings(), FakeOrgClient([_acct("111111111111", "prod", "CLOSED")]))

    assert result["changed"] == ["111111111111"]
    acct = _by_id(repo)["111111111111"]
    assert acct.org_state == "CLOSED"
    assert "ORG_ACCOUNT_CLOSED" in aws_access.org_blocks(acct)
    # CLOSED is a terminal state: validation cannot even be attempted.
    assert aws_access.validation_refusal(acct, aws_access.SCANNER, {"revision": 1}) == "ORG_ACCOUNT_GONE"


def test_undetermined_state_is_recorded_as_unknown_not_active():
    repo = InMemoryRepository()
    _sweep(repo, _settings(), FakeOrgClient([_acct("111111111111", "prod", "ACTIVE")]))
    # A later response omits both State and Status for the account.
    result = _sweep(repo, _settings(), FakeOrgClient([{"Id": "111111111111", "Name": "prod"}]))

    assert result["changed"] == ["111111111111"]
    acct = _by_id(repo)["111111111111"]
    assert acct.org_state is None
    assert "ORG_STATE_UNKNOWN" in aws_access.org_blocks(acct)


def test_a_new_account_with_no_state_is_not_registered():
    repo = InMemoryRepository()
    result = _sweep(repo, _settings(), FakeOrgClient([{"Id": "111111111111", "Name": "prod"}]))
    assert result["registered"] == []
    assert repo.list_aws_accounts() == []


def test_excluding_registered_account_blocks_future_use_and_preserves_registry():
    repo = InMemoryRepository()
    client = FakeOrgClient([_acct("111111111111", "prod", "ACTIVE")])
    _sweep(repo, _settings(), client)
    original = _by_id(repo)["111111111111"]
    _sweep(repo, _settings(excludes=frozenset({original.account_id})), client)
    account = _by_id(repo)[original.account_id]
    assert account.id == original.id and account.enabled
    assert "OUT_OF_DEPLOYMENT_SCOPE" in aws_access.org_blocks(account)
    assert _sweep(repo, _settings(excludes=frozenset({original.account_id})), client)["changed"] == []
    _sweep(repo, _settings(), client)
    assert _by_id(repo)[original.account_id].in_deployment_scope is None


def test_removing_ou_limit_clears_old_scope_block():
    repo = InMemoryRepository()
    client = FakeOrgClient([_acct("111111111111", "prod", "ACTIVE")],
                           tree={"ou-a": {"accounts": ["111111111111"]}})
    _sweep(repo, _settings(ou_ids=frozenset({"ou-a"})), client)
    client._tree = {}
    _sweep(repo, _settings(ou_ids=frozenset({"ou-a"})), client)
    assert _by_id(repo)["111111111111"].in_deployment_scope is False
    _sweep(repo, _settings(), client)
    assert _by_id(repo)["111111111111"].in_deployment_scope is None


def test_failed_role_is_retried_after_account_factory_role_becomes_ready():
    repo = InMemoryRepository()
    client = FakeOrgClient([_acct("111111111111", "prod", "ACTIVE")])
    _sweep(repo, _settings(), client)
    account = _by_id(repo)["111111111111"]
    repo.update_aws_account(account.id, validation_status="INVALID")
    queued = []
    _sweep(repo, _settings(), client, queue_validation=lambda a: queued.append(a.account_id))
    assert queued == [account.account_id]
