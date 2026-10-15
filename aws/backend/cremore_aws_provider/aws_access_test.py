from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import AwsAccount
from cremore_aws_provider import aws_access as access

ROLE_ARN = "arn:aws:iam::123456789012:role/CredentialExposureScannerRole"


@pytest.fixture(params=["memory", "sqlite"])
def repo(request):
    if request.param == "memory":
        return InMemoryRepository()
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


def _account(repo, **fields):
    return repo.create_aws_account(AwsAccount(account_id="123456789012", name="prod", scanner_role_arn=ROLE_ARN,
                                              external_id="external-id-0123456789", **fields))


def _approve(repo, purpose=access.SCANNER):
    return access.save_approval(repo, purpose, {"match_key": "identity-center:aws:1:A"}, "admin")


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
@pytest.mark.parametrize("purpose", access.PURPOSES)
def test_concurrent_approvals_receive_distinct_revisions(tmp_path, monkeypatch, backend, purpose):
    engine = None
    if backend == "memory":
        store = InMemoryRepository()
    else:
        engine = make_engine("sqlite+pysqlite:///" + (tmp_path / "approvals.sqlite3").as_posix())
        create_all(engine)
        store = SqlRepository(engine)
    start, read = Barrier(8), Barrier(8)
    original = access.next_revision

    def overlapping_revision(repo, purpose):
        revision = original(repo, purpose)
        read.wait(timeout=15)  # Make the previous read-then-write race deterministic.
        return revision

    def approve(writer):
        start.wait(timeout=15)
        return access.save_approval(store, purpose, {"match_key": f"identity-{writer}"}, str(writer))

    monkeypatch.setattr(access, "next_revision", overlapping_revision)
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            approvals = list(pool.map(approve, range(8)))
        assert sorted(value["revision"] for value in approvals) == list(range(1, 9))
        latest = max(approvals, key=lambda value: value["revision"])
        record = store.get_setting(access.APPROVAL_KEYS[purpose])
        assert record["value"] == latest
        assert latest["match_key"] == "identity-" + record["updated_by"]
        assert access.approval(store, next(p for p in access.PURPOSES if p != purpose)) is None
    finally:
        if engine is not None:
            engine.dispose()


def test_result_counts_only_under_the_revisions_it_was_produced_with(repo):
    acct = _account(repo)
    approved = _approve(repo)
    assert access.effective_validation(acct, access.SCANNER, approved)["status"] == "PENDING"
    assert access.record_validation(repo, acct, access.SCANNER, access_revision=1, approval_revision=approved["revision"],
                                    current_approval_revision=approved["revision"], status="VALID", detail="SCANNER_ROLE_ASSUMED")
    acct = repo.get_aws_account(acct.id)
    assert access.effective_validation(acct, access.SCANNER, approved)["status"] == "VALID"
    assert access.use_refusal(acct, access.SCANNER, approved) is None
    # a scanner result never validates the remediation purpose
    assert access.effective_validation(acct, access.REMEDIATION, access.approval(repo, access.REMEDIATION))["status"] == "NOT_CONFIGURED"

    # a new approval makes the stored result stale without rewriting it
    newer = _approve(repo)
    stale = access.effective_validation(acct, access.SCANNER, newer)
    assert stale == {"status": "PENDING", "detail": "REVALIDATION_REQUIRED", "validated_at": None}
    assert access.use_refusal(acct, access.SCANNER, newer) == "REVALIDATION_REQUIRED"
    # ...and the check that re-proves it needs no prior VALID
    assert access.validation_refusal(acct, access.SCANNER, newer) is None


def test_replacing_legacy_approval_invalidates_its_effective_revision_one(repo):
    account = _account(repo)
    repo.put_setting(access.APPROVAL_KEYS[access.SCANNER], {"match_key": "legacy"}, "old-admin")
    legacy = access.approval(repo, access.SCANNER)
    assert legacy["revision"] == 1 and access.next_revision(repo, access.SCANNER) == 2
    assert access.record_validation(repo, account, access.SCANNER, access_revision=1,
        approval_revision=1, current_approval_revision=1, status="VALID", detail="SCANNER_ROLE_ASSUMED")
    current = access.save_approval(repo, access.SCANNER, {"match_key": "replacement"}, "new-admin")
    assert current["revision"] == 2
    assert access.effective_validation(repo.get_aws_account(account.id), access.SCANNER, current) == {
        "status": "PENDING", "detail": "REVALIDATION_REQUIRED", "validated_at": None}


def test_a_late_result_from_an_older_revision_is_ignored(repo):
    acct = _account(repo)
    old = _approve(repo)
    new = _approve(repo)
    # started under the old approval, finished after the new one
    assert not access.record_validation(repo, acct, access.SCANNER, access_revision=1, approval_revision=old["revision"],
                                        current_approval_revision=new["revision"], status="VALID", detail="SCANNER_ROLE_ASSUMED")
    # started before the role ARN changed
    changed = repo.update_aws_account(acct.id, **access.access_changes(acct, {"scanner_role_arn": ROLE_ARN + "2"}))
    assert changed.access_revision == 2
    assert not access.record_validation(repo, changed, access.SCANNER, access_revision=1, approval_revision=new["revision"],
                                        current_approval_revision=new["revision"], status="VALID", detail="SCANNER_ROLE_ASSUMED")
    assert repo.get_aws_account(acct.id).validation_key is None
    # unchanged fields never bump the revision
    assert access.access_changes(changed, {"name": "x", "scanner_role_arn": ROLE_ARN + "2"}) == {"name": "x", "scanner_role_arn": ROLE_ARN + "2"}


def test_adding_a_remediation_role_never_invalidates_the_scanner_result(repo):
    acct = _account(repo)
    approved = _approve(repo)
    access.record_validation(repo, acct, access.SCANNER, access_revision=1, approval_revision=approved["revision"],
                             current_approval_revision=approved["revision"], status="VALID", detail="SCANNER_ROLE_ASSUMED")
    acct = repo.get_aws_account(acct.id)
    changes = access.access_changes(acct, {"remediation_role_arn": ROLE_ARN.replace("Scanner", "Remediation")})
    assert changes["remediation_access_revision"] == 2 and "access_revision" not in changes
    acct = repo.update_aws_account(acct.id, **changes)
    assert access.effective_validation(acct, access.SCANNER, approved)["status"] == "VALID"
    # a new ExternalId is trusted by both roles, so both are re-proven
    both = access.access_changes(acct, {"external_id": "external-id-rotated-000"})
    assert both["access_revision"] == 2 and both["remediation_access_revision"] == 3


def test_purpose_is_part_of_the_job_key_even_when_revisions_are_equal(repo):
    acct = _account(repo, remediation_role_arn=ROLE_ARN.replace("Scanner", "Remediation"))
    scanner = access.queue_validation(repo, acct, access.SCANNER, 1)
    assert access.queue_validation(repo, acct, access.SCANNER, 1) == scanner
    assert access.queue_validation(repo, acct, access.REMEDIATION, 1) != scanner
    assert access.queue_validation(repo, acct, access.SCANNER, 2) != scanner


def test_organization_facts_block_independently(repo):
    manual = _account(repo, org_state="SUSPENDED")
    assert access.org_blocks(manual) == []  # facts only apply to organization-sourced accounts

    acct = AwsAccount(account_id="210987654321", name="org", source="ORGANIZATION", org_state="ACTIVE",
                      org_present=True, in_deployment_scope=False)
    assert access.org_blocks(acct) == ["OUT_OF_DEPLOYMENT_SCOPE"]  # ACTIVE does not lift a scope exit
    acct.org_state = "SUSPENDED"
    assert access.org_blocks(acct) == ["ORG_ACCOUNT_SUSPENDED", "OUT_OF_DEPLOYMENT_SCOPE"]
    acct.org_state, acct.in_deployment_scope = "ACTIVE", True
    assert access.org_blocks(acct) == []
    for state in (None, "PENDING_ACTIVATION"):
        acct.org_state = state
        assert access.org_blocks(acct)
    acct.org_state, acct.org_present = "ACTIVE", False
    assert access.org_blocks(acct) == ["ORG_ACCOUNT_REMOVED"]
    assert access.validation_refusal(acct, access.SCANNER, {"revision": 1}) == "ACCESS_NOT_CONFIGURED"
    acct.scanner_role_arn, acct.external_id = ROLE_ARN, "external-id-0123456789"
    assert access.validation_refusal(acct, access.SCANNER, {"revision": 1}) == "ORG_ACCOUNT_GONE"


def test_disabled_accounts_can_be_validated_but_not_used(repo):
    acct = _account(repo, enabled=False)
    approved = _approve(repo)
    assert access.validation_refusal(acct, access.SCANNER, approved) is None
    assert access.use_refusal(acct, access.SCANNER, approved) == "ACCOUNT_DISABLED"


def test_runtime_identity_accounts_need_no_role(repo):
    acct = repo.create_aws_account(AwsAccount(account_id="111111111111", name="self", access=access.RUNTIME_IDENTITY))
    assert access.configured(acct, access.SCANNER) and access.configured(acct, access.REMEDIATION)
    assert access.validation_refusal(acct, access.SCANNER, _approve(repo)) is None


def test_legacy_rows_read_back_with_defaults():
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    repo = SqlRepository(engine)
    acct = _account(repo)
    from sqlalchemy import update

    from cremore.db.schema import aws_accounts
    with engine.begin() as conn:
        conn.execute(update(aws_accounts).values(access=None, access_revision=None, source=None,
                                                 remediation_validation_status=None))
    legacy = repo.get_aws_account(acct.id)
    assert (legacy.access, legacy.access_revision, legacy.source) == ("ROLE", 1, "MANUAL")
    assert repo.update_aws_account_if_revision(acct.id, "access_revision", 1, validation_detail="X") is not None
    assert repo.update_aws_account_if_revision(acct.id, "remediation_access_revision", 1, validation_detail="Y") is not None
    with pytest.raises(ValueError):
        repo.update_aws_account_if_revision(acct.id, "enabled", 1, validation_detail="Z")
