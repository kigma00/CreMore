"""Upgrade recovery keeps committed evidence and never mixes old/new snapshots."""

from copy import deepcopy

import pytest

from cremore.coverage.models import digest
from cremore_github_provider.metadata import adapter

from .fake import (
    ENTERPRISE,
    SECRETS,
    FakeBroker,
    FakeTransport,
    enterprise_spec,
    org_responses,
    spec,
)
from .test_adapter import NOW, drive


def old_hash(connection):
    raw = connection.model_dump()
    raw["options"].pop("github_inventory")
    return digest(raw)


def test_organization_checkpoint_before_new_default_resumes_without_repeating_the_app_read():
    connection = spec(options={"sources": ["org_sso"]})
    _, _, records, state, _ = drive(connection, org_responses(), stop_after=1)
    state["config_hash"] = old_hash(connection)
    _, broker, _records, resumed, final = drive(connection, org_responses(), checkpoint=state, committed=records)
    assert broker.app_calls == 0
    assert final.status == "COMPLETE"
    assert resumed["config_hash"] == adapter._config_hash(connection)


@pytest.mark.parametrize("completed", [False, True])
def test_retired_list_checkpoint_closes_with_actionable_reason_without_network_or_new_export(completed):
    connection = enterprise_spec()
    run = adapter._Run(connection, {}, old_hash(connection), now=lambda: NOW)
    run.add(adapter._seed(connection, run))
    state = run.checkpoint()
    for task in state["tasks"].values():
        if task["kind"] == "inventory":
            task.update(path=f"/enterprises/{ENTERPRISE}/credentials", status="complete" if completed else "pending",
                        next_path=None if completed else f"/enterprises/{ENTERPRISE}/credentials?page=2", count=7)
    state["emitted"] = 7
    before = deepcopy(state)
    tx, broker = FakeTransport(), FakeBroker()
    pages = list(adapter.collect_pages(connection, secrets=SECRETS, checkpoint=state, check=lambda: None,
        transport=tx, broker=broker, read_records=lambda: iter(()), now=lambda: NOW))
    assert len(pages) == 1 and not pages[0].records
    assert pages[0].status == "PARTIAL" and pages[0].reasons == ["GITHUB_INVENTORY_API_CHANGED_RECOLLECT"]
    assert pages[0].checkpoint["emitted"] == 7 and state == before
    assert not tx.calls and not broker.issued and broker.app_calls == 0


def test_legacy_hash_does_not_excuse_changed_scope_limits_or_disabled_inventory():
    connection = spec(options={"sources": ["org_sso"]})
    _, _, records, state, _ = drive(connection, org_responses(), stop_after=1)
    state["config_hash"] = old_hash(connection)
    changed = connection.model_copy(update={"max_records": connection.max_records + 1})
    with pytest.raises(ValueError, match="GITHUB_CHECKPOINT_MISMATCH"):
        list(adapter.collect_pages(changed, secrets=SECRETS, checkpoint=state, check=lambda: None,
            transport=FakeTransport(), broker=FakeBroker(), read_records=lambda: iter(records)))
    no_inventory = connection.model_copy(deep=True)
    no_inventory.options.github_inventory = False
    assert adapter._legacy_config_hash(no_inventory) is None
