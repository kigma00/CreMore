"""Tamper evidence for the audit trail on every store: the chain a worker seals after the fact, what verify()
finds when rows are changed, deleted, forged or un-sealed and sealed again, the anchors inside and outside the
database, acknowledgements, and the hourly SIEM event. Every write below that bypasses CreMore is one a person with
database access and no key could make."""

from __future__ import annotations

import datetime as dt
import json
import os
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import IntegrityError

from cremore.config import Settings
from cremore.db import audit_chain
from cremore.db.postgres_scan_test import (
    pg as pg,  # noqa: PLC0414 -- explicit pytest fixture re-export
)
from cremore.db.repository import InMemoryRepository
from cremore.db.schema import finding_events, siem_events
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import FindingEvent
from cremore.operations import audit_integrity
from cremore.siem.formats import severity, to_cef

SETTINGS = Settings(FINGERPRINT_KEY="ab" * 32)
NOW = dt.datetime(2026, 9, 29, 3, 0, tzinfo=dt.UTC)


def action(n: int, actor: str = "alice") -> FindingEvent:
    return FindingEvent(target_type="action_plan", target_id=uuid.uuid4(), actor=actor,
                        event_type="ACTION_PLAN_APPROVED", from_status="PENDING_APPROVAL", to_status="APPROVED",
                        note=f"plan_hash={n:064x}")


class Store:
    """One backend, with the database-level writes someone who bypasses CreMore could make."""

    def __init__(self, repo, engine=None):
        self.repo, self.engine = repo, engine

    def _sql(self, statement):
        with self.engine.begin() as conn:
            conn.execute(statement)

    def change(self, event_id, **values):
        if self.engine is not None:
            self._sql(update(finding_events).where(finding_events.c.id == event_id).values(**values))
            return
        marks = {name: values.pop(name) for name in ("entry_mac", "chain_mac", "chain_seq") if name in values}
        if marks:
            self.repo.audit_marks[event_id] = {**self.repo.audit_marks[event_id], **marks}
        if values:
            self.repo.finding_events[event_id] = self.repo.finding_events[event_id].model_copy(update=values)

    def remove(self, event_id):
        if self.engine is None:
            del self.repo.finding_events[event_id]
        else:
            self._sql(delete(finding_events).where(finding_events.c.id == event_id))

    def unseal(self, from_seq=1):
        """Take the chain's positions away from every row at or after ``from_seq``."""
        if self.engine is not None:
            self._sql(update(finding_events).where(finding_events.c.chain_seq >= from_seq).values(chain_seq=None, chain_mac=None))
            return
        for mark in self.repo.audit_marks.values():
            if mark["chain_seq"] is not None and mark["chain_seq"] >= from_seq:
                mark["chain_seq"] = mark["chain_mac"] = None

    def forge(self, event: FindingEvent) -> FindingEvent:
        """A row written straight into the store: no process key, so no entry MAC."""
        key, self.repo.audit_key = self.repo.audit_key, None
        try:
            return self.repo.record_finding_event(event)
        finally:
            self.repo.audit_key = key

    def chain(self):
        return self.repo.audit_chain_page(0, 10000)

    def seq(self, event_id) -> int:
        return next(row["chain_seq"] for row in self.chain() if row["id"] == event_id)

    def of_type(self, event_type):
        return [row for row in self.chain() + self.repo.unsealed_audit() if row["event_type"] == event_type]

    def queued(self, event_type: str) -> list[dict]:
        if self.engine is None:
            payloads = list(self.repo.siem_events.values())
        else:
            with self.engine.connect() as conn:
                payloads = list(conn.execute(select(siem_events.c.payload)).scalars())
        return sorted((payload for payload in payloads if payload["event_type"] == event_type), key=lambda event: event["occurred_at"])

    def restart(self):
        """A new worker process: whatever the last one remembered is gone."""
        for name in ("_audit_sealed_head", "_audit_last_anchor"):
            self.repo.__dict__.pop(name, None)


@pytest.fixture(params=["memory", "sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def store(request, tmp_path):
    if request.param == "memory":
        yield Store(InMemoryRepository())
        return
    if request.param == "postgres":
        engine, repo = request.getfixturevalue("pg")  # owns and drops its schema
        yield Store(repo, engine)
        return
    engine = make_engine(f"sqlite+pysqlite:///{(tmp_path / 'audit.db').as_posix()}")
    create_all(engine)
    try:
        yield Store(SqlRepository(engine), engine)
    finally:
        engine.dispose()


def written(store, count, start=0):
    """Rows CreMore writes: the process key is attached as the API and worker attach it."""
    audit_integrity.attach(store.repo, SETTINGS)
    return [store.repo.record_finding_event(action(start + n)) for n in range(count)]


def kinds(report):
    return sorted({item["kind"] for item in report["problems"] if not item["acknowledged"]})


def test_rows_written_before_the_chain_are_taken_in_and_the_chain_verifies(store):
    old = store.forge(action(0))  # written by a release without the chain
    audit_integrity.attach(store.repo, SETTINGS)
    rows = written(store, 3, start=1)
    assert audit_integrity.verify(store.repo, SETTINGS, now=NOW)["state"] == "NOT_STARTED"
    assert audit_integrity.seal(store.repo, SETTINGS) == 5  # four rows and the start of the chain
    report = audit_integrity.verify(store.repo, SETTINGS, now=NOW)
    assert report["state"] == "INTACT" and report["verified_through"] == 5 and report["pending"] == 0
    chain = store.chain()
    # Everything written before the first seal comes first, whatever the clock said; the start closes the baseline.
    assert {row["id"] for row in chain[:4]} == {old.id, *(row.id for row in rows)}
    assert chain[4]["event_type"] == audit_chain.GENESIS_EVENT
    assert chain[4]["note"] == f"legacy_rows=4 key={audit_chain.key_id(audit_integrity.key(SETTINGS))}"
    assert report["genesis"] == {"seq": 5, "mac": chain[4]["chain_mac"]} and report["legacy_rows"] == 4
    assert report["head"] == {"seq": 5, "mac": chain[4]["chain_mac"]}
    written(store, 2, start=10)
    assert audit_integrity.seal(store.repo, SETTINGS) == 2
    assert audit_integrity.verify(store.repo, SETTINGS)["state"] == "INTACT"
    assert audit_integrity.seal(store.repo, SETTINGS) == 0


def test_every_changed_or_deleted_row_is_named_not_only_the_first(store):
    written(store, 7)
    audit_integrity.seal(store.repo, SETTINGS)
    chain = store.chain()
    store.change(chain[1]["id"], note="plan_hash=" + "f" * 64)  # someone rewrites who approved what
    store.remove(chain[4]["id"])
    store.change(chain[5]["id"], note="plan_hash=" + "e" * 64)  # right after the gap: only its entry MAC is left
    report = audit_integrity.verify(store.repo, SETTINGS)
    assert report["state"] == "BROKEN"
    found = {(item["kind"], item["seq"]) for item in report["problems"]}
    assert found == {("MAC_MISMATCH", 2), ("SEQUENCE_GAP", 5), ("MAC_MISMATCH", 6)}
    assert next(item for item in report["problems"] if item["seq"] == 2)["event_id"] == str(chain[1]["id"])


def test_a_malformed_mac_reads_as_a_changed_row_not_a_crash(store):
    rows = written(store, 3)
    audit_integrity.seal(store.repo, SETTINGS)
    store.change(rows[0].id, chain_mac="é" * 64)
    store.change(rows[2].id, entry_mac="é")
    report = audit_integrity.verify(store.repo, SETTINGS)
    assert report["state"] == "BROKEN" and "MAC_MISMATCH" in kinds(report)


def test_a_row_no_cremore_process_wrote_is_named_before_and_after_it_is_sealed(store):
    written(store, 2)
    audit_integrity.seal(store.repo, SETTINGS)
    forged = store.forge(action(99, actor="mallory"))
    report = audit_integrity.verify(store.repo, SETTINGS)
    assert report["state"] == "UNAUTHENTICATED" and report["unauthenticated"]["pending_count"] == 1
    assert [item["event_id"] for item in report["problems"]] == [str(forged.id)]
    audit_integrity.seal(store.repo, SETTINGS)
    report = audit_integrity.verify(store.repo, SETTINGS)
    assert report["state"] == "UNAUTHENTICATED" and report["unauthenticated"]["sealed_count"] == 1
    assert [item["seq"] for item in report["problems"]] == [4]  # after the two rows and the start


def test_an_admin_acknowledgement_clears_only_the_problem_it_names_as_it_was(store):
    written(store, 2)
    audit_integrity.seal(store.repo, SETTINGS)
    first = store.forge(action(97, actor="old-replica"))
    audit_integrity.seal(store.repo, SETTINGS)
    [problem] = audit_integrity.verify(store.repo, SETTINGS)["problems"]
    assert problem["kind"] == "UNAUTHENTICATED" and problem["ack"].startswith(f"UNAUTHENTICATED@event:{first.id}#")
    # Only a problem open now can be acknowledged, never one in advance.
    with pytest.raises(ValueError, match="AUDIT_ACK_NOT_OPEN"):
        audit_integrity.acknowledge(store.repo, SETTINGS, "admin-1", ["MAC_MISMATCH@seq:1#" + "0" * 32], "in advance")
    with pytest.raises(ValueError, match="AUDIT_ACK_INVALID"):
        audit_integrity.acknowledge(store.repo, SETTINGS, "admin-1", ["seq:3"], "old form")
    audit_integrity.acknowledge(store.repo, SETTINGS, "admin-1", [problem["ack"]], "written by the API before its upgrade")
    report = audit_integrity.verify(store.repo, SETTINGS)
    assert report["state"] == "INTACT" and report["open_problems"] == 0 and report["problem_count"] == 1
    acknowledgement = store.of_type(audit_chain.ACK_EVENT)[0] if store.of_type(audit_chain.ACK_EVENT) else next(
        row for row in store.chain() + store.repo.unsealed_audit() if row["event_type"] == audit_chain.ACK_EVENT)
    assert acknowledgement["actor"] == "admin-1" and audit_chain.authentic(audit_integrity.key(SETTINGS), acknowledgement)
    # Rewriting the examined row afterwards is a new problem: the acknowledgement named the row as it was.
    store.change(first.id, actor="mallory")
    assert audit_integrity.verify(store.repo, SETTINGS)["open_problems"] >= 1


def test_widening_an_acknowledged_gap_opens_it_again(store):
    written(store, 6)
    audit_integrity.seal(store.repo, SETTINGS)
    chain = store.chain()
    store.remove(chain[2]["id"])
    [gap] = audit_integrity.verify(store.repo, SETTINGS)["problems"]
    assert (gap["kind"], gap["seq"]) == ("SEQUENCE_GAP", 3)
    audit_integrity.acknowledge(store.repo, SETTINGS, "admin-1", [gap["ack"]], "a row deleted by the retention job")
    assert audit_integrity.verify(store.repo, SETTINGS)["state"] == "INTACT"
    store.remove(chain[3]["id"])  # the acknowledgement named the gap as it was: 3 up to 4
    report = audit_integrity.verify(store.repo, SETTINGS)
    assert report["state"] == "BROKEN" and report["open_problems"] == 1


def test_the_row_after_an_acknowledged_gap_cannot_be_swapped_or_changed(store):
    for n in range(4):
        store.forge(action(n, actor="legacy"))  # written before the chain: no entry MAC
    written(store, 1, start=4)
    audit_integrity.seal(store.repo, SETTINGS)  # four old rows and one new (in clock order), then the start at 6
    written(store, 4, start=10)
    audit_integrity.seal(store.repo, SETTINGS)  # 7 to 10
    chain = store.chain()
    at = next(i for i in range(1, 5) if chain[i]["entry_mac"] is None)  # an old row with a row before it
    store.remove(chain[at - 1]["id"])  # a gap among the old rows, and one after the start
    store.remove(chain[7]["id"])
    gaps = audit_integrity.verify(store.repo, SETTINGS)["problems"]
    assert sorted((item["kind"], item["seq"]) for item in gaps) == [("SEQUENCE_GAP", at), ("SEQUENCE_GAP", 8)]
    audit_integrity.acknowledge(store.repo, SETTINGS, "admin-1", [item["ack"] for item in gaps], "restored from a backup")
    assert audit_integrity.verify(store.repo, SETTINGS)["state"] == "INTACT"
    # The old row right after the first gap has no MAC of its own; the acknowledgement named it as it was.
    store.change(chain[at]["id"], actor="mallory")
    report = audit_integrity.verify(store.repo, SETTINGS)
    assert report["state"] == "BROKEN" and [(item["kind"], item["seq"]) for item in report["problems"] if not item["acknowledged"]] == [
        ("SEQUENCE_GAP", at)]
    store.change(chain[at]["id"], actor="legacy")
    assert audit_integrity.verify(store.repo, SETTINGS)["state"] == "INTACT"
    # Swapping the row after the second gap for another authentic one, with its MAC copied so the next link holds.
    victim = chain[8]
    [spare] = written(store, 1, start=50)
    store.remove(victim["id"])
    store.change(spare.id, chain_seq=victim["chain_seq"], chain_mac=victim["chain_mac"])
    report = audit_integrity.verify(store.repo, SETTINGS)
    assert report["state"] == "BROKEN" and [(item["kind"], item["seq"]) for item in report["problems"] if not item["acknowledged"]] == [
        ("SEQUENCE_GAP", 8)]


def test_accepting_a_waiting_row_outlives_its_seal(store):
    written(store, 2)
    audit_integrity.seal(store.repo, SETTINGS)
    forged = store.forge(action(95, actor="old-replica"))
    [problem] = audit_integrity.verify(store.repo, SETTINGS)["problems"]
    assert problem["seq"] is None and problem["ack"].startswith(f"UNAUTHENTICATED@event:{forged.id}#")
    audit_integrity.acknowledge(store.repo, SETTINGS, "admin-1", [problem["ack"]], "written by the API before its upgrade")
    audit_integrity.seal(store.repo, SETTINGS)
    report = audit_integrity.verify(store.repo, SETTINGS)
    assert report["state"] == "INTACT" and report["problems"][0]["seq"] == store.seq(forged.id)


def test_a_row_put_outside_the_chain_is_named(store):
    written(store, 2)
    audit_integrity.seal(store.repo, SETTINGS)
    forged = store.forge(action(66, actor="mallory"))
    if store.engine is not None:
        with pytest.raises(IntegrityError):
            store.change(forged.id, chain_seq=0)  # the position check refuses it
        if store.engine.dialect.name != "postgresql":
            return
        store._sql(text("ALTER TABLE finding_events DROP CONSTRAINT finding_events_chain_seq_positive"))
    store.change(forged.id, chain_seq=0, chain_mac="0" * 64)
    report = audit_integrity.verify(store.repo, SETTINGS)
    assert report["state"] == "BROKEN" and "SEQUENCE_INVALID" in kinds(report)
    assert next(item for item in report["problems"] if item["kind"] == "SEQUENCE_INVALID")["event_id"] == str(forged.id)


def test_a_chain_emptied_while_the_worker_runs_is_not_started_again(store):
    written(store, 3)
    audit_integrity.seal(store.repo, SETTINGS)
    store.unseal(1)
    for row in store.of_type(audit_chain.GENESIS_EVENT):
        store.remove(row["id"])
    assert audit_integrity.seal(store.repo, SETTINGS) == 0  # the same process remembers the chain it sealed
    assert not store.of_type(audit_chain.GENESIS_EVENT) and store.of_type(audit_chain.REWOUND_EVENT)
    report = audit_integrity.verify(store.repo, SETTINGS)
    assert report["state"] == "BROKEN" and "CHAIN_RESET" in kinds(report)
    assert audit_integrity.seal(store.repo, SETTINGS) == 0 and len(store.of_type(audit_chain.REWOUND_EVENT)) == 1
    # Removing the record that waits does not make the running worker start over: it writes the record again.
    [rewound] = store.of_type(audit_chain.REWOUND_EVENT)
    store.remove(rewound["id"])
    assert audit_integrity.seal(store.repo, SETTINGS) == 0
    assert not store.of_type(audit_chain.GENESIS_EVENT) and len(store.of_type(audit_chain.REWOUND_EVENT)) == 1
    assert "CHAIN_RESET" in kinds(audit_integrity.verify(store.repo, SETTINGS))


def test_a_changed_start_does_not_switch_off_later_checks(store):
    written(store, 3)
    audit_integrity.seal(store.repo, SETTINGS)
    [start] = store.of_type(audit_chain.GENESIS_EVENT)
    store.change(start["id"], note=start["note"].replace(start["note"][-16:], "0" * 16))  # "key=0000...": another key?
    report = audit_integrity.verify(store.repo, SETTINGS)
    assert "KEY_MISMATCH" not in kinds(report) and ("MAC_MISMATCH", start["chain_seq"]) in {
        (item["kind"], item["seq"]) for item in report["problems"]}
    forged = store.forge(action(77, actor="mallory"))
    audit_integrity.seal(store.repo, SETTINGS)
    report = audit_integrity.verify(store.repo, SETTINGS)
    assert (("UNAUTHENTICATED", store.seq(forged.id)) in {(item["kind"], item["seq"]) for item in report["problems"]})


def test_a_start_row_nobody_sealed_is_named_and_moves_nothing(store):
    for n in range(3):
        store.forge(action(n, actor="legacy"))  # history from before the chain
    fake = store.forge(audit_chain.chain_event(audit_chain.GENESIS_EVENT, "legacy_rows=0 key=" + "0" * 16))
    for n in range(3, 6):
        store.forge(action(n, actor="legacy"))
    written(store, 2, start=6)
    assert audit_integrity.seal(store.repo, SETTINGS) == 10  # it cannot keep the chain from starting
    report = audit_integrity.verify(store.repo, SETTINGS)
    # The real start sets where authentication begins: the old rows after the fake one are not flagged.
    assert report["genesis"]["seq"] == 10 and report["legacy_rows"] == 9
    assert [(item["kind"], item["event_id"]) for item in report["problems"]] == [("GENESIS_INVALID", str(fake.id))]
    audit_integrity.acknowledge(store.repo, SETTINGS, "admin-1", [report["problems"][0]["ack"]], "inserted before the upgrade")
    assert audit_integrity.verify(store.repo, SETTINGS)["state"] == "INTACT"
    # Relabelling an old row as a start afterwards is one changed row, not a flood.
    old = next(row for row in store.chain() if row["actor"] == "legacy")
    store.change(old["id"], actor=audit_chain.CHAIN_ACTOR, event_type=audit_chain.GENESIS_EVENT)
    report = audit_integrity.verify(store.repo, SETTINGS)
    assert [(item["kind"], item["seq"]) for item in report["problems"] if not item["acknowledged"]] == [("MAC_MISMATCH", old["chain_seq"])]


def test_rows_sealed_again_in_front_of_the_start_move_it_and_it_says_so(store):
    old = [store.forge(action(n, actor="legacy")) for n in range(4)]
    for row in old:  # well before the upgrade
        store.change(row.id, created_at=dt.datetime(2021, 1, 1, tzinfo=dt.UTC))
    audit_integrity.attach(store.repo, SETTINGS)
    audit_integrity.seal(store.repo, SETTINGS)  # the four old rows, then the start at 5 ("legacy_rows=4")
    written(store, 4, start=10)
    audit_integrity.seal(store.repo, SETTINGS)
    assert audit_integrity.verify(store.repo, SETTINGS)["genesis"]["seq"] == 5
    # Un-sealed from 3, through the start, with a backdated row that lands in front of it once sealed again.
    store.unseal(3)
    forged = store.forge(action(99, actor="bob"))
    store.change(forged.id, created_at=dt.datetime(2020, 1, 1, tzinfo=dt.UTC))
    audit_integrity.seal(store.repo, SETTINGS)  # the running worker records the rewind, then seals the rest
    report = audit_integrity.verify(store.repo, SETTINGS)
    assert kinds(report) == ["CHAIN_REWOUND", "GENESIS_MOVED"] and report["genesis"]["seq"] != 5
    assert store.seq(forged.id) < report["genesis"]["seq"]  # where nothing is authenticated
    # Accepting the rewind alone does not accept what moved the start.
    rewound = next(item["ack"] for item in report["problems"] if item["kind"] == "CHAIN_REWOUND")
    audit_integrity.acknowledge(store.repo, SETTINGS, "admin-1", [rewound], "maintenance")
    assert kinds(audit_integrity.verify(store.repo, SETTINGS)) == ["GENESIS_MOVED"]


def test_an_anchor_kept_outside_catches_a_shortened_chain(store):
    written(store, 3)
    audit_integrity.seal(store.repo, SETTINGS)  # three rows, then the start at 4
    written(store, 2, start=3)
    audit_integrity.seal(store.repo, SETTINGS)
    head = audit_integrity.verify(store.repo, SETTINGS)["head"]
    assert head["seq"] == 6
    assert audit_integrity.verify(store.repo, SETTINGS, anchor=(head["seq"], head["mac"]))["anchor"] == {
        "seq": head["seq"], "state": "MATCHED"}
    wrong = audit_integrity.verify(store.repo, SETTINGS, anchor=(head["seq"], "0" * 64))
    assert wrong["state"] == "ANCHOR_MISMATCH" and wrong["anchor"]["state"] == "MISMATCH"
    # Deleting the newest rows leaves no gap inside the chain; only the anchor shows it.
    for row in store.chain()[-2:]:
        store.remove(row["id"])
    shortened = audit_integrity.verify(store.repo, SETTINGS, anchor=(head["seq"], head["mac"]))
    assert shortened["state"] == "ANCHOR_MISMATCH" and shortened["anchor"]["state"] == "MISSING"
    # Cutting back into the start of the chain is a break even without an anchor.
    store.remove(store.chain()[-1]["id"])
    assert "GENESIS_MISSING" in kinds(audit_integrity.verify(store.repo, SETTINGS))


def test_unsealing_rows_to_hide_a_deletion_is_recorded_while_the_sealer_runs(store):
    written(store, 5)
    audit_integrity.seal(store.repo, SETTINGS)
    victim = store.chain()[2]
    store.unseal(victim["chain_seq"])
    store.remove(victim["id"])
    audit_integrity.seal(store.repo, SETTINGS)  # the same process: it knows the head it sealed
    report = audit_integrity.verify(store.repo, SETTINGS)
    assert report["state"] == "BROKEN" and "CHAIN_REWOUND" in kinds(report)
    # The record of the rewind is sealed in the same transaction: it cannot be deleted while it waits.
    assert [row["chain_seq"] is not None for row in store.of_type(audit_chain.REWOUND_EVENT)] == [True]


def test_after_a_restart_the_anchors_in_the_chain_still_catch_rows_sealed_again(store):
    written(store, 5)
    audit_integrity.seal(store.repo, SETTINGS)
    assert audit_integrity.publish(store.repo, SETTINGS, now=NOW)  # anchor 1 claims the head
    written(store, 2, start=10)
    audit_integrity.seal(store.repo, SETTINGS)
    victim = store.chain()[1]
    store.unseal(victim["chain_seq"])
    store.remove(victim["id"])
    store.restart()
    audit_integrity.seal(store.repo, SETTINGS)  # a new process re-seals what it finds
    report = audit_integrity.verify(store.repo, SETTINGS)
    assert report["state"] == "BROKEN" and "ANCHOR_CLAIM_MISMATCH" in kinds(report)


def test_a_chain_whose_positions_are_gone_is_never_started_again(store):
    written(store, 3)
    audit_integrity.seal(store.repo, SETTINGS)
    assert audit_integrity.publish(store.repo, SETTINGS, now=NOW)
    store.unseal(1)
    store.restart()
    assert audit_integrity.seal(store.repo, SETTINGS) == 0
    report = audit_integrity.verify(store.repo, SETTINGS)
    # The anchor in the chain loses the position it claimed as well.
    assert report["state"] == "BROKEN" and kinds(report) == ["ANCHOR_CLAIM_MISMATCH", "CHAIN_RESET"]
    assert audit_integrity.publish(store.repo, SETTINGS, now=NOW + dt.timedelta(hours=1))
    assert store.queued("audit.chain_anchor")[-1]["audit"]["chain_state"] == "BROKEN"


def test_a_rewrite_that_also_removes_the_start_and_anchors_shows_only_to_the_siem(store):
    written(store, 3)
    audit_integrity.seal(store.repo, SETTINGS)
    assert audit_integrity.publish(store.repo, SETTINGS, now=NOW)
    before = store.queued("audit.chain_anchor")[-1]["audit"]
    store.unseal(1)
    for row in store.of_type(audit_chain.GENESIS_EVENT) + store.of_type(audit_chain.ANCHOR_EVENT):
        store.remove(row["id"])
    store.restart()
    audit_integrity.seal(store.repo, SETTINGS)
    assert audit_integrity.verify(store.repo, SETTINGS)["state"] == "INTACT"  # nothing left in the database says otherwise
    assert audit_integrity.publish(store.repo, SETTINGS, now=NOW + dt.timedelta(hours=1))
    after = store.queued("audit.chain_anchor")[-1]["audit"]
    # What a SIEM rule sees: another start, and anchor numbers counting from one again.
    assert after["genesis_mac"] != before["genesis_mac"] and (before["anchor_no"], after["anchor_no"]) == (1, 1)


def test_the_hourly_anchor_is_a_row_in_the_chain_and_an_event_for_the_siem(store):
    written(store, 2)
    assert audit_integrity.publish(store.repo, SETTINGS, now=NOW) is False  # nothing sealed yet: nothing to anchor
    audit_integrity.seal(store.repo, SETTINGS)
    later = NOW + dt.timedelta(hours=1)
    head = audit_integrity.verify(store.repo, SETTINGS)["head"]
    assert audit_integrity.publish(store.repo, SETTINGS, now=later) is True
    assert audit_integrity.publish(store.repo, SETTINGS, now=later + dt.timedelta(minutes=5)) is False
    [event] = store.queued("audit.chain_anchor")
    genesis = audit_integrity.verify(store.repo, SETTINGS)["genesis"]
    assert event["audit"] == {"chain_state": "INTACT", "chain_seq": head["seq"], "chain_mac": head["mac"],
                              "genesis_seq": genesis["seq"], "genesis_mac": genesis["mac"], "anchor_no": 1,
                              "open_problems": 0, "problem_seq": None, "problem_reason": None, "unauthenticated": 0, "pending": 0}
    assert severity(event) == 1 and "cs3=INTACT" in to_cef(event) and "cn2=1" in to_cef(event)
    [row] = store.of_type(audit_chain.ANCHOR_EVENT)
    assert row["note"] == f"anchor=1 seq={head['seq']} mac={head['mac']} state=INTACT"
    audit_integrity.seal(store.repo, SETTINGS)
    assert audit_integrity.publish(store.repo, SETTINGS, now=later + dt.timedelta(hours=1))
    assert store.queued("audit.chain_anchor")[-1]["audit"]["anchor_no"] == 2
    report = audit_integrity.verify(store.repo, SETTINGS)
    assert report["state"] == "INTACT" and report["anchors"]["count"] == 2


def test_a_broken_chain_is_a_high_severity_anchor_without_row_content():
    repo = InMemoryRepository()
    audit_integrity.attach(repo, SETTINGS)
    rows = [repo.record_finding_event(action(n)) for n in range(3)]
    audit_integrity.seal(repo, SETTINGS)
    repo.finding_events[rows[0].id] = repo.finding_events[rows[0].id].model_copy(update={"actor": "mallory"})
    assert audit_integrity.publish(repo, SETTINGS, now=NOW)
    event = next(value for value in repo.siem_events.values() if value["event_type"] == "audit.chain_anchor")
    assert event["audit"]["chain_state"] == "BROKEN" and event["audit"]["problem_reason"] == "MAC_MISMATCH"
    assert severity(event) == 9
    assert "mallory" not in json.dumps(event) and "plan_hash" not in json.dumps(event)


def test_when_verification_fails_the_hour_still_sends_an_unknown_anchor(monkeypatch, caplog):
    repo = InMemoryRepository()
    audit_integrity.attach(repo, SETTINGS)
    repo.record_finding_event(action(1))
    audit_integrity.seal(repo, SETTINGS)

    def unreadable(*_args, **_kwargs):
        raise RuntimeError("synthetic")

    monkeypatch.setattr(audit_integrity, "verify", unreadable)
    assert audit_integrity.publish(repo, SETTINGS, now=NOW)
    event = next(value for value in repo.siem_events.values() if value["event_type"] == "audit.chain_anchor")
    assert event["audit"]["chain_state"] == "UNKNOWN" and severity(event) == 9
    assert "audit chain anchor" in caplog.text  # the copy of record in the worker's log


def test_a_dedicated_key_seals_the_chain_and_another_key_reads_as_a_key_mismatch():
    dedicated = Settings(FINGERPRINT_KEY="ab" * 32, AUDIT_CHAIN_KEY="cd" * 32)
    assert audit_integrity.key(dedicated) != audit_integrity.key(SETTINGS)
    repo = InMemoryRepository()
    audit_integrity.attach(repo, dedicated)
    for n in range(3):
        repo.record_finding_event(action(n))
    audit_integrity.seal(repo, dedicated)
    assert audit_integrity.verify(repo, dedicated)["state"] == "INTACT"
    report = audit_integrity.verify(repo, SETTINGS)
    assert report["state"] == "BROKEN" and kinds(report) == ["KEY_MISMATCH"]


def test_sealers_racing_on_postgresql_never_share_a_position(request):
    if not os.environ.get("CREMORE_TEST_POSTGRES_URL"):
        pytest.skip("CREMORE_TEST_POSTGRES_URL is not set")
    _engine, repo = request.getfixturevalue("pg")
    audit_integrity.attach(repo, SETTINGS)
    for n in range(40):
        repo.record_finding_event(action(n))
    secret = audit_integrity.key(SETTINGS)

    def seal(_):
        return repo.seal_audit(secret, 7)

    for _round in range(10):
        with ThreadPoolExecutor(4) as pool:
            list(pool.map(seal, range(4)))
    report = audit_integrity.verify(repo, SETTINGS)
    assert report["state"] == "INTACT" and report["verified_through"] == 41 and report["pending"] == 0


def test_without_a_fingerprint_key_nothing_is_sealed_or_published():
    repo = InMemoryRepository()
    repo.record_finding_event(action(1))
    blank = Settings()
    assert audit_integrity.seal(repo, blank) == 0 and audit_integrity.publish(repo, blank, now=NOW) is False
