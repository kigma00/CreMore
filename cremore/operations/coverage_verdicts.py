"""Publish vault-comparison verdict changes as ``coverage.verdict_changed``.

Every worker replica calls this from its maintenance tick; a five-minute slot
lets one replica compute the comparison ``GET /api/v1/coverage`` serves and
compare each exposed or issued credential's verdict with the last one
published. The first pass records a baseline silently; after that a new verdict
or a changed one is an event. While the vault scope is unconfirmed the
comparison is suspended and nothing is published or recorded.

Each key keeps a sequence number, and an event's id derives from the key and
the next number, so a crash between queueing events and saving the verdicts
repeats the same ids and the outbox keeps one copy. At most ``MAX_EVENTS``
changes are published per pass; the rest follow in the next.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, Integer, Table, Text, delete, select

from cremore.siem.events import coverage_verdict_changed

SLOT_KEY = "operations:coverage-verdicts"
INTERVAL_SECONDS = 300
MAX_EVENTS = 500


def register_tables(metadata):
    if "coverage_verdicts" in metadata.tables:
        return metadata.tables["coverage_verdicts"]
    return Table("coverage_verdicts", metadata,
                 Column("key", Text, primary_key=True), Column("state", Text, nullable=False),
                 Column("sequence", Integer, nullable=False), Column("updated_at", DateTime(timezone=True), nullable=False))


def row_key(row: dict) -> str | None:
    """A stable key per exposed or issued credential; other rows carry no verdict."""
    if row.get("origin") == "EXPOSURE" and row.get("credential_id"):
        return "exposure:" + row["credential_id"]
    if row.get("origin") == "ISSUANCE":
        if row.get("entity_id"):
            return "entity:" + row["entity_id"]
        issued = row.get("issued") or {}
        if row.get("identifier"):
            return ":".join(("issued", row.get("credential_type", ""), row["identifier"],
                             str(issued.get("connection_id", ""))))
    return None


class _Store:
    def __init__(self, repo):
        self.repo, self.engine = repo, getattr(repo, "engine", None)
        if self.engine is None:
            with repo._lock:
                if not hasattr(repo, "coverage_verdicts"):
                    repo.coverage_verdicts = {}
        else:
            from cremore.db.schema import metadata
            self.table = register_tables(metadata)

    def load(self) -> dict:
        if self.engine is None:
            with self.repo._lock:
                return {key: dict(value) for key, value in self.repo.coverage_verdicts.items()}
        with self.engine.connect() as conn:
            return {row.key: {"state": row.state, "sequence": row.sequence}
                    for row in conn.execute(select(self.table))}

    def save(self, changed: dict, removed: list, now) -> None:
        if self.engine is None:
            with self.repo._lock:
                for key in removed:
                    self.repo.coverage_verdicts.pop(key, None)
                self.repo.coverage_verdicts.update({key: dict(value) for key, value in changed.items()})
            return
        with self.engine.begin() as conn:
            if removed:
                conn.execute(delete(self.table).where(self.table.c.key.in_(removed)))
            for key, value in changed.items():
                statement = self.repo._insert(conn, self.table).values(
                    key=key, state=value["state"], sequence=value["sequence"], updated_at=now)
                conn.execute(statement.on_conflict_do_update(
                    index_elements=[self.table.c.key],
                    set_={"state": value["state"], "sequence": value["sequence"], "updated_at": now}))


def publish(repo, settings, orchestrator, *, now=None) -> int:
    """Queue verdict changes once per slot; returns how many events were queued."""
    from cremore.coverage.correlation import REPORT_LIMIT, report
    from cremore.coverage.models import Contract

    now = now or datetime.now(UTC)
    if not repo.claim_slot(SLOT_KEY, int(now.timestamp()) // INTERVAL_SECONDS, "worker"):
        return 0
    key = orchestrator.config.fingerprint_key
    contract = Contract(engine_digest=orchestrator.engine.detection_digest,
                        policy_digest=orchestrator.coverage_policy_digest).model_dump()
    view = report(repo, contract, limit=REPORT_LIMIT, now=now, settings=settings,
                  fingerprint_key_id=hashlib.sha256(key).hexdigest() if key else None)
    if not view["scope_confirmed"]:
        return 0
    current = {}
    for row in view["items"]:
        name = row_key(row)
        if name is not None:
            current.setdefault(name, row)
    store = _Store(repo)
    stored = store.load()
    if not stored:
        store.save({name: {"state": row["state"], "sequence": 0} for name, row in current.items()}, [], now)
        return 0
    changed, queued = {}, 0
    for name in sorted(current):
        row, before = current[name], stored.get(name)
        if before is not None and before["state"] == row["state"]:
            continue
        if queued >= MAX_EVENTS:
            break
        sequence = (before or {}).get("sequence", 0) + 1
        event = coverage_verdict_changed(key=name, sequence=sequence, row=row,
                                         previous_state=before["state"] if before else None, now=now,
                                         absence_basis=view.get("absence_basis"))
        repo.record_siem_event(event)
        queued += 1
        changed[name] = {"state": row["state"], "sequence": sequence}
    removed = [name for name in stored if name not in current]
    store.save(changed, removed, now)
    return queued
