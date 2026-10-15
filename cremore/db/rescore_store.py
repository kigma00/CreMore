"""Singleton evaluation checkpoint; bounded transactions reuse repository locks."""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime

from sqlalchemy import JSON, Column, DateTime, Integer, String, Table, func, or_, select, update

from cremore.db.task_store import TaskStore, _clock
from cremore.domain.models import Exposure, Finding


def register_rescore_table(metadata):
    if "scan_rescore_state" in metadata.tables:
        return metadata.tables["scan_rescore_state"]
    return Table("scan_rescore_state", metadata,
        Column("id", Integer, primary_key=True),
        Column("digest", String(64), nullable=False),
        Column("checkpoint", JSON, nullable=False),
        Column("updated_at", DateTime(timezone=True), nullable=False))


class RescoreStore:
    def __init__(self, repo):
        self.repo = repo
        self.transactions = TaskStore(repo)
        self.engine = getattr(repo, "engine", None)
        if self.engine is not None:
            from cremore.db.schema import metadata
            self.table = register_rescore_table(metadata)
        elif not hasattr(repo, "rescore_state_memory"):
            repo.rescore_state_memory = None

    def profile_revision(self, conn=None):
        """Small change token; no centroid/sample materialization in worker ticks."""
        if self.engine is None:
            rows = list(self.repo.fp_profiles.values())
            return [len(rows), max((str(p.updated_at) for p in rows), default="")]
        from cremore.db.schema import fp_profiles
        if conn is not None:
            count, changed = conn.execute(select(func.count(), func.max(fp_profiles.c.updated_at))).one()
            return [count, str(changed or "")]
        with self.engine.connect() as connection:
            count, changed = connection.execute(select(func.count(), func.max(fp_profiles.c.updated_at))).one()
            return [count, str(changed or "")]

    @contextmanager
    def transaction(self, digest):
        with self.transactions._transaction() as conn:
            if conn is None:
                # The development repository mirrors SQL rollback semantics.
                names = ("exposures", "findings", "finding_events", "rescore_state_memory")
                before = {name: deepcopy(getattr(self.repo, name)) for name in names}
                state = deepcopy(self.repo.rescore_state_memory)
            else:
                conn.execute(self.transactions._insert(conn, self.table).values(
                    id=1, digest=digest, checkpoint={}, updated_at=_clock(conn)).on_conflict_do_nothing())
                state = dict(conn.execute(select(self.table).where(self.table.c.id == 1).with_for_update()).mappings().one())
            if state is None or state["digest"] != digest:
                state = {"digest": digest, "checkpoint": {}}
            state["checkpoint"] = deepcopy(state["checkpoint"])
            try:
                yield self.transactions._bound(conn), state["checkpoint"], conn
                if conn is None:
                    self.repo.rescore_state_memory = state
                else:
                    conn.execute(update(self.table).where(self.table.c.id == 1).values(
                        digest=digest, checkpoint=state["checkpoint"], updated_at=_clock(conn)))
            except BaseException:
                if conn is None:
                    for name, value in before.items():
                        setattr(self.repo, name, value)
                raise

    def finding(self, conn, checkpoint):
        current = checkpoint.get("finding_id")
        after = checkpoint.get("after_finding")
        if conn is None:
            if current:
                return self.repo.get_finding(uuid.UUID(current))
            rows = (f for f in self.repo.findings.values() if not after or str(f.id) > after)
            return min(rows, key=lambda f: str(f.id), default=None)
        from cremore.db.schema import findings
        query = select(findings)
        if current:
            query = query.where(findings.c.id == uuid.UUID(current))
        elif after:
            query = query.where(findings.c.id > uuid.UUID(after))
        row = conn.execute(query.order_by(findings.c.id).limit(1)).mappings().first()
        if row is None:
            return None
        self.repo._lock_credential(conn, row["credential_id"])
        row = conn.execute(select(findings).where(findings.c.id == row["id"]).with_for_update()).mappings().first()
        return Finding.model_validate(dict(row)) if row else None

    def page(self, conn, credential_id, after, limit):
        if conn is None:
            rows = (e for e in self.repo.exposures.values() if e.credential_id == credential_id
                    and e.status != "REMOVED" and (not after or str(e.id) > after))
            return sorted(rows, key=lambda e: str(e.id))[:limit]
        from cremore.db.schema import exposures
        from cremore.db.sql import _to
        query = select(exposures).where(exposures.c.credential_id == credential_id, exposures.c.status != "REMOVED")
        if after:
            query = query.where(exposures.c.id > uuid.UUID(after))
        return [_to(Exposure, r) for r in conn.execute(query.order_by(exposures.c.id).limit(limit)).mappings()]

    def observations_changed(self, conn, credential_id, started):
        cutoff = datetime.fromisoformat(started)
        if conn is None:
            return any(e.credential_id == credential_id and any(
                t and (t.replace(tzinfo=UTC) if t.tzinfo is None else t) >= cutoff
                for t in (e.last_seen_at, e.removed_at)) for e in self.repo.exposures.values())
        from cremore.db.schema import exposures
        return conn.execute(select(exposures.c.id).where(exposures.c.credential_id == credential_id,
            or_(exposures.c.last_seen_at >= cutoff, exposures.c.removed_at >= cutoff)).limit(1)).first() is not None
