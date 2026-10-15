"""What analysts add to a finding beside its triage status: tags, the review stage, the
state of each remediation step and the latest owner contact.

The workflow status (open, acknowledged, resolved, false positive, ignored) stays on
the finding and its own transitions. An acknowledged finding is either still being
reviewed or already being remediated (``stage``), and any status transition clears
the stage. Each recommended remediation step (revoke, clean up, move into a vault,
reduce access) keeps its own state and comment. A contact records how and by when an
owner was asked; the message itself is never stored. Every change is guarded by a
revision, and the routes record it in the finding's history. No secret is stored here.
"""

from __future__ import annotations

import copy
import datetime as _dt
import uuid

from sqlalchemy import JSON, Column, DateTime, Integer, String, Table, Text, Uuid, select, update
from sqlalchemy.exc import IntegrityError

STAGES = ("review", "action")
STEP_IDS = ("revoke", "cleanup", "vault", "scope")
STEP_STATES = ("open", "progress", "done", "na")


class AnnotationConflict(ValueError):
    """The annotations changed since they were read."""


def register_tables(metadata):
    if "finding_annotations" in metadata.tables:
        return metadata.tables["finding_annotations"]
    return Table(
        "finding_annotations", metadata,
        Column("finding_id", Uuid, primary_key=True),
        Column("tags", JSON, nullable=False),
        Column("stage", String(16), nullable=True),
        # step id -> {status, comment, updated_by, updated_at}
        Column("steps", JSON, nullable=False),
        # {channel, template, recipients, due_at, at, by}
        Column("contact", JSON(none_as_null=True), nullable=True),
        Column("revision", Integer, nullable=False),
        Column("updated_by", Text, nullable=False),
        Column("updated_at", DateTime(timezone=True), nullable=False))


def _now():
    return _dt.datetime.now(_dt.UTC)


def empty(finding_id) -> dict:
    return {"finding_id": uuid.UUID(str(finding_id)), "tags": [], "stage": None, "steps": {}, "contact": None,
            "revision": 0, "updated_by": None, "updated_at": None}


class AnnotationStore:
    def __init__(self, repo):
        self.repo, self.engine = repo, getattr(repo, "engine", None)
        if self.engine is None:
            with repo._lock:
                if not hasattr(repo, "finding_annotations"):
                    repo.finding_annotations = {}
        else:
            from cremore.db.schema import metadata

            self.table = register_tables(metadata)

    def get(self, finding_id) -> dict:
        finding_id = uuid.UUID(str(finding_id))
        if self.engine is None:
            with self.repo._lock:
                row = self.repo.finding_annotations.get(finding_id)
                return copy.deepcopy(row) if row else empty(finding_id)
        with self.engine.connect() as conn:
            row = conn.execute(select(self.table).where(self.table.c.finding_id == finding_id)).mappings().first()
        return dict(row) if row else empty(finding_id)

    def many(self, finding_ids) -> dict:
        """``{finding id: annotations}`` for every finding that has any."""
        ids = [uuid.UUID(str(i)) for i in finding_ids]
        if not ids:
            return {}
        if self.engine is None:
            with self.repo._lock:
                return {i: copy.deepcopy(self.repo.finding_annotations[i]) for i in ids
                        if i in self.repo.finding_annotations}
        out = {}
        with self.engine.connect() as conn:
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                for row in conn.execute(select(self.table).where(self.table.c.finding_id.in_(chunk))).mappings():
                    out[row["finding_id"]] = dict(row)
        return out

    def change(self, finding_id, revision: int, actor: str, **changes) -> dict:
        """Apply ``changes`` if the annotations are still at ``revision`` (0 before the first)."""
        finding_id = uuid.UUID(str(finding_id))
        now = _now()
        if self.engine is None:
            with self.repo._lock:
                current = self.repo.finding_annotations.get(finding_id) or empty(finding_id)
                if current["revision"] != revision:
                    raise AnnotationConflict("ANNOTATIONS_CHANGED")
                row = {**current, **copy.deepcopy(changes), "revision": revision + 1, "updated_by": actor,
                       "updated_at": now}
                self.repo.finding_annotations[finding_id] = row
                return copy.deepcopy(row)
        with self.engine.begin() as conn:
            if revision == 0:
                row = {**empty(finding_id), **changes, "revision": 1, "updated_by": actor, "updated_at": now}
                try:
                    with conn.begin_nested():
                        conn.execute(self.table.insert().values(**row))
                except IntegrityError:  # a concurrent first write created it
                    raise AnnotationConflict("ANNOTATIONS_CHANGED") from None
                return row
            done = conn.execute(update(self.table).where(self.table.c.finding_id == finding_id,
                                                         self.table.c.revision == revision)
                                .values(**changes, revision=revision + 1, updated_by=actor, updated_at=now))
            if done.rowcount != 1:
                raise AnnotationConflict("ANNOTATIONS_CHANGED")
            return dict(conn.execute(select(self.table).where(self.table.c.finding_id == finding_id)).mappings().one())

    def clear_stage(self, finding_id, actor: str) -> None:
        """A status transition ends the review stage the finding was in."""
        finding_id = uuid.UUID(str(finding_id))
        if self.engine is None:
            with self.repo._lock:
                row = self.repo.finding_annotations.get(finding_id)
                if row and row["stage"] is not None:
                    row.update(stage=None, revision=row["revision"] + 1, updated_by=actor, updated_at=_now())
            return
        with self.engine.begin() as conn:
            conn.execute(update(self.table).where(self.table.c.finding_id == finding_id, self.table.c.stage.is_not(None))
                         .values(stage=None, revision=self.table.c.revision + 1, updated_by=actor, updated_at=_now()))
