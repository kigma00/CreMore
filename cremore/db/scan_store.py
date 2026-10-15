"""Durable root checkpoints and bounded, sanitized content-cache storage.

Missing state means scan, never means clean. A cache row only says what this
detection policy found in one exact revision it read: an S3 row, a clean one
included, carries the revision GET observed (ETag, size, last-modified), so a
hit means that very revision was read under this digest. Any other revision or
digest misses and is read again; a miss proves nothing. One row per object and
digest holds its latest revision, so a new revision replaces the old in place.
Tables share the application's schema/initialization lock; no new database.
"""

from __future__ import annotations

import hashlib
import json
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    Float,
    String,
    Table,
    Uuid,
    delete,
    func,
    select,
    text,
)


def register_scan_tables(metadata):
    def table(name, *columns):
        return metadata.tables[name] if name in metadata.tables else Table(name, metadata, *columns)

    return {
        "pacing": table(
            "scan_request_pacing",
            Column("id", String(64), primary_key=True),
            Column("next_at", Float, nullable=False),
        ),
        "roots": table(
            "scan_root_states",
            Column("id", String(64), primary_key=True),
            Column("connection_id", Uuid, nullable=False, index=True),
            Column("state", JSON, nullable=False),
            Column("updated_at", DateTime(timezone=True)),
        ),
        "cache": table(
            "scan_detection_cache",
            Column("id", String(64), primary_key=True),
            Column("connection_id", Uuid, nullable=False, index=True),
            Column("root_id", String(64), nullable=False, index=True),
            Column("subject", String(2048), nullable=False),
            Column("revision", String(256), nullable=False),
            Column("digest", String(64), nullable=False),
            Column("detections", JSON, nullable=False),
            Column("updated_at", DateTime(timezone=True), index=True),
        ),
    }


def stable_digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


# Row values: {"v": 2, "detections": [...], "skip": None | "MEDIA_FORMAT" | "UNSUPPORTED_FORMAT",
# "reasons": {extraction reason: 1}, "format": document format}. "reasons" names a
# deterministic gap (a partial or skipped inspection) that every reuse reports again.
CACHE_SKIPS = frozenset({"MEDIA_FORMAT", "UNSUPPORTED_FORMAT"})


def _identity(connection_id, root_id, subject, digest):
    # The revision is compared, not keyed: writing a new one replaces the row, no DELETE
    # scan per write. Rows keyed with their revision before this simply age out (prune).
    return stable_digest([str(connection_id), root_id, subject, digest])


def _entry(value):
    """Rows written before v2 are plain detection lists of complete text reads."""
    if isinstance(value, list):
        return {"v": 2, "detections": value, "skip": None, "reasons": {}, "format": "text"}
    return value


class ScanStore:
    """Same storage contract for SQL and the existing in-memory test repository."""

    def __init__(self, repo):
        self.repo = repo
        self.engine = getattr(repo, "engine", None)
        if self.engine is not None:
            from cremore.db.schema import metadata

            self.tables = register_scan_tables(metadata)
        else:
            if not hasattr(repo, "scan_state_memory"):
                repo.scan_state_memory = {"roots": {}, "cache": {}, "lock": threading.RLock()}
            self.memory = repo.scan_state_memory

    @contextmanager
    def _transaction(self):
        if self.engine is not None:
            with self.engine.begin() as connection:
                yield connection
        else:
            with self.memory["lock"]:
                yield None

    def _upsert(self, connection, table, values):
        dialect = connection.dialect.name
        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as native_insert
        elif dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as native_insert
        else:
            raise ValueError("UNSUPPORTED_SCAN_DATABASE")
        statement = native_insert(table).values(**values)
        connection.execute(
            statement.on_conflict_do_update(
                index_elements=[table.c.id], set_={k: v for k, v in values.items() if k != "id"}
            )
        )

    def root(self, root_id):
        with self._transaction() as connection:
            if connection is None:
                return dict(self.memory["roots"].get(root_id, {}))
            value = connection.execute(
                select(self.tables["roots"].c.state).where(self.tables["roots"].c.id == root_id)
            ).scalar_one_or_none()
            return value or {}

    def request_delay(self, key, interval, *, cooldown=None):
        """Atomically admit a request or return a delay; never sleep under a lock.

        Keys are provider/token digests, never tokens. The DB clock makes the cap
        independent of worker host clocks. A cooldown is shared without admitting
        a request. Expired rows cost one tiny row per authentication identity.
        """
        import math

        from cremore.db.task_store import _clock

        if (len(key) != 64 or any(c not in "0123456789abcdef" for c in key)
                or not math.isfinite(interval) or not 0 < interval <= 60
                or cooldown is not None and (not math.isfinite(cooldown) or not 0 <= cooldown <= 3600)):
            raise ValueError("REQUEST_PACING_INVALID")
        with self._transaction() as connection:
            if connection is None:
                rows = self.memory.setdefault("pacing", {})
                now = _clock().timestamp()
                next_at = rows.get(key, 0)
            else:
                if connection.dialect.name == "sqlite":
                    connection.exec_driver_sql("BEGIN IMMEDIATE")
                from cremore.db.task_store import TaskStore

                table = self.tables["pacing"]
                connection.execute(TaskStore._insert(connection, table).values(id=key, next_at=0)
                                   .on_conflict_do_nothing(index_elements=[table.c.id]))
                next_at = connection.execute(select(table.c.next_at).where(table.c.id == key)
                                             .with_for_update()).scalar_one()
                now = _clock(connection).timestamp()
            delay = max(0.0, next_at - now)
            if cooldown is not None or not delay:
                next_at = max(next_at, now + cooldown) if cooldown is not None else now + interval
                if connection is None:
                    rows[key] = next_at
                else:
                    connection.execute(table.update().where(table.c.id == key).values(next_at=next_at))
            return delay

    def roots(self, root_ids):
        """Read a bounded set of root checkpoints without one SQL query per root."""
        identities = list(dict.fromkeys(root_ids))
        if len(identities) > 20_000:
            raise ValueError("ROOT_CHECKPOINT_READ_LIMIT")
        with self._transaction() as connection:
            if connection is None:
                return {
                    identity: dict(self.memory["roots"][identity])
                    for identity in identities
                    if identity in self.memory["roots"]
                }
            table = self.tables["roots"]
            states = {}
            for offset in range(0, len(identities), 500):
                rows = connection.execute(
                    select(table.c.id, table.c.state).where(
                        table.c.id.in_(identities[offset : offset + 500])
                    )
                )
                states.update({identity: state for identity, state in rows})
            return states

    def save_root(self, root_id, connection_id, state):
        # Root state may contain failed keys, but never downloaded bytes or tokens.
        if len(json.dumps(state, default=str)) > 2_000_000:
            raise ValueError("ROOT_STATE_LIMIT")
        with self._transaction() as connection:
            if connection is None:
                self.memory["roots"][root_id] = dict(state)
                return
            self._upsert(
                connection,
                self.tables["roots"],
                {
                    "id": root_id,
                    "connection_id": connection_id,
                    "state": state,
                    "updated_at": datetime.now(UTC),
                },
            )

    def cached(self, connection_id, root_id, subject, revision, digest):
        return self.cached_many(connection_id, [(root_id, subject, revision)], digest).get(
            (root_id, subject, revision))

    def cached_many(self, connection_id, keys, digest):
        """Look up ``(root_id, subject, revision)`` keys at once; a row answers only for its revision."""
        wanted = {}
        for root_id, subject, revision in keys:
            wanted.setdefault(_identity(connection_id, root_id, subject, digest), []).append((root_id, subject, revision))
        with self._transaction() as connection:
            if connection is None:
                rows = [(i, self.memory["cache"][i]["revision"], self.memory["cache"][i]["detections"])
                        for i in wanted if i in self.memory["cache"]]
            else:
                table, ids, rows = self.tables["cache"], list(wanted), []
                for offset in range(0, len(ids), 500):
                    rows += connection.execute(select(table.c.id, table.c.revision, table.c.detections)
                                               .where(table.c.id.in_(ids[offset : offset + 500]))).all()
        return {key: _entry(value) for identity, revision, value in rows for key in wanted[identity]
                if key[2] == revision}

    def cache(self, connection_id, root_id, subject, revision, digest, detections, *,
              skip=None, reasons=None, fmt="text", source_type=None):
        # Callers supply passive SanitizedDetection only; identifiers are not serialized.
        # source_type is still accepted from existing callers; every source now keeps one row per object.
        if skip is not None and (skip not in CACHE_SKIPS or detections):
            raise ValueError("CACHE_SKIP_INVALID")
        allowed = {
            "detector_name",
            "credential_type",
            "fingerprint",
            "provider",
            "identifier_hint",
            "line_number",
            "redacted_line",
            "confidence",
            "decoder_type",
            "material_kind",
            "extra_safe_data",
        }
        encoded = []
        for detection in detections:
            value = {key: getattr(detection, key) for key in allowed}
            if any(key.startswith("verification_") for key in value["extra_safe_data"]):
                raise ValueError("LIVE_VERIFICATION_NOT_CACHEABLE")
            encoded.append(value)
        # Only fixed reason codes and a format label: never extracted text.
        encoded = {"v": 2, "detections": encoded, "skip": skip,
                   "reasons": {str(k): int(v) for k, v in (reasons or {}).items()}, "format": str(fmt)[:32]}
        if len(json.dumps(encoded).encode()) > 128_000:
            return  # Not cached is safe; detection still persists normally.
        identity = _identity(connection_id, root_id, subject, digest)
        with self._transaction() as connection:
            if connection is None:
                self.memory["cache"][identity] = {"revision": revision, "detections": encoded}
                return
            table = self.tables["cache"]
            self._upsert(
                connection,
                table,
                {
                    "id": identity,
                    "connection_id": connection_id,
                    "root_id": root_id,
                    "subject": subject,
                    "revision": revision,
                    "digest": digest,
                    "detections": encoded,
                    "updated_at": datetime.now(UTC),
                },
            )

    def prune_cache(self, *, max_entries=2_000_000, days=14, batch=1000):
        """Bounded maintenance of disposable masked results, never source evidence.

        Row limit is an eviction target, not a hard byte quota. Active workers
        can temporarily exceed it between maintenance passes. A cache miss reads
        the approved source again and cannot be interpreted as a clean result.
        """
        with self._transaction() as connection:
            if connection is None:
                excess = max(0, len(self.memory["cache"]) - max_entries)
                keys = list(self.memory["cache"])[: min(excess, batch)]
                for key in keys:
                    self.memory["cache"].pop(key, None)
                return len(keys)
            table = self.tables["cache"]
            cutoff = datetime.now(UTC) - timedelta(days=days)
            old = list(
                connection.scalars(
                    select(table.c.id)
                    .where(table.c.updated_at < cutoff)
                    .order_by(table.c.updated_at)
                    .limit(batch)
                )
            )
            # Skipping past max_entries rows costs a scan of them: only when the table can hold more.
            if len(old) < batch and self._may_exceed(connection, table, max_entries):
                old += list(
                    connection.scalars(
                        select(table.c.id)
                        .order_by(table.c.updated_at.desc(), table.c.id)
                        .offset(max_entries)
                        .limit(batch - len(old))
                    )
                )
            if old:
                connection.execute(delete(table).where(table.c.id.in_(old)))
            return len(set(old))

    @staticmethod
    def _may_exceed(connection, table, bound):
        """PostgreSQL's planner estimate (none yet counts as possible, a tenth of slack for
        a stale one); other databases count."""
        if connection.dialect.name == "postgresql":
            estimate = connection.execute(text("SELECT reltuples FROM pg_class WHERE oid = to_regclass(:name)"),
                                          {"name": table.name}).scalar()
            return estimate is None or estimate < 0 or estimate > bound * 0.9
        return connection.scalar(select(func.count()).select_from(table)) > bound
