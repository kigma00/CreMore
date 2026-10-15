"""Provider connections and the records they own, in memory or in the database.

A provider connection is one provider identity and one credential. What it is used
for lives in the existing stores (content connections, AWS accounts, coverage and
metadata connections); ``provider_connection_children`` says which of those records
a provider connection owns, so a credential change or a disable reaches every one.
"""

from __future__ import annotations

import copy
import datetime as _dt
import uuid
from contextlib import contextmanager

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    Integer,
    String,
    Table,
    Text,
    Uuid,
    delete,
    select,
    update,
)

CHILD_KINDS = ("content", "aws_account", "metadata", "coverage")


class ProviderConnectionConflict(ValueError):
    """The record changed since it was read (revision mismatch)."""


# In-memory state no wizard step writes, which holds its own lock and cannot be copied.
_NOT_WRITTEN = frozenset({"scan_state_memory"})


@contextmanager
def atomic(repo):
    """One wizard step that writes several stores: all of it, or none of it.

    Yields the repository to write through. In the database every store is bound to one
    transaction; in memory (development and tests) the repository lock is held and the
    state is put back if the step fails. A step that failed half-way would otherwise
    leave records a retry collides with.
    """
    from cremore.db.task_store import TaskStore

    tasks = TaskStore(repo)
    with tasks._transaction() as conn:
        if conn is not None:
            yield tasks._bound(conn)
            return
        state = vars(repo)
        before = {name: copy.deepcopy(value) for name, value in state.items()
                  if name not in _NOT_WRITTEN and isinstance(value, (dict, list, set))}
        names = set(state)
        try:
            yield repo
        except BaseException:
            for name in set(state) - names:
                del state[name]
            for name, value in before.items():
                current = state[name]
                if isinstance(current, list):
                    current[:] = value
                else:
                    current.clear()
                    current.update(value)
            raise


def register_tables(metadata):
    if "provider_connections" in metadata.tables:
        return metadata.tables["provider_connections"], metadata.tables["provider_connection_children"]
    connections = Table(
        "provider_connections", metadata,
        Column("id", Uuid, primary_key=True),
        Column("provider", String(64), nullable=False), Column("edition", String(32), nullable=False),
        Column("name", String(120), nullable=False), Column("target", JSON, nullable=False),
        Column("auth_method", String(64), nullable=False),
        # role -> sealed or vault:// reference; the API never returns these.
        Column("secret_refs", JSON, nullable=False),
        Column("purposes", JSON, nullable=False), Column("checks", JSON, nullable=False),
        # purpose -> the step 4 choices it was activated with (AWS applies them to adopted accounts).
        Column("plans", JSON, nullable=False),
        # Nullable for additive upgrades and older writers; NULL means no individual pauses.
        Column("disabled_purposes", JSON, nullable=True),
        Column("status", String(16), nullable=False), Column("revision", Integer, nullable=False),
        Column("created_by", Text, nullable=False), Column("updated_by", Text, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("updated_at", DateTime(timezone=True), nullable=False))
    children = Table(
        "provider_connection_children", metadata,
        Column("kind", String(16), primary_key=True), Column("child_id", String(64), primary_key=True),
        Column("provider_connection_id", Uuid, nullable=False, index=True),
        Column("purpose", String(16), nullable=False),
        # child credential slot -> provider connection role, so a new credential reaches it.
        Column("secret_slots", JSON, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False))
    return connections, children


def _now():
    return _dt.datetime.now(_dt.UTC)


def _row(row):
    return None if row is None else {**dict(row), "disabled_purposes": list(row.get("disabled_purposes") or [])}


def active_plans(record):
    """Configured plans that have not been explicitly paused; configuration is retained."""
    disabled = set(record.get("disabled_purposes") or [])
    return {purpose: plan for purpose, plan in (record.get("plans") or {}).items() if purpose not in disabled}


def child_feature_enabled(repo, kind, child_id, purpose):
    """Execution guard for shared children whose own enabled flag serves several features."""
    store = ProviderConnectionStore(repo)
    owner = store.parent_of("aws_account" if kind == "aws" else "content", child_id)
    record = store.get(owner) if owner else None
    return record is None or (record["status"] != "DISABLED" and purpose not in (record.get("disabled_purposes") or []))


class ProviderConnectionStore:
    def __init__(self, repo):
        self.repo, self.engine = repo, getattr(repo, "engine", None)
        if self.engine is None:
            with repo._lock:
                if not hasattr(repo, "provider_connections"):
                    repo.provider_connections, repo.provider_connection_children = {}, {}
        else:
            from cremore.db.schema import metadata

            self.table, self.children_table = register_tables(metadata)

    # --- provider connections ---------------------------------------------------

    def create(self, record: dict, actor: str) -> dict:
        now = _now()
        row = {"id": uuid.uuid4(), "checks": {}, "plans": {}, "disabled_purposes": [], "status": "DRAFT", "revision": 1, "created_by": actor,
               "updated_by": actor, "created_at": now, "updated_at": now, **record}
        if self.engine is None:
            with self.repo._lock:
                self.repo.provider_connections[row["id"]] = dict(row)
            return dict(row)
        with self.engine.begin() as conn:
            conn.execute(self.table.insert().values(**row))
        return dict(row)

    def get(self, connection_id) -> dict | None:
        connection_id = uuid.UUID(str(connection_id))
        if self.engine is None:
            with self.repo._lock:
                return _row(self.repo.provider_connections.get(connection_id))
        with self.engine.connect() as conn:
            return _row(conn.execute(select(self.table).where(self.table.c.id == connection_id)).mappings().first())

    def list(self) -> list[dict]:
        if self.engine is None:
            with self.repo._lock:
                rows = [_row(row) for row in self.repo.provider_connections.values()]
        else:
            with self.engine.connect() as conn:
                rows = [_row(row) for row in conn.execute(select(self.table)).mappings()]
        return sorted(rows, key=lambda row: (row["created_at"], str(row["id"])))

    def update(self, connection_id, revision: int, actor: str, **changes) -> dict:
        """Apply ``changes`` if the record is still at ``revision``; the revision then moves on."""
        connection_id = uuid.UUID(str(connection_id))
        values = {**changes, "revision": revision + 1, "updated_by": actor, "updated_at": _now()}
        if self.engine is None:
            with self.repo._lock:
                current = self.repo.provider_connections.get(connection_id)
                if current is None or current["revision"] != revision:
                    raise ProviderConnectionConflict("PROVIDER_CONNECTION_CHANGED")
                current.update(values)
                return dict(current)
        with self.engine.begin() as conn:
            done = conn.execute(update(self.table).where(self.table.c.id == connection_id,
                                                         self.table.c.revision == revision).values(**values))
            if done.rowcount != 1:
                raise ProviderConnectionConflict("PROVIDER_CONNECTION_CHANGED")
            return dict(conn.execute(select(self.table).where(self.table.c.id == connection_id)).mappings().one())

    def delete(self, connection_id) -> None:
        """Remove a provider connection that owns nothing."""
        connection_id = uuid.UUID(str(connection_id))
        if self.children(connection_id):
            raise ProviderConnectionConflict("PROVIDER_CONNECTION_HAS_CHILDREN")
        if self.engine is None:
            with self.repo._lock:
                self.repo.provider_connections.pop(connection_id, None)
            return
        with self.engine.begin() as conn:
            conn.execute(delete(self.table).where(self.table.c.id == connection_id))

    # --- owned records -----------------------------------------------------------

    def link(self, connection_id, purpose: str, kind: str, child_id, secret_slots: dict | None = None) -> None:
        if kind not in CHILD_KINDS:
            raise ValueError("PROVIDER_CONNECTION_CHILD_KIND")
        row = {"kind": kind, "child_id": str(child_id), "provider_connection_id": uuid.UUID(str(connection_id)),
               "purpose": purpose, "secret_slots": dict(secret_slots or {}), "created_at": _now()}
        if self.engine is None:
            with self.repo._lock:
                self.repo.provider_connection_children[(kind, row["child_id"])] = row
            return
        with self.engine.begin() as conn:
            conn.execute(self.children_table.insert().values(**row))

    def relink(self, connection_id, purpose: str, kind: str, child_id, secret_slots: dict | None = None) -> None:
        """Move a linked record to another provider connection (its previous owner was disabled)."""
        values = {"provider_connection_id": uuid.UUID(str(connection_id)), "purpose": purpose,
                  "secret_slots": dict(secret_slots or {}), "created_at": _now()}
        if self.engine is None:
            with self.repo._lock:
                self.repo.provider_connection_children[(kind, str(child_id))].update(values)
            return
        with self.engine.begin() as conn:
            conn.execute(update(self.children_table).where(self.children_table.c.kind == kind,
                                                           self.children_table.c.child_id == str(child_id))
                         .values(**values))

    def children(self, connection_id) -> list[dict]:
        connection_id = uuid.UUID(str(connection_id))
        if self.engine is None:
            with self.repo._lock:
                rows = [dict(row) for row in self.repo.provider_connection_children.values()
                        if row["provider_connection_id"] == connection_id]
        else:
            with self.engine.connect() as conn:
                rows = [dict(row) for row in conn.execute(select(self.children_table).where(
                    self.children_table.c.provider_connection_id == connection_id)).mappings()]
        return sorted(rows, key=lambda row: (row["created_at"], row["kind"], row["child_id"]))

    def parent_of(self, kind: str, child_id) -> uuid.UUID | None:
        key = (kind, str(child_id))
        if self.engine is None:
            with self.repo._lock:
                row = self.repo.provider_connection_children.get(key)
        else:
            with self.engine.connect() as conn:
                row = conn.execute(select(self.children_table).where(
                    self.children_table.c.kind == kind,
                    self.children_table.c.child_id == key[1])).mappings().first()
        return None if row is None else row["provider_connection_id"]
