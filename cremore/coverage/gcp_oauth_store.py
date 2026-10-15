"""Short-lived, browser-bound OAuth sessions in the installation's shared DB."""

from __future__ import annotations

import hashlib
import secrets
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime

from sqlalchemy import JSON, Column, DateTime, Index, Table, Text, Uuid, delete, func, select

from cremore.coverage.store import CoverageError, CoverageStore, utc


def register_tables(metadata):
    if "gcp_oauth_sessions" in metadata.tables:
        return metadata.tables["gcp_oauth_sessions"]
    table = Table("gcp_oauth_sessions", metadata,
        Column("id", Uuid, primary_key=True), Column("actor", Text, nullable=False),
        Column("binding_hash", Text, nullable=False), Column("state_hash", Text, nullable=False),
        Column("stage", Text, nullable=False), Column("expires_at", DateTime(timezone=True), nullable=False),
        Column("data", JSON, nullable=False))
    Index("gcp_oauth_sessions_expiry", table.c.expires_at)
    return table


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class GcpOAuthStore(CoverageStore):
    def __init__(self, repo):
        super().__init__(repo)
        if self.engine is None:
            with repo._lock:
                self.memory.setdefault("oauth_sessions", {})
        else:
            from cremore.db.schema import metadata
            self.oauth_sessions = register_tables(metadata)

    @contextmanager
    def transaction(self):
        # Completion writes a provider connection, what it owns, jobs and audit events together.
        # Match SQL rollback semantics in the in-memory development repository.
        with super().transaction() as conn:
            if conn is not None:
                yield conn
                return
            names = ("connections", "_conn_index", "jobs", "finding_events", "check_events",
                     "provider_connections", "provider_connection_children")
            before = {name: deepcopy(getattr(self.repo, name)) for name in names if hasattr(self.repo, name)}
            try:
                yield None
            except BaseException:
                for name, value in before.items():
                    setattr(self.repo, name, value)
                raise

    def create_session(self, row):
        now = datetime.now(UTC)
        with self.transaction() as conn:
            if conn is None:
                for key, item in list(self.memory["oauth_sessions"].items()):
                    if utc(item["expires_at"]) <= now:
                        del self.memory["oauth_sessions"][key]
                count = sum(item["actor"] == row["actor"] for item in self.memory["oauth_sessions"].values())
            else:
                table = self.oauth_sessions
                conn.execute(delete(table).where(table.c.expires_at <= now))
                count = conn.execute(select(func.count()).select_from(table).where(table.c.actor == row["actor"])).scalar_one()
            if count >= 10:
                raise CoverageError("GCP_OAUTH_TOO_MANY_SESSIONS")
            self._put(conn, "oauth_sessions", row, new=True)

    def owned(self, conn, sid, actor, browser_key, stages, *, lock=False):
        row = self._get(conn, "oauth_sessions", sid, lock=lock)
        if (not row or row["actor"] != actor or not secrets.compare_digest(row["binding_hash"], digest(browser_key))
                or utc(row["expires_at"]) <= datetime.now(UTC)):
            raise CoverageError("GCP_OAUTH_SESSION_EXPIRED_OR_INVALID")
        if row["stage"] not in stages:
            raise CoverageError("GCP_OAUTH_SESSION_ALREADY_USED")
        return row

    def save(self, conn, row):
        self._put(conn, "oauth_sessions", row)
