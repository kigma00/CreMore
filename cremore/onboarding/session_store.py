"""Short-lived authentication drafts, separate from valid provider connections."""

import copy
import datetime as dt
import uuid

from sqlalchemy import JSON, Column, DateTime, Integer, String, Table, Text, Uuid, select, update

from cremore.onboarding.store import ProviderConnectionConflict


def register_table(metadata):
    if "provider_onboarding_sessions" in metadata.tables:
        return metadata.tables["provider_onboarding_sessions"]
    return Table("provider_onboarding_sessions", metadata,
        Column("id", Uuid, primary_key=True), Column("actor", Text, nullable=False),
        Column("binding_hash", String(64), nullable=False), Column("revision", Integer, nullable=False),
        Column("expires_at", DateTime(timezone=True), nullable=False, index=True),
        Column("data", JSON, nullable=False))


class SessionStore:
    def __init__(self, repo):
        self.repo, self.engine = repo, getattr(repo, "engine", None)
        if self.engine is None:
            with repo._lock:
                if not hasattr(repo, "provider_onboarding_sessions"):
                    repo.provider_onboarding_sessions = {}
        else:
            from cremore.db.schema import metadata

            self.table = register_table(metadata)

    def create(self, actor, binding_hash, data, expires_at):
        row = {"id": uuid.uuid4(), "actor": actor, "binding_hash": binding_hash,
               "revision": 1, "expires_at": expires_at, "data": copy.deepcopy(data)}
        if self.engine is None:
            with self.repo._lock:
                self.repo.provider_onboarding_sessions[row["id"]] = row
        else:
            with self.engine.begin() as conn:
                conn.execute(self.table.insert().values(**row))
        return copy.deepcopy(row)

    def get(self, sid, *, lock=False):
        sid = uuid.UUID(str(sid))
        if self.engine is None:
            with self.repo._lock:
                return copy.deepcopy(self.repo.provider_onboarding_sessions.get(sid))
        with self.engine.connect() as conn:
            statement = select(self.table).where(self.table.c.id == sid)
            row = conn.execute(statement.with_for_update() if lock else statement).mappings().first()
        return self._row(row)

    @staticmethod
    def _row(row):
        if row is None:
            return None
        out = dict(row)
        # SQLite returns naive UTC even for DateTime(timezone=True).
        if out["expires_at"].tzinfo is None:
            out["expires_at"] = out["expires_at"].replace(tzinfo=dt.UTC)
        return out

    def save(self, row, data):
        data = copy.deepcopy(data)
        if self.engine is None:
            with self.repo._lock:
                current = self.repo.provider_onboarding_sessions.get(row["id"])
                if current is None or current["revision"] != row["revision"]:
                    raise ProviderConnectionConflict("ONBOARDING_SESSION_CHANGED")
                current.update(data=data, revision=row["revision"] + 1)
                return copy.deepcopy(current)
        with self.engine.begin() as conn:
            done = conn.execute(update(self.table).where(self.table.c.id == row["id"],
                self.table.c.revision == row["revision"]).values(data=data, revision=row["revision"] + 1))
            if done.rowcount != 1:
                raise ProviderConnectionConflict("ONBOARDING_SESSION_CHANGED")
        return {**row, "data": data, "revision": row["revision"] + 1}

    def expired(self, now, limit=100):
        if self.engine is None:
            with self.repo._lock:
                rows = sorted(self.repo.provider_onboarding_sessions.values(), key=lambda row: row["expires_at"])
                return [copy.deepcopy(row) for row in rows if row["expires_at"] <= now
                        and row["data"].get("state") not in {"EXPIRED", "CANCELLED", "COMPLETED"}][:limit]
        with self.engine.connect() as conn:
            # State filtering is portable between SQLite and PostgreSQL JSON.
            rows = conn.execute(select(self.table).where(self.table.c.expires_at <= now,
                self.table.c.data["state"].as_string().not_in(["EXPIRED", "CANCELLED", "COMPLETED"]))
                .order_by(self.table.c.expires_at, self.table.c.id).limit(limit)).mappings()
            return [self._row(row) for row in rows]
