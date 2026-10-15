"""Searchable, replaceable profile projection of completed IdP metadata observations.

Only explicit keep_profiles collections populate this index. Coverage records remain the evidence;
this projection never supplies a new identity assertion, completeness or source authorization.
"""

from __future__ import annotations

import copy
import uuid

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    Table,
    Text,
    Uuid,
    and_,
    delete,
    func,
    or_,
    select,
)

from cremore.coverage.facts import unpack_facts


def register_tables(metadata):
    if "identity_directory_entries" in metadata.tables:
        return metadata.tables["identity_directory_entries"], metadata.tables["identity_directory_keys"]
    entries = Table("identity_directory_entries", metadata,
        Column("entity_id", Uuid, ForeignKey("coverage_entities.id", ondelete="CASCADE"), primary_key=True),
        Column("person_ref", Uuid, nullable=False), Column("connection_id", Uuid, nullable=False),
        Column("run_id", Uuid, nullable=False),
        Column("record_id", Uuid, ForeignKey("coverage_records.id", ondelete="CASCADE"), nullable=False),
        Column("provider", Text, nullable=False), Column("origin", Text, nullable=False),
        Column("tenant", Text, nullable=False), Column("idp_user_id", Text, nullable=False),
        Column("name", Text), Column("email", Text), Column("department", Text), Column("title", Text),
        Column("state", Text, nullable=False), Column("observed_at", DateTime(timezone=True), nullable=False),
        Column("sort_key", Text, nullable=False), Column("search_key", Text, nullable=False),
        Column("email_key", Text, nullable=False), Column("key_id", Text))
    Index("identity_directory_person", entries.c.person_ref)
    Index("identity_directory_page", entries.c.connection_id, entries.c.sort_key, entries.c.entity_id)
    Index("identity_directory_email", entries.c.email_key)
    keys = Table("identity_directory_keys", metadata,
        Column("entity_id", Uuid, ForeignKey("identity_directory_entries.entity_id", ondelete="CASCADE"), primary_key=True),
        Column("kind", Text, primary_key=True), Column("digest", Text, primary_key=True),
        Column("key_id", Text, nullable=False))
    Index("identity_directory_digest", keys.c.key_id, keys.c.digest)
    return entries, keys


def project_entity(store, conn, entity, run, spec):
    """Replace one profile inside the metadata finish transaction, including opt-out removal."""
    from cremore.identity.leavers import identity_providers, person_ref

    idps, _ = identity_providers()
    if entity["provider"] not in idps or entity["purpose"] != "identity_status" or entity["object_kind"] != "principal":
        return
    entries, keys = (None, None) if conn is None else register_tables(store.entities.metadata)
    if conn is None:
        store.memory.setdefault("directory_entries", {}).pop(entity["id"], None)
        store.memory.setdefault("directory_keys", {}).pop(entity["id"], None)
    else:
        conn.execute(delete(keys).where(keys.c.entity_id == entity["id"]))
        conn.execute(delete(entries).where(entries.c.entity_id == entity["id"]))
    if not (spec.get("options") or {}).get("keep_profiles") or not entity["object_id"].startswith("user:"):
        return
    body = entity["summary"] or {}
    facts = unpack_facts(body.get("facts") or [])
    profile = {key: facts.get(source) if isinstance(facts.get(source), str) else None
               for key, source in (("name", "display_name"), ("email", "email"), ("department", "department"), ("title", "title"))}
    user_id = entity["object_id"][5:]
    profile["name"] = profile["name"] or profile["email"] or user_id
    row = {"entity_id": entity["id"], "person_ref": person_ref(entity["provider"], entity["origin"], entity["tenant"], user_id),
           "connection_id": run["connection_id"], "run_id": run["id"], "record_id": entity["current_record_id"],
           "provider": entity["provider"], "origin": entity["origin"], "tenant": entity["tenant"], "idp_user_id": user_id,
           **profile, "state": {"ACTIVE": "ACTIVE", "DISABLED": "DEPARTED", "DELETED": "DEPARTED", "PENDING": "PENDING"}.get(body.get("normalized_state"), "UNKNOWN"),
           "observed_at": entity["observed_at"], "sort_key": profile["name"].casefold(),
           "search_key": " ".join(value or "" for value in profile.values()).casefold(),
           "email_key": (profile["email"] or "").strip().casefold(), "key_id": body.get("identity_key_id")}
    digest_rows = [{"entity_id": entity["id"], "kind": key["kind"], "digest": key["digest"], "key_id": row["key_id"]}
                   for key in body.get("identity_keys") or [] if row["key_id"]]
    if conn is None:
        store.memory["directory_entries"][entity["id"]] = copy.deepcopy(row)
        store.memory["directory_keys"][entity["id"]] = copy.deepcopy(digest_rows)
    else:
        conn.execute(entries.insert().values(**row))
        if digest_rows:
            conn.execute(keys.insert(), digest_rows)


def prune_profiles(store, conn, run_ids):
    """Follow source retention even on SQLite connections without FK enforcement."""
    if conn is None:
        for key, profile in list(store.memory.get("directory_entries", {}).items()):
            if profile["run_id"] in run_ids:
                store.memory["directory_entries"].pop(key, None)
                store.memory.get("directory_keys", {}).pop(key, None)
        return
    entries, keys = register_tables(store.entities.metadata)
    removed = select(entries.c.entity_id).where(entries.c.run_id.in_(run_ids))
    conn.execute(delete(keys).where(keys.c.entity_id.in_(removed)))
    conn.execute(delete(entries).where(entries.c.run_id.in_(run_ids)))


class DirectoryStore:
    def __init__(self, repo):
        from cremore.coverage.metadata_store import MetadataStore
        from cremore.identity.leavers import LeaverStore

        self.repo, self.store = repo, MetadataStore(repo)
        self.leavers = LeaverStore(repo)
        if self.store.engine is not None:
            self.entries, self.keys = register_tables(self.store.entities.metadata)

    def _statement(self, allowed):
        e, entities = self.entries, self.store.entities
        people = self.leavers.people_t
        query = select(e).join(entities, and_(entities.c.id == e.c.entity_id, entities.c.current_record_id == e.c.record_id)).outerjoin(
            people, people.c.person_ref == e.c.person_ref).where(e.c.connection_id.in_(allowed),
                or_(people.c.state.is_(None), people.c.state != "PURGED"))
        if isinstance(allowed, dict) and allowed:
            query = query.where(or_(*(and_(e.c.connection_id == cid, e.c.provider == source["provider"],
                e.c.origin == source["origin"], e.c.tenant == source["tenant"]) for cid, source in allowed.items())))
        return query

    def _rows(self, allowed):
        entities, known = self.store.memory["entities"], self.leavers.memory["people"]
        return [copy.deepcopy(row) for row in self.store.memory.get("directory_entries", {}).values()
                if row["connection_id"] in allowed and entities.get(row["entity_id"], {}).get("current_record_id") == row["record_id"]
                and (not isinstance(allowed, dict) or all(row[key] == allowed[row["connection_id"]][key] for key in ("provider", "origin", "tenant")))
                and known.get(row["person_ref"], {}).get("state") != "PURGED"]

    def page(self, allowed, *, query="", after=None, limit=200):
        """Keyset pagination and search execute in SQL; memory has the same ordering for tests."""
        with self.store.transaction() as conn:
            if conn is None:
                rows = [row for row in self._rows(allowed) if not query or query in row["search_key"]]
                rows.sort(key=lambda row: (row["sort_key"], str(row["entity_id"])))
                total = len(rows)
                if after:
                    rows = [row for row in rows if (row["sort_key"], str(row["entity_id"])) > after]
                return rows[:limit], total
            query_ = self._statement(allowed)
            if query:
                query_ = query_.where(self.entries.c.search_key.contains(query, autoescape=True))
            total = conn.execute(select(func.count()).select_from(query_.subquery())).scalar_one()
            if after:
                query_ = query_.where(or_(self.entries.c.sort_key > after[0], and_(
                    self.entries.c.sort_key == after[0], self.entries.c.entity_id > uuid.UUID(after[1]))))
            rows = conn.execute(query_.order_by(self.entries.c.sort_key, self.entries.c.entity_id).limit(limit)).mappings()
            return [dict(row) for row in rows], total

    def find(self, allowed, *, person_ref=None, person_refs=None, digests=(), key_id=None, email_key=None, limit=501):
        """Bounded exact lookups for dispatch, duplicate contacts and owner suggestions."""
        with self.store.transaction() as conn:
            if conn is None:
                rows = self._rows(allowed)
                if person_ref is not None:
                    rows = [row for row in rows if row["person_ref"] == person_ref]
                if person_refs is not None:
                    rows = [row for row in rows if row["person_ref"] in person_refs]
                if email_key is not None:
                    rows = [row for row in rows if row["email_key"] == email_key]
                if digests:
                    ids = {eid for eid, keys in self.store.memory.get("directory_keys", {}).items()
                           if any(k["digest"] in digests and (key_id is None or k["key_id"] == key_id) for k in keys)}
                    rows = [row for row in rows if row["entity_id"] in ids]
                return rows[:limit]
            query = self._statement(allowed)
            if person_ref is not None:
                query = query.where(self.entries.c.person_ref == person_ref)
            if person_refs is not None:
                query = query.where(self.entries.c.person_ref.in_(person_refs))
            if email_key is not None:
                query = query.where(self.entries.c.email_key == email_key)
            if digests:
                keyed = select(self.keys.c.entity_id).where(self.keys.c.digest.in_(digests))
                if key_id is not None:
                    keyed = keyed.where(self.keys.c.key_id == key_id)
                query = query.where(self.entries.c.entity_id.in_(keyed))
            return [dict(row) for row in conn.execute(query.limit(limit)).mappings()]

    def keys_for(self, entity_ids):
        with self.store.transaction() as conn:
            if conn is None:
                return {eid: copy.deepcopy(self.store.memory.get("directory_keys", {}).get(eid, [])) for eid in entity_ids}
            found = {eid: [] for eid in entity_ids}
            for row in conn.execute(select(self.keys).where(self.keys.c.entity_id.in_(entity_ids))).mappings():
                found[row["entity_id"]].append(dict(row))
            return found

    def duplicate_emails(self, email_keys, sources, *, after, before):
        ready = {cid: source for cid, source in sources.items() if source["usable"]}
        runs = {uuid.UUID(source["run_id"]) for source in ready.values()}
        if not email_keys or not runs:
            return set()
        from cremore.coverage.store import utc

        with self.store.transaction() as conn:
            if conn is None:
                found = {}
                for row in self._rows(ready):
                    source = ready[row["connection_id"]]
                    if (row["email_key"] in email_keys and row["state"] == "ACTIVE" and row["run_id"] in runs
                            and after <= utc(row["observed_at"]) <= before
                            and (row["provider"], row["origin"], row["tenant"]) == (source["provider"], source["origin"], source["tenant"])):
                        found.setdefault(row["email_key"], set()).add(row["person_ref"])
                return {key for key, refs in found.items() if len(refs) > 1}
            e = self.entries
            allowed = or_(*(and_(e.c.connection_id == cid, e.c.provider == s["provider"], e.c.origin == s["origin"],
                                e.c.tenant == s["tenant"]) for cid, s in ready.items()))
            eligible = self._statement(ready).where(allowed, e.c.run_id.in_(runs), e.c.state == "ACTIVE",
                e.c.email_key.in_(email_keys), e.c.observed_at >= after, e.c.observed_at <= before).subquery()
            query = select(eligible.c.email_key).group_by(eligible.c.email_key).having(func.count(func.distinct(eligible.c.person_ref)) > 1)
            return set(conn.execute(query).scalars())

    def rebuild(self, *, batch_size=250):
        """Explicit bounded backfill from existing metadata; never performed by a search request."""
        after, count = None, 0
        while True:
            with self.store.transaction() as conn:
                if conn is None:
                    rows = sorted((row for row in self.store.memory["entities"].values()
                        if row["purpose"] == "identity_status" and row["current_record_id"]
                        and (after is None or str(row["id"]) > str(after))), key=lambda row: str(row["id"]))[:batch_size]
                else:
                    query = select(self.store.entities).where(self.store.entities.c.purpose == "identity_status",
                        self.store.entities.c.current_record_id.is_not(None)).order_by(self.store.entities.c.id).limit(batch_size)
                    if after is not None:
                        query = query.where(self.store.entities.c.id > after)
                    rows = [dict(row) for row in conn.execute(query.with_for_update()).mappings()]
                if not rows:
                    return count
                for entity in rows:
                    after = entity["id"]
                    run = self.store._get(conn, "runs", entity["latest_run_id"])
                    if run is None:
                        continue
                    owner = self.store._get(conn, "connections", run["connection_id"])
                    spec = run["contract"].get("spec_snapshot") or (owner or {}).get("spec") or {}
                    if not ((owner or {}).get("spec", {}).get("options") or {}).get("keep_profiles"):
                        spec = {**spec, "options": {**(spec.get("options") or {}), "keep_profiles": False}}
                    project_entity(self.store, conn, entity, run, spec)
                    count += 1

    def projection_ready(self, run_id):
        with self.store.transaction() as conn:
            if conn is None:
                entries = self.store.memory.get("directory_entries", {})
                return all(entries.get(e["id"], {}).get("record_id") == e["current_record_id"]
                           for e in self.store.memory["entities"].values() if e["latest_run_id"] == run_id
                           and e["object_kind"] == "principal" and e["purpose"] == "identity_status")
            e, d = self.store.entities, self.entries
            missing = select(e.c.id).outerjoin(d, and_(e.c.id == d.c.entity_id, e.c.current_record_id == d.c.record_id)).where(
                e.c.latest_run_id == run_id, e.c.object_kind == "principal", e.c.purpose == "identity_status", d.c.entity_id.is_(None)).limit(1)
            return conn.execute(missing).first() is None
