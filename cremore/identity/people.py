"""Searchable, explicitly retained people of the current sign-in IdP.

Accounts are never merged by email. Dispatch resolves the stable person_ref again against current
source authorization, complete fresh inventory and an unambiguous active contact.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid
from datetime import UTC, datetime, timedelta

from cremore.coverage.store import utc
from cremore.db.people_directory_store import DirectoryStore
from cremore.identity.idp import PROFILE_LIMIT

FIELDS = ("name", "email", "department", "title")
MAX_AGE = timedelta(hours=24)
_DIGEST = re.compile(r"[a-f0-9]{64}")


class DirectoryError(ValueError):
    def __init__(self, code, http_status=409):
        super().__init__(code)
        self.code, self.http_status = code, http_status


def _same_target(spec, expected):
    return all(str(spec.get(key) or "") == str(expected.get(key) or "") for key in ("provider", "origin", "tenant")) and {
        (scope["kind"], scope["id"]) for scope in spec.get("scopes") or []} == {
        (scope["kind"], scope["id"]) for scope in expected.get("scopes") or []}


def _authorized(repo, settings, connection, parents):
    """Bind to an active onboarding parent and a root of the current login IdP."""
    from cremore.onboarding import catalog, sign_in, targets
    from cremore.onboarding.store import active_plans

    parent_id = parents.parent_of("metadata", connection["id"])
    parent = parents.get(parent_id) if parent_id else None
    team = getattr(settings, "auth_mode", "local") == "oidc"
    if parent is None:
        return not team, None
    plans = active_plans(parent)
    if parent["status"] != "ACTIVE" or "identity" not in plans:
        return False, parent
    try:
        module = catalog.module(parent["provider"])
        for root in targets.records_of(parent, "identity"):
            if sign_in.problem(settings, parent["provider"], root["target"], ["identity"], repo=repo, excluding=parent["id"]):
                continue
            for child in module.children(root, "identity", plans["identity"]):
                if child.get("kind") == "metadata" and _same_target(connection["spec"], child.get("spec") or {}):
                    return True, parent
    except (KeyError, ValueError, TypeError):
        return False, parent
    return False, parent


def _sources(repo, settings, indexed, now):
    from cremore.coverage.metadata_models import MetadataConnectionSpec
    from cremore.coverage.scheduling import connection_job
    from cremore.identity import leavers
    from cremore.identity.idp import apps_only
    from cremore.onboarding.store import ProviderConnectionStore

    parents, sources, bindings = ProviderConnectionStore(repo), {}, []
    idps, _ = leavers.identity_providers()
    for connection in indexed.store.list_connections():
        spec = connection["spec"]
        if spec.get("schema_version") != 2 or spec.get("provider") not in idps or apps_only(spec) or not connection["enabled"]:
            continue
        authorized, parent = _authorized(repo, settings, connection, parents)
        if not authorized:
            continue
        runs = indexed.store.connection_runs(connection["id"], limit=1)["items"]
        run = runs[0] if runs else None
        status = "READY"
        if not (spec.get("options") or {}).get("keep_profiles"):
            status = "PROFILES_DISABLED"
        elif run is None or run["revision"] != connection["revision"]:
            status = "NOT_SYNCED"
        elif run["status"] == "RUNNING":
            status = "SYNCING"
        elif run["status"] == "PARTIAL":
            status = "PARTIAL"
        elif run["status"] != "COMPLETE" or run["finished_at"] is None:
            status = "UNAVAILABLE"
        elif not leavers._listed_everyone(indexed.store, run):
            status = "PARTIAL"
        elif utc(run["finished_at"]) < now - MAX_AGE or utc(run["started_at"]) > now + timedelta(minutes=5):
            status = "STALE"
        elif not indexed.projection_ready(run["id"]):
            status = "NOT_SYNCED"
        job = connection_job(repo, connection["id"], active=True)
        sources[connection["id"]] = {"connection_id": str(connection["id"]), "provider": spec["provider"],
            "provider_connection_id": str(parent["id"]) if parent else None,
            "schedule_minutes": MetadataConnectionSpec.model_validate(spec).schedule_minutes,
            "collection_status": job.status if job else None,
            "name": spec.get("name"), "origin": spec["origin"], "tenant": spec.get("tenant", ""),
            "status": status, "usable": status == "READY", "reason": None if status == "READY" else status,
            "observed_at": utc(run["finished_at"]).isoformat() if run and run["finished_at"] else None,
            "run_id": str(run["id"]) if run else None}
        bindings.append((str(connection["id"]), connection["revision"], str(run["id"]) if run else None,
                         run["status"] if run else None, parent["revision"] if parent else None, status))
    issuer = getattr(settings, "oidc_issuer_url", "") if getattr(settings, "auth_mode", "local") == "oidc" else "local"
    snapshot = hashlib.sha256(json.dumps([issuer, sorted(bindings)], separators=(",", ":")).encode()).hexdigest()
    return sources, snapshot


def _directory(sources):
    shown = list(sources.values())
    status = next((status for status in ("READY", "SYNCING", "PARTIAL", "STALE", "UNAVAILABLE", "NOT_SYNCED", "PROFILES_DISABLED")
                   if any(source["status"] == status for source in shown)), "NOT_CONFIGURED")
    return {"status": status, "usable": status == "READY", "reason": None if status == "READY" else status,
            "observed_at": max((source["observed_at"] for source in shown if source["observed_at"]), default=None), "sources": shown}


def _reason(row, sources, now):
    source = sources[row["connection_id"]]
    if not source["usable"]:
        return source["status"]
    if str(row["run_id"]) != source["run_id"]:
        return "STALE"
    if (row["provider"], row["origin"], row["tenant"]) != (source["provider"], source["origin"], source["tenant"]):
        return "UNAVAILABLE"
    if utc(row["observed_at"]) < now - MAX_AGE or utc(row["observed_at"]) > now + timedelta(minutes=5):
        return "STALE"
    if row["state"] != "ACTIVE":
        return "INACTIVE"
    from cremore.governance.contact import ContactError, address

    try:
        address(row["email"])
    except ContactError:
        return "NO_CONTACT"
    return None


def _departed(indexed, rows, sources):
    """Refs of rows an older run made that the departed-owner check calls DEPARTED: a person gone from a complete
    listing (deleted without a disable first) is never projected again, so the row alone still says ACTIVE."""
    older = [row["person_ref"] for row in rows if str(row["run_id"]) != sources[row["connection_id"]]["run_id"]]
    return {ref for ref, state in indexed.leavers.states(older).items() if state == "DEPARTED"}


def _public(row, sources, now, *, reason=None, departed=frozenset()):
    reason = reason or _reason(row, sources, now)
    ref = str(row["person_ref"])
    state = "DEPARTED" if row["person_ref"] in departed else row["state"]
    return {"id": ref, "person_ref": ref, **{field: row[field] for field in FIELDS}, "state": state,
            "sources": [{"provider": row["provider"], "connection_id": str(row["connection_id"]), "state": state}],
            "refs": [ref], "selectable": reason is None, "reason": reason,
            "observed_at": utc(row["observed_at"]).isoformat()}


def _duplicate(indexed, row, sources, now):
    return row["email_key"] in indexed.duplicate_emails([row["email_key"]], sources,
        after=now - MAX_AGE, before=now + timedelta(minutes=5))


def directory(repo, settings=None, *, query="", cursor="", limit=200, now=None):
    """DB-filtered profiles with snapshot-bound keyset pagination, never a fixed first-500 list."""
    now = now or datetime.now(UTC)
    query = " ".join(query.split()).casefold()
    if not 1 <= limit <= 500 or len(query) > 200:
        raise DirectoryError("DIRECTORY_QUERY_INVALID", 422)
    indexed = DirectoryStore(repo)
    sources, snapshot = _sources(repo, settings, indexed, now)
    allowed = {cid: source for cid, source in sources.items() if source["status"] != "PROFILES_DISABLED"}
    after = None
    if cursor:
        try:
            if not isinstance(cursor, str) or len(cursor) > 8192:
                raise ValueError
            payload = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
            if payload["snapshot"] != snapshot or payload["query"] != query or payload["version"] != 1:
                raise ValueError
            name, eid = payload["after"]
            if not isinstance(name, str) or len(name) > PROFILE_LIMIT * 3:
                raise ValueError
            after = (name, str(uuid.UUID(eid)))
        except (ValueError, KeyError, TypeError):
            raise DirectoryError("DIRECTORY_CURSOR_EXPIRED") from None
    rows, total = indexed.page(allowed, query=query, after=after, limit=limit + 1)
    more, rows = len(rows) > limit, rows[:limit]
    duplicates = indexed.duplicate_emails([row["email_key"] for row in rows], sources,
        after=now - MAX_AGE, before=now + timedelta(minutes=5))
    departed = _departed(indexed, rows, sources)
    items = [_public(row, sources, now, reason="AMBIGUOUS_EMAIL" if _reason(row, sources, now) is None
                     and row["email_key"] in duplicates else None, departed=departed) for row in rows]
    next_cursor = None
    if more:
        last = rows[-1]
        payload = {"version": 1, "snapshot": snapshot, "query": query, "after": [last["sort_key"], str(last["entity_id"])]}
        next_cursor = base64.urlsafe_b64encode(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()).decode().rstrip("=")
    return {"items": items, "total": total, "next_cursor": next_cursor, "directory": _directory(sources)}


def _resolve(indexed, sources, ref, now):
    rows = indexed.find(sources, person_ref=ref, limit=501)
    eligible = [row for row in rows if _reason(row, sources, now) is None]
    if not eligible:
        raise DirectoryError("PERSON_" + (_reason(rows[0], sources, now) if rows else "NOT_AVAILABLE"))
    if len(rows) > 500 or len({row["email_key"] for row in eligible}) != 1:
        raise DirectoryError("PERSON_AMBIGUOUS_EMAIL")
    row = max(eligible, key=lambda row: (utc(row["observed_at"]), str(row["entity_id"])))
    if _duplicate(indexed, row, sources, now):
        raise DirectoryError("PERSON_AMBIGUOUS_EMAIL")
    keys = indexed.keys_for([row["entity_id"]])[row["entity_id"]]
    return {**_public(row, sources, now), "provider": row["provider"], "origin": row["origin"], "tenant": row["tenant"],
            "idp_user_id": row["idp_user_id"], "connection_id": str(row["connection_id"]), "entity_id": str(row["entity_id"]),
            "key_id": row["key_id"], "keys": [{"kind": key["kind"], "digest": key["digest"]} for key in keys]}


def resolve_person(repo, settings, person_ref, *, now=None):
    now = now or datetime.now(UTC)
    try:
        ref = uuid.UUID(str(person_ref))
    except ValueError:
        raise DirectoryError("PERSON_REFERENCE_INVALID", 422) from None
    indexed = DirectoryStore(repo)
    sources, snapshot = _sources(repo, settings, indexed, now)
    result = _resolve(indexed, sources, ref, now)
    if _sources(repo, settings, indexed, now)[1] != snapshot:
        raise DirectoryError("PERSON_DIRECTORY_CHANGED")
    return result


def eligible_people_for_digests(repo, settings, digests, key_id=None, *, now=None):
    """Internal suggestions only: identity digests never enter the public directory response."""
    digests = list(dict.fromkeys(digests))
    if not digests:
        return []
    if len(digests) > 100 or any(not isinstance(value, str) or not _DIGEST.fullmatch(value) for value in digests):
        raise DirectoryError("DIRECTORY_DIGEST_QUERY_INVALID", 422)
    if key_id is None:
        from cremore.identity.keys import Digester

        key = getattr(settings, "fingerprint_key_bytes", None)
        if not key:
            return []
        key_id = Digester(key).key_id
    now = now or datetime.now(UTC)
    indexed = DirectoryStore(repo)
    sources, snapshot = _sources(repo, settings, indexed, now)
    rows = indexed.find(sources, digests=digests, key_id=key_id, limit=501)
    if len(rows) > 500:
        raise DirectoryError("DIRECTORY_MATCH_LIMIT")
    # A shared identity value is ambiguous even when only one matching account is
    # currently dispatchable. Filtering inactive accounts first would turn an
    # ownership conflict into a false exact match.
    matches = {}
    keyed = indexed.keys_for([row["entity_id"] for row in rows])
    for row in rows:
        for key in keyed[row["entity_id"]]:
            if key["key_id"] == key_id and key["digest"] in digests:
                matches.setdefault(key["digest"], set()).add(row["person_ref"])
    if any(len(refs) > 1 for refs in matches.values()):
        raise DirectoryError("DIRECTORY_IDENTITY_AMBIGUOUS")
    found = []
    for ref in sorted({row["person_ref"] for row in rows}, key=str):
        try:
            found.append(_resolve(indexed, sources, ref, now))
        except DirectoryError:
            continue
    if _sources(repo, settings, indexed, now)[1] != snapshot:
        raise DirectoryError("PERSON_DIRECTORY_CHANGED")
    return found


def profiles_for(repo, settings, refs, *, now=None):
    """Batched display profiles for explicit assigned references; inactivity is displayed, not hidden."""
    wanted = set()
    for value in refs:
        try:
            wanted.add(uuid.UUID(str(value)))
        except ValueError:
            continue
    now = now or datetime.now(UTC)
    indexed = DirectoryStore(repo)
    sources, _ = _sources(repo, settings, indexed, now)
    allowed = {cid: source for cid, source in sources.items() if source["status"] != "PROFILES_DISABLED"}
    ordered, result = sorted(wanted, key=str), {}
    for start in range(0, len(ordered), 500):
        rows = indexed.find(allowed, person_refs=ordered[start:start + 500], limit=5001)
        departed = _departed(indexed, rows, sources)
        for row in sorted(rows, key=lambda item: utc(item["observed_at"])):
            source = sources[row["connection_id"]]
            if (row["provider"], row["origin"], row["tenant"]) == (source["provider"], source["origin"], source["tenant"]):
                result[str(row["person_ref"])] = _public(row, sources, now, departed=departed)
    return result


def main():
    """Explicit backfill of saved opt-in profiles, never provider requests."""
    import argparse
    import os

    from cremore.db.sql import SqlRepository, create_all, make_engine

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rebuild", required=True, action="store_true")
    parser.parse_args()
    url = os.environ.get("DATABASE_URL")
    if not url:
        parser.error("DATABASE_URL is required")
    engine = make_engine(url)
    try:
        create_all(engine)
        count = DirectoryStore(SqlRepository(engine)).rebuild()
        print(json.dumps({"profiles_examined": count}))
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
