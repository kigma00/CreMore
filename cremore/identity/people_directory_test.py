"""Tenant-bound, server-paged responder lookup using synthetic IdP records only."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cremore_okta_provider import adapter
from cremore_okta_provider.tests import test_identity as okta
from fastapi.testclient import TestClient
from sqlalchemy import delete, event, select

from cremore.api import create_app
from cremore.config import Settings
from cremore.coverage import METADATA_JOB_KIND
from cremore.coverage.metadata_models import MetadataBatch, MetadataFinish, metadata_contract
from cremore.coverage.metadata_store import MetadataStore
from cremore.db.people_directory_store import DirectoryStore
from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414 -- disposable localhost database
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import ScanJob
from cremore.identity import idp, leavers, people
from cremore.onboarding.store import ProviderConnectionStore

LOCAL = Settings(AUTH_MODE="local", API_TOKEN="t" * 40, FINGERPRINT_KEY=(b"k" * 32).hex())
TEAM = Settings(AUTH_MODE="oidc", OIDC_ISSUER_URL="https://acme.okta.com", OIDC_CLIENT_ID="cremore",
                FINGERPRINT_KEY=(b"k" * 32).hex())


@pytest.fixture(params=["memory", "sqlite", "postgres"])
def repo(request):
    if request.param == "memory":
        yield InMemoryRepository()
    elif request.param == "postgres":
        yield request.getfixturevalue("pg")[1]
    else:
        engine = make_engine("sqlite:///:memory:")
        create_all(engine)
        try:
            yield SqlRepository(engine)
        finally:
            engine.dispose()


def records(spec, count=1, *, state="ACTIVE", email=None, stamp=None):
    stamp = (stamp or datetime.now(UTC)).isoformat()
    result = []
    for index in range(count):
        mail = email if email is not None else f"person{index:05d}@acme.test"
        result.append(adapter._collector.user_record(spec, spec.scopes[0], "users",
            idp.User(id=f"00uperson{index:05d}", raw_state=state, state=state,
                keys=(("EMAIL", mail),), profile=(("display_name", f"Person {index:05d}"), ("email", mail),
                                                  ("department", "Platform"), ("title", "Engineer"))), stamp, okta.DIGEST))
    result.append(adapter._collector.report(spec.scopes[0], "users", stamp, "COMPLETE", complete=True))
    return result


def save(store, spec, items, *, owner=None, status="COMPLETE"):
    if owner is None:
        owner, _ = store.create(spec, "synthetic")
    run = store.start(owner["id"], owner["revision"], str(uuid.uuid4()), metadata_contract(spec).model_dump())
    batches = [items[start:start + 250] for start in range(0, len(items), 250)]
    for index, batch in enumerate(batches):
        store.append(owner["id"], run["id"], MetadataBatch(index=index, items=batch), trusted_discovery=True)
    store.finish(owner["id"], run["id"], MetadataFinish(batch_count=len(batches), item_count=len(items), status=status))
    return owner


def setup(repo, *, count=1, host="acme.okta.com", bind=True, profiles=True, status="COMPLETE", state="ACTIVE", email=None, stamp=None):
    spec = okta.spec(origin="https://" + host, tenant=host, scopes=[{"kind": "organization", "id": host}],
                     options={"keep_profiles": profiles})
    store = MetadataStore(repo)
    owner = save(store, spec, records(spec, count, state=state, email=email, stamp=stamp), status=status)
    parent = None
    if bind:
        parents = ProviderConnectionStore(repo)
        parent = parents.create({"provider": "okta", "edition": "cloud", "name": host, "target": {"organization": host},
            "auth_method": "private_key_jwt", "secret_refs": {}, "purposes": ["identity"], "plans": {
                "identity": {"people_details": profiles}}, "status": "ACTIVE"}, "admin")
        parents.link(parent["id"], "identity", "metadata", owner["id"])
    return store, spec, owner, parent


def mutate(store, name, row_id, **changes):
    with store.transaction() as conn:
        row = store._get(conn, name, row_id)
        row.update(changes)
        store._put(conn, name, row)


def test_search_and_keyset_pages_reach_people_beyond_500_without_full_inventory(repo, monkeypatch):
    setup(repo, count=605)
    monkeypatch.setattr(MetadataStore, "inventory", lambda *a, **k: pytest.fail("full inventory read"))
    monkeypatch.setattr(leavers.LeaverStore, "people", lambda *a, **k: pytest.fail("full people read"))
    queries = []
    if getattr(repo, "engine", None) is not None:
        def seen(_conn, _cursor, statement, _parameters, _context, _many):
            queries.append(statement)
        event.listen(repo.engine, "before_cursor_execute", seen)
    try:
        found, cursor = [], ""
        while True:
            page = people.directory(repo, TEAM, limit=200, cursor=cursor)
            found.extend(page["items"])
            cursor = page["next_cursor"]
            if cursor is None:
                break
        assert len(found) == len({row["person_ref"] for row in found}) == 605
        assert all(row["selectable"] for row in found)
        last = people.directory(repo, TEAM, query="person00604", limit=25)
        assert last["total"] == 1 and last["items"][0]["email"] == "person00604@acme.test"
        assert people.resolve_person(repo, TEAM, last["items"][0]["person_ref"])["email"] == "person00604@acme.test"
        assert people.directory(repo, TEAM, query="%_")["total"] == 0  # literal search, no wildcard expansion
        if queries:
            assert any("identity_directory_entries.search_key LIKE" in query and "LIMIT" in query for query in queries)
    finally:
        if queries:
            event.remove(repo.engine, "before_cursor_execute", seen)


def test_team_directory_excludes_other_tenants_orphans_and_old_login_provider(repo):
    setup(repo)
    setup(repo, host="other.okta.com")
    setup(repo, host="orphan.okta.com", bind=False)
    page = people.directory(repo, TEAM)
    assert page["total"] == 1 and page["directory"]["status"] == "READY"
    ref = page["items"][0]["person_ref"]
    changed = TEAM.model_copy(update={"oidc_issuer_url": "https://new.okta.com"})
    assert people.directory(repo, changed)["directory"]["status"] == "NOT_CONFIGURED"
    with pytest.raises(people.DirectoryError, match="PERSON_NOT_AVAILABLE"):
        people.resolve_person(repo, changed, ref)
    assert people.directory(repo, TEAM)["items"][0]["refs"] == [ref]


@pytest.mark.parametrize("job_status", [None, "QUEUED", "RUNNING", "CANCELLING", "SUCCEEDED"])
def test_directory_source_exposes_its_schedule_parent_and_active_collection(repo, job_status):
    store, spec, owner, parent = setup(repo)
    mutate(store, "connections", owner["id"], spec=spec.model_copy(update={"schedule_minutes": 5}).model_dump())
    if job_status is not None:
        job = repo.enqueue_job(ScanJob(kind=METADATA_JOB_KIND,
            payload={"provider": "okta", "coverage_connection_id": str(owner["id"]), "coverage_revision": owner["revision"]}))
        if job_status != "QUEUED":
            assert repo.claim_next_job().id == job.id
        if job_status == "CANCELLING":
            repo.request_job_cancel(job.id)
        elif job_status == "SUCCEEDED":
            repo.complete_job(job.id, objects=0, findings=0)
    page = people.directory(repo, TEAM)
    [source] = page["directory"]["sources"]
    assert source["connection_id"] == str(owner["id"])
    assert source["provider_connection_id"] == str(parent["id"])
    assert source["schedule_minutes"] == 5
    assert source["collection_status"] == (job_status if job_status in {"QUEUED", "RUNNING", "CANCELLING"} else None)
    # Job acceptance does not change the evidence from the latest finished run.
    assert source["status"] == "READY" and source["observed_at"] and page["items"][0]["selectable"]
    assert "secret_refs" not in source and "payload" not in source
    ProviderConnectionStore(repo).update(parent["id"], parent["revision"], "admin", disabled_purposes=["identity"])
    assert people.directory(repo, TEAM)["directory"]["sources"] == []


def test_local_directory_without_parent_keeps_manual_collection_reference(repo):
    _, _, owner, _ = setup(repo, bind=False)
    [source] = people.directory(repo, LOCAL)["directory"]["sources"]
    assert source["connection_id"] == str(owner["id"])
    assert source["provider_connection_id"] is None and source["collection_status"] is None
    assert source["schedule_minutes"] == 0


@pytest.mark.parametrize("change,reason", [("partial", "PARTIAL"), ("stale", "STALE"), ("inactive", "INACTIVE"),
    ("email", "NO_CONTACT"), ("disabled", "NOT_AVAILABLE"), ("paused", "NOT_AVAILABLE"),
    ("profiles", "PROFILES_DISABLED"), ("auth", "NOT_SYNCED")])
def test_dispatch_revalidates_current_profile_and_source(repo, change, reason):
    store, _, owner, parent = setup(repo, status="PARTIAL" if change == "partial" else "COMPLETE",
        state="DISABLED" if change == "inactive" else "ACTIVE", email="invalid-contact" if change == "email" else None,
        stamp=datetime.now(UTC) - timedelta(days=2) if change == "stale" else None)
    ref = str(leavers.person_ref("okta", "https://acme.okta.com", "acme.okta.com", "00uperson00000"))
    if change == "disabled":
        mutate(store, "connections", owner["id"], enabled=False)
    elif change == "paused":
        ProviderConnectionStore(repo).update(parent["id"], parent["revision"], "admin", disabled_purposes=["identity"])
    elif change == "profiles":
        mutate(store, "connections", owner["id"], spec={**owner["spec"], "options": {**owner["spec"]["options"], "keep_profiles": False}})
    elif change == "auth":
        mutate(store, "connections", owner["id"], revision=owner["revision"] + 1)
    with pytest.raises(people.DirectoryError, match="PERSON_" + reason):
        people.resolve_person(repo, TEAM, ref)
    if change in {"stale", "inactive", "email", "partial", "auth"}:
        item = people.directory(repo, TEAM)["items"][0]
        assert not item["selectable"] and item["reason"] == reason


def test_ambiguous_mailboxes_stay_separate_and_are_not_dispatchable(repo):
    setup(repo, count=2, email="shared@acme.test")
    rows = people.directory(repo, TEAM)["items"]
    assert len(rows) == 2 and len({row["person_ref"] for row in rows}) == 2
    assert {row["reason"] for row in rows} == {"AMBIGUOUS_EMAIL"}
    with pytest.raises(people.DirectoryError, match="PERSON_AMBIGUOUS_EMAIL"):
        people.resolve_person(repo, TEAM, rows[0]["person_ref"])
    with pytest.raises(people.DirectoryError, match="DIRECTORY_IDENTITY_AMBIGUOUS"):
        people.eligible_people_for_digests(repo, TEAM, [okta.DIGEST("shared@acme.test")], okta.DIGEST.key_id)


def test_cursor_is_bound_to_query_tenant_and_collection_snapshot(repo):
    store, spec, owner, _ = setup(repo, count=3)
    cursor = people.directory(repo, TEAM, limit=1)["next_cursor"]
    with pytest.raises(people.DirectoryError, match="DIRECTORY_CURSOR_EXPIRED"):
        people.directory(repo, TEAM, cursor=cursor, query="different")
    for bad in ("garbage", "W10", "e30", "x" * 3000):
        with pytest.raises(people.DirectoryError, match="DIRECTORY_CURSOR_EXPIRED"):
            people.directory(repo, TEAM, cursor=bad)
    save(store, spec, records(spec, count=3), owner=owner)
    with pytest.raises(people.DirectoryError, match="DIRECTORY_CURSOR_EXPIRED"):
        people.directory(repo, TEAM, cursor=cursor)


@pytest.mark.parametrize("name,query", [("한" * idp.PROFILE_LIMIT, ""), ("ß" * idp.PROFILE_LIMIT, ""),
                                     ("🦄" * idp.PROFILE_LIMIT, "🦄" * 200)])
def test_directory_cursor_accepts_maximum_unicode_profile_names(repo, name, query):
    store, spec, owner, _ = setup(repo)
    rows = records(spec, count=2)
    for index, row in enumerate(rows[:-1]):
        rows[index] = row.model_copy(update={"facts": idp.profile_facts((
            ("display_name", name), ("email", f"person{index}@acme.test")))})
    save(store, spec, rows, owner=owner)
    first = people.directory(repo, TEAM, limit=1, query=query)
    second = people.directory(repo, TEAM, limit=1, query=query, cursor=first["next_cursor"])
    assert first["items"][0]["id"] != second["items"][0]["id"] and second["next_cursor"] is None


def test_projection_is_explicitly_rebuilt_from_saved_profiles_and_matching_is_keyed(repo):
    _, _, _, _ = setup(repo)
    indexed = DirectoryStore(repo)
    with indexed.store.transaction() as conn:
        if conn is None:
            indexed.store.memory["directory_entries"].clear()
            indexed.store.memory["directory_keys"].clear()
        else:
            conn.execute(delete(indexed.keys))
            conn.execute(delete(indexed.entries))
    before = people.directory(repo, TEAM)
    assert before["directory"]["status"] == "NOT_SYNCED" and before["total"] == 0
    assert indexed.rebuild(batch_size=1) == 1
    profile = people.directory(repo, TEAM)["items"][0]
    assert profile["selectable"] and "keys" not in profile and "digest" not in str(profile)
    matches = people.eligible_people_for_digests(repo, TEAM, [okta.DIGEST("person00000@acme.test")], okta.DIGEST.key_id)
    assert [row["person_ref"] for row in matches] == [profile["person_ref"]]
    assert matches[0]["keys"] and matches[0]["provider"] == "okta"
    assert people.eligible_people_for_digests(repo, TEAM, [okta.DIGEST("person00000@acme.test")], "0" * 64) == []
    assert people.profiles_for(repo, TEAM, [profile["person_ref"], str(uuid.uuid4())]) == {profile["person_ref"]: profile}
    with pytest.raises(people.DirectoryError, match="PERSON_NOT_AVAILABLE"):
        people.resolve_person(repo, TEAM, uuid.uuid4())
    with pytest.raises(people.DirectoryError, match="PERSON_REFERENCE_INVALID"):
        people.resolve_person(repo, TEAM, "not-a-reference")


def test_people_api_keeps_legacy_fields_and_rejects_invalid_cursor(repo):
    setup(repo, count=2)
    client = TestClient(create_app(repo=repo, settings=LOCAL))
    headers = {"Authorization": "Bearer " + "t" * 40}
    first = client.get("/api/v1/people?limit=1", headers=headers)
    assert first.status_code == 200
    body = first.json()
    assert body["total"] == 2 and body["items"][0]["id"] == body["items"][0]["person_ref"]
    second = client.get("/api/v1/people", params={"limit": 1, "cursor": body["next_cursor"]}, headers=headers)
    assert second.status_code == 200 and second.json()["items"][0]["id"] != body["items"][0]["id"]
    assert client.get("/api/v1/people?cursor=bad", headers=headers).status_code == 409


def test_retargeted_connection_never_exposes_previous_tenant_profiles(repo):
    store, _, owner, parent = setup(repo)
    old_ref = people.directory(repo, TEAM)["items"][0]["person_ref"]
    new_host = "new.okta.com"
    spec = {**owner["spec"], "origin": "https://" + new_host, "tenant": new_host,
            "scopes": [{"kind": "organization", "id": new_host}]}
    mutate(store, "connections", owner["id"], spec=spec, revision=owner["revision"] + 1)
    ProviderConnectionStore(repo).update(parent["id"], parent["revision"], "admin", target={"organization": new_host})
    new_login = TEAM.model_copy(update={"oidc_issuer_url": "https://" + new_host})
    found = people.directory(repo, new_login)
    assert found["total"] == 0 and found["items"] == []
    assert people.profiles_for(repo, new_login, [old_ref]) == {}
    with pytest.raises(people.DirectoryError, match="PERSON_NOT_AVAILABLE"):
        people.resolve_person(repo, new_login, old_ref)


def test_pausing_directory_during_reference_resolution_is_not_accepted(repo, monkeypatch):
    _, _, _, parent = setup(repo)
    ref = people.directory(repo, TEAM)["items"][0]["person_ref"]
    original = DirectoryStore.keys_for
    def pause(indexed, entity_ids):
        result = original(indexed, entity_ids)
        ProviderConnectionStore(repo).update(parent["id"], parent["revision"], "admin", disabled_purposes=["identity"])
        return result
    monkeypatch.setattr(DirectoryStore, "keys_for", pause)
    with pytest.raises(people.DirectoryError, match="PERSON_DIRECTORY_CHANGED"):
        people.resolve_person(repo, TEAM, ref)


@pytest.mark.parametrize("latest", ["RUNNING", "FAILED"])
def test_new_running_or_failed_sync_never_promotes_previous_complete_profile(repo, latest):
    store, spec, owner, _ = setup(repo)
    ref = people.directory(repo, TEAM)["items"][0]["person_ref"]
    run = store.start(owner["id"], owner["revision"], str(uuid.uuid4()), metadata_contract(spec).model_dump())
    if latest == "FAILED":
        store.finish(owner["id"], run["id"], MetadataFinish(batch_count=0, item_count=0, status="FAILED"))
    state = "SYNCING" if latest == "RUNNING" else "UNAVAILABLE"
    assert people.directory(repo, TEAM)["directory"]["status"] == state
    with pytest.raises(people.DirectoryError, match="PERSON_" + state):
        people.resolve_person(repo, TEAM, ref)


def test_purged_identities_do_not_reappear_from_retained_profile_projection(repo):
    setup(repo)
    ref = uuid.UUID(people.directory(repo, TEAM)["items"][0]["person_ref"])
    leavers.evaluate(repo, LOCAL, report_rows=[])
    state = leavers.LeaverStore(repo)
    before = state.people()[ref]
    state.save(people=[{**before, "state": "PURGED", "purged_at": datetime.now(UTC)}])
    assert people.directory(repo, TEAM)["total"] == 0
    assert people.profiles_for(repo, TEAM, [ref]) == {}
    with pytest.raises(people.DirectoryError, match="PERSON_NOT_AVAILABLE"):
        people.resolve_person(repo, TEAM, ref)


def test_a_person_gone_from_a_complete_listing_is_shown_departed(repo):
    store, spec, owner, _ = setup(repo, count=2)
    save(store, spec, records(spec, 1), owner=owner)  # person00001 was deleted without being disabled first
    leavers.evaluate(repo, LOCAL, report_rows=[])
    page = people.directory(repo, TEAM)["items"]
    assert {row["email"]: (row["state"], row["sources"][0]["state"], row["selectable"]) for row in page} == {
        "person00000@acme.test": ("ACTIVE", "ACTIVE", True), "person00001@acme.test": ("DEPARTED", "DEPARTED", False)}
    gone = next(row["person_ref"] for row in page if row["email"] == "person00001@acme.test")
    assert people.profiles_for(repo, TEAM, [gone])[gone]["state"] == "DEPARTED"


@pytest.mark.parametrize("second_state", ["ACTIVE", "DISABLED"])
def test_same_identity_digest_is_ambiguous_before_inactive_accounts_are_filtered(repo, second_state):
    store, spec, owner, _ = setup(repo)
    stamp = datetime.now(UTC).isoformat()
    rows = [adapter._collector.user_record(spec, spec.scopes[0], "users",
        idp.User(id=f"00ualiasperson{index}", raw_state=state, state=state,
            keys=(("EMAIL", f"person{index}@acme.test"), ("LOGIN", "shared-login")),
            profile=(("display_name", f"Person {index}"), ("email", f"person{index}@acme.test"))),
        stamp, okta.DIGEST) for index, state in enumerate(("ACTIVE", second_state))]
    rows.append(adapter._collector.report(spec.scopes[0], "users", stamp, "COMPLETE", complete=True))
    save(store, spec, rows, owner=owner)
    with pytest.raises(people.DirectoryError, match="DIRECTORY_IDENTITY_AMBIGUOUS"):
        people.eligible_people_for_digests(repo, TEAM, [okta.DIGEST("shared-login")])
    # Explicitly selecting the current active account still uses its own unique contact.
    active = people.directory(repo, TEAM, query="person0@")["items"][0]
    assert people.resolve_person(repo, TEAM, active["person_ref"])["email"] == "person0@acme.test"


def test_pruning_source_records_removes_projected_profile_even_if_older_entity_is_retained(repo):
    store, spec, owner, _ = setup(repo)
    first = store.connection_runs(owner["id"])["items"][0]["id"]
    save(store, spec, records(spec, email="current@acme.test"), owner=owner)
    assert people.directory(repo, TEAM)["items"][0]["email"] == "current@acme.test"
    assert store.prune_runs(owner["id"], before=datetime.now(UTC) + timedelta(seconds=1), keep=[first]) == 1
    indexed = DirectoryStore(repo)
    with store.transaction() as conn:
        if conn is None:
            assert len(store.memory["entities"]) == 1
            assert store.memory["directory_entries"] == {} and store.memory["directory_keys"] == {}
        else:
            assert conn.execute(select(store.entities.c.id)).first() is not None
            assert conn.execute(select(indexed.entries.c.entity_id)).first() is None
            assert conn.execute(select(indexed.keys.c.entity_id)).first() is None
