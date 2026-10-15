"""A GitLab connection whose token rotates itself, through the worker's renewal sweep against a synthetic
GitLab: the token's expiry is read once a day, the rotation is marked before it starts, the successor is kept and
every record follows it, and a rotation that stopped half-way or may have happened is never tried again with the
old token (GitLab would revoke the whole token family) until an admin enters a new one."""

import datetime as dt
import json
import uuid

import httpx

from cremore.coverage.store import CoverageStore
from cremore.db.repository import InMemoryRepository
from cremore.onboarding import renewal, service
from cremore.onboarding.onboarding_test import SETTINGS
from cremore.onboarding.store import ProviderConnectionStore
from cremore.secretstore.resolver import SecretResolver

RESOLVER = SecretResolver(sealing_key=SETTINGS.sealing_keys)
OLD, NEW, THIRD = "glpat-" + "o" * 20, "glpat-" + "n" * 20, "glpat-" + "t" * 20
NOW = dt.datetime(2026, 9, 29, 3, tzinfo=dt.UTC)


def gitlab(calls, tokens, *, rotate_status=200, rotate_path="/api/v4/groups/42/access_tokens/self/rotate"):
    """A GitLab whose live token is ``tokens[0]``; a rotation revokes it and makes the next one live."""
    def handler(request):
        token = request.headers["PRIVATE-TOKEN"]
        calls.append((request.method, request.url.path, token))
        if token != tokens[0]:
            return httpx.Response(401)
        if request.url.path == "/api/v4/personal_access_tokens/self":
            return httpx.Response(200, json={"id": 1, "scopes": ["read_api", "read_repository", "self_rotate"], "active": True,
                                             "expires_at": "2026-10-20", "created_at": "2026-07-22T00:00:00Z"})
        assert request.url.path == rotate_path
        if rotate_status != 200:
            return httpx.Response(rotate_status)
        tokens.pop(0)
        return httpx.Response(200, json={"id": 2, "token": tokens[0], "expires_at": json.loads(request.content)["expires_at"],
                                         "created_at": NOW.isoformat()})
    return lambda: httpx.Client(transport=httpx.MockTransport(handler))


def connected(repo):
    record = service.create(repo, SETTINGS, {"provider": "gitlab", "purposes": ["exposure", "inventory"], "auth_method": "token",
                                             "target": {"scope": "group", "id": "42"}, "credential": {"token": OLD}}, "admin")
    store = ProviderConnectionStore(repo)
    store.update(record["id"], store.get(record["id"])["revision"], "worker", status="CHECKED")
    from cremore.onboarding.fixtures_test import activate_with_access

    view = activate_with_access(repo, SETTINGS, record["id"], {"purposes": {"exposure": {}, "inventory": {}}}, "admin")
    return record, view


def refs(repo, view):
    out = set()
    for row in view["created"]:
        if row["kind"] == "content":
            out.add(repo.get_connection(uuid.UUID(row["id"])).secret_ref)
        else:
            out |= set(CoverageStore(repo).get(uuid.UUID(row["id"]))["spec"]["secret_refs"].values())
    return out


def test_the_token_is_read_then_rotated_and_every_record_follows_it():
    repo = InMemoryRepository()
    record, view = connected(repo)
    tokens, calls = [OLD, NEW], []
    # First the token is asked about itself (nothing rotates): expiry 2026-10-20 of a life from 07-22.
    assert renewal.sweep(repo, SETTINGS, RESOLVER, gitlab(calls, tokens), now=NOW) == 1
    note = ProviderConnectionStore(repo).get(record["id"])["checks"]["renewal"]
    assert note["action"] == "inspect" and note["keep"]["expires_at"] == "2026-10-20" and note["keep"]["self_rotate"]
    assert all(method == "GET" for method, _path, _token in calls)
    # The next hour it is in the last third of its life: it rotates, and the successor is what every record uses.
    renewal.sweep(repo, SETTINGS, RESOLVER, gitlab(calls, tokens), now=NOW + dt.timedelta(hours=1))
    stored = ProviderConnectionStore(repo).get(record["id"])
    assert RESOLVER.resolve(stored["secret_refs"]["credential"])["token"] == NEW
    assert refs(repo, view) == {stored["secret_refs"]["credential"]}
    assert stored["checks"]["renewal"]["state"] == "OK" and stored["checks"]["renewal"]["keep"]["expires_at"] == "2026-12-28"
    assert [call for call in calls if call[0] == "POST"] == [("POST", "/api/v4/groups/42/access_tokens/self/rotate", OLD)]
    assert any(event.event_type == "PROVIDER_CONNECTION_CREDENTIAL_RENEWED" for event in repo.finding_events.values())
    # Nothing is due again soon, and the old token is never used again.
    calls.clear()
    renewal.sweep(repo, SETTINGS, RESOLVER, gitlab(calls, tokens), now=NOW + dt.timedelta(hours=2))
    assert all(token == NEW for _method, _path, token in calls)


def test_multiple_targets_rotate_one_owner_and_preserve_removed_sources():
    from cremore.onboarding import targets
    from cremore.onboarding.fixtures_test import grant_access

    repo = InMemoryRepository()
    record, _view = connected(repo)
    store = ProviderConnectionStore(repo)
    current = store.get(record["id"])
    roots = [{"id": targets.target_id(t), "target": t} for t in (
        {"scope": "group", "id": "42", "base_url": "https://gitlab.com"},
        {"scope": "group", "id": "43", "base_url": "https://gitlab.com"})]
    candidate = {**current, "target": {"version": 2, "roots": roots}}
    # These synthetic checks stand in for the draft's per-target grants.
    candidate = store.update(current["id"], current["revision"], "admin", target=candidate["target"])
    grant_access(repo, candidate["id"], candidate["plans"])
    from cremore.onboarding import catalog, children

    children.reconcile_targets(repo, SETTINGS, candidate, [],
        service._described(catalog.module("gitlab"), candidate, candidate["plans"]), "admin")
    current = store.get(record["id"])
    service.remove_targets(repo, SETTINGS, record["id"], {"expected_revision": current["revision"],
        "target_ids": [roots[1]["id"]]}, "admin")
    disabled = [s.id for s in repo.list_connections() if s.status == "DISABLED"]
    assert disabled
    calls, tokens = [], [OLD, NEW]
    path = "/api/v4/personal_access_tokens/self/rotate"
    fake = gitlab(calls, tokens, rotate_path=path)
    renewal.sweep(repo, SETTINGS, RESOLVER, fake, now=NOW)
    renewal.sweep(repo, SETTINGS, RESOLVER, fake, now=NOW + dt.timedelta(hours=1))
    owner_ref = store.get(record["id"])["secret_refs"]["credential"]
    assert RESOLVER.resolve(owner_ref)["token"] == NEW
    assert [call for call in calls if call[0] == "POST"] == [("POST", path, OLD)]
    assert all(s.secret_ref == owner_ref for s in repo.list_connections())
    assert all(repo.get_connection(sid).status == "DISABLED" for sid in disabled)
    assert all(set(CoverageStore(repo).get(uuid.UUID(link["child_id"]))["spec"]["secret_refs"].values()) == {owner_ref}
        for link in store.children(record["id"]) if link["kind"] == "metadata")


def test_a_rotation_that_stopped_half_way_waits_for_a_new_token():
    repo = InMemoryRepository()
    record, _view = connected(repo)
    store = ProviderConnectionStore(repo)
    current = store.get(record["id"])
    # The worker stopped after marking the rotation: GitLab may have revoked the stored token already.
    store.update(current["id"], current["revision"], "worker", checks={**current["checks"], "renewal": {
        "state": "RUNNING", "action": "renew", "at": NOW.isoformat(),
        "keep": {"expires_at": "2026-10-20", "created_at": "2026-07-22T00:00:00Z", "seen_at": NOW.isoformat()}}})
    calls = []
    renewal.sweep(repo, SETTINGS, RESOLVER, gitlab(calls, [OLD, NEW]), now=NOW + dt.timedelta(minutes=10))
    assert not calls and store.get(record["id"])["checks"]["renewal"]["state"] == "RUNNING"  # still within the hour
    renewal.sweep(repo, SETTINGS, RESOLVER, gitlab(calls, [OLD, NEW]), now=NOW + dt.timedelta(hours=2))
    assert store.get(record["id"])["checks"]["renewal"]["code"] == "RENEWAL_INTERRUPTED" and not calls
    for hours in (3, 30):
        renewal.sweep(repo, SETTINGS, RESOLVER, gitlab(calls, [OLD, NEW]), now=NOW + dt.timedelta(hours=hours))
    assert not calls  # never again with the old token
    # A new token from an admin starts over.
    renewed = service.set_credential(repo, SETTINGS, record["id"], {"credential": {"token": THIRD}}, "admin")
    assert renewed["checks"]["renewal"] is None
    renewal.sweep(repo, SETTINGS, RESOLVER, gitlab(calls, [THIRD]), now=NOW + dt.timedelta(hours=31))
    assert calls and all(token == THIRD for _method, _path, token in calls)


def test_an_uncertain_rotation_is_not_tried_again():
    repo = InMemoryRepository()
    record, _view = connected(repo)
    calls = []
    renewal.sweep(repo, SETTINGS, RESOLVER, gitlab(calls, [OLD, NEW], rotate_status=502), now=NOW)
    renewal.sweep(repo, SETTINGS, RESOLVER, gitlab(calls, [OLD, NEW], rotate_status=502), now=NOW + dt.timedelta(hours=1))
    note = ProviderConnectionStore(repo).get(record["id"])["checks"]["renewal"]
    assert note["state"] == "FAILED" and note["code"] == "GITLAB_ROTATION_UNCERTAIN"
    calls.clear()
    renewal.sweep(repo, SETTINGS, RESOLVER, gitlab(calls, [OLD, NEW]), now=NOW + dt.timedelta(hours=2))
    assert not calls
