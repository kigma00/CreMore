"""Console roles for Google sign-in from Workspace groups: what the API asks for, what the worker keeps, what a
sign-in gets. A synthetic Workspace and a synthetic issuer only."""

import datetime as _dt
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.conftest import AUDIENCE, FakeIssuer, FakeResp, oidc_settings
from cremore.config import Settings
from cremore.db.repository import InMemoryRepository
from cremore.identity import sign_in_groups
from cremore.identity.idp import ReadError
from cremore.identity.keys import Digester
from cremore.onboarding import catalog
from cremore.onboarding.store import ProviderConnectionStore

GOOGLE = "https://accounts.google.com"
KEY = "ab" * 32
ADMINS, VIEWERS = "cremore-admins@acme.com", "cremore-viewers@acme.com"
NOW = _dt.datetime(2026, 10, 2, 9, 0, tzinfo=_dt.UTC)
DIGEST = Digester(bytes.fromhex(KEY))


def google_settings(**overrides):
    return oidc_settings(**{"FINGERPRINT_KEY": KEY, "OIDC_ISSUER_URL": GOOGLE, "OIDC_ADMIN_GROUP": " Cremore-Admins@acme.com",
                            "OIDC_VIEWER_GROUP": VIEWERS, "OIDC_ANALYST_GROUP": " ", "OIDC_REMEDIATOR_GROUP": "",
                            **overrides})


class Resolver:
    def __init__(self, fail=False):
        self.fail = fail

    def resolve(self, ref):
        if self.fail:
            raise RuntimeError("synthetic-secret-in-error")
        return {"private_key": "synthetic", "username": "admin@" + ref.rpartition(":")[2]}


def directory(repo, domain="acme.com", *, status="ACTIVE"):
    """A Google Workspace people connection, as the wizard leaves it once collecting."""
    store = ProviderConnectionStore(repo)
    record = store.create({"provider": "google_workspace", "edition": "cloud", "name": f"Google Workspace · {domain}",
                           "target": {"domain": domain}, "auth_method": "service_account_delegation",
                           "secret_refs": {"credential": "sealed:" + domain}, "purposes": ["identity"]}, "admin")
    return store.update(record["id"], record["revision"], "worker", status=status, plans={"identity": {}})


@pytest.fixture
def members(monkeypatch):
    """What the Workspace module answers for each group (or the error it raises), and what it was asked."""
    asked, state = [], {"error": {}}
    answers = {ADMINS: ["dana@acme.com"], VIEWERS: ["dana@acme.com", "Eve@Acme.com", "ｍａｌｌｏｒｙ@acme.com"]}

    def read(connection, secrets, client, groups):
        asked.append((connection["target"]["domain"], secrets["credential"]["username"], list(groups)))
        [group] = groups  # one group a call
        if group in state["error"]:
            raise ReadError(state["error"][group])
        return {group: list(answers[group])}

    monkeypatch.setattr(catalog.module("google_workspace"), "role_group_members", read)
    return asked, state, answers


def sweep(repo, settings, at, resolver=None):
    return sign_in_groups.sweep(repo, settings, resolver or Resolver(), lambda: None, now=at)


def stored(repo):
    return repo.get_setting(sign_in_groups.KEY)["value"]


def test_the_api_asks_for_the_role_groups_only_when_people_sign_in_with_google():
    repo = InMemoryRepository()
    sign_in_groups.publish_wanted(repo, Settings(FINGERPRINT_KEY=KEY))
    sign_in_groups.publish_wanted(repo, oidc_settings(FINGERPRINT_KEY=KEY))
    assert repo.get_setting(sign_in_groups.WANTED) is None  # an IdP whose tokens carry the groups needs nothing
    sign_in_groups.publish_wanted(repo, google_settings())
    # Trimmed, lower case; a blank or non-address value is no group at all.
    assert repo.get_setting(sign_in_groups.WANTED)["value"] == {"groups": [ADMINS, VIEWERS]}
    sign_in_groups.publish_wanted(repo, oidc_settings(FINGERPRINT_KEY=KEY))
    assert repo.get_setting(sign_in_groups.WANTED)["value"] == {"groups": []}  # switched away: the worker stops


def test_the_worker_keeps_digests_of_the_members_and_reads_again_after_the_interval(members):
    asked, _state, _answers = members
    repo = InMemoryRepository()
    settings = google_settings()
    assert sweep(repo, settings, NOW) is False  # nothing asked for yet
    sign_in_groups.publish_wanted(repo, settings)
    assert sweep(repo, settings, NOW) is True
    assert stored(repo)["code"] == "GOOGLE_WORKSPACE_PEOPLE_DIRECTORY_REQUIRED"
    directory(repo)
    later = NOW + sign_in_groups.INTERVAL
    assert sweep(repo, settings, later) is True
    kept = stored(repo)
    # The fullwidth address is no Workspace address: nothing folds it into another person's.
    assert kept["groups"] == {ADMINS: [DIGEST("dana@acme.com")], VIEWERS: sorted([DIGEST("dana@acme.com"), DIGEST("eve@acme.com")])}
    assert (kept["domain"], kept["code"], kept["key_id"]) == ("acme.com", None, DIGEST.key_id)
    assert not any(person in json.dumps(kept).lower() for person in ("dana", "eve@"))  # the groups' addresses only
    assert asked == [("acme.com", "admin@acme.com", [ADMINS]), ("acme.com", "admin@acme.com", [VIEWERS])]
    # Within the interval nothing is asked again; after it, it is.
    assert sweep(repo, settings, later + _dt.timedelta(minutes=1)) is False
    assert sweep(repo, settings, later + sign_in_groups.INTERVAL) is True
    assert len(asked) == 4


def test_a_removed_member_loses_the_role_at_the_next_read_and_one_unreadable_group_holds_no_other(members):
    _asked, state, answers = members
    repo = InMemoryRepository()
    settings = google_settings()
    sign_in_groups.publish_wanted(repo, settings)
    directory(repo)
    sweep(repo, settings, NOW)
    dana = {"email": "dana@acme.com", "email_verified": True, "hd": "acme.com"}
    lookup = sign_in_groups.Lookup(repo, settings, ttl=0, now=lambda: NOW + _dt.timedelta(minutes=10))
    assert lookup(dana) == (ADMINS, VIEWERS)
    answers[ADMINS] = []
    state["error"] = {VIEWERS: "GOOGLE_WORKSPACE_HTTP_404"}
    sweep(repo, settings, NOW + sign_in_groups.INTERVAL)
    assert lookup(dana) == ()  # out of the admins, and the viewers' group grants nothing until it is read
    kept = stored(repo)
    assert kept["codes"] == {VIEWERS: "GOOGLE_WORKSPACE_HTTP_404"} and kept["code"] == "GOOGLE_WORKSPACE_HTTP_404"
    view = sign_in_groups.view(repo, settings)["groups"]
    assert view["viewer"] == {"group": VIEWERS, "members": None, "code": "GOOGLE_WORKSPACE_HTTP_404"}
    assert view["admin"] == {"group": ADMINS, "members": 0, "code": None}


def test_an_outage_keeps_the_last_membership_for_an_hour_a_cause_here_ends_it(members):
    _asked, state, _answers = members
    repo = InMemoryRepository()
    settings = google_settings()
    sign_in_groups.publish_wanted(repo, settings)
    record = directory(repo)
    sweep(repo, settings, NOW)
    first = stored(repo)
    state["error"] = {ADMINS: "GOOGLE_WORKSPACE_UNAVAILABLE", VIEWERS: "GOOGLE_WORKSPACE_UNAVAILABLE"}
    sweep(repo, settings, NOW + sign_in_groups.INTERVAL)
    kept = stored(repo)
    assert kept["code"] == "GOOGLE_WORKSPACE_UNAVAILABLE"
    assert (kept["groups"], kept["read_at"]) == (first["groups"], first["read_at"])
    dana = {"email": "dana@acme.com", "email_verified": True, "hd": "acme.com"}
    assert sign_in_groups.Lookup(repo, settings, now=lambda: NOW + _dt.timedelta(minutes=50))(dana) == (ADMINS, VIEWERS)
    assert sign_in_groups.Lookup(repo, settings, now=lambda: NOW + _dt.timedelta(minutes=61))(dana) == ()
    # A credential this installation cannot open, or no people connection: nothing read before is kept.
    sweep(repo, settings, NOW + 2 * sign_in_groups.INTERVAL, Resolver(fail=True))
    kept = stored(repo)
    assert (kept["code"], kept["groups"], kept["read_at"]) == ("SECRET_UNAVAILABLE", {}, None)
    assert "synthetic-secret" not in json.dumps(kept)
    state["error"] = {}
    sweep(repo, settings, NOW + 3 * sign_in_groups.INTERVAL)
    assert stored(repo)["groups"]
    # So does a delegation the company took back: nothing it allowed before is kept.
    denied = "GOOGLE_WORKSPACE_DELEGATION_NOT_ALLOWED"
    state["error"] = {ADMINS: denied, VIEWERS: denied}
    sweep(repo, settings, NOW + 3 * sign_in_groups.INTERVAL + _dt.timedelta(minutes=5))
    assert (stored(repo)["code"], stored(repo)["groups"]) == (denied, {})
    state["error"] = {}
    sweep(repo, settings, NOW + 3 * sign_in_groups.INTERVAL + _dt.timedelta(minutes=10))
    assert stored(repo)["groups"]
    # And a key or admin Google's token endpoint now refuses (invalid_grant), or an admin no longer allowed to read.
    for step, refused in enumerate(("GOOGLE_WORKSPACE_TOKEN_REFUSED", "GOOGLE_WORKSPACE_ACCESS_DENIED")):
        state["error"] = {ADMINS: refused, VIEWERS: refused}
        sweep(repo, settings, NOW + 3 * sign_in_groups.INTERVAL + _dt.timedelta(minutes=15 + 10 * step))
        assert (stored(repo)["code"], stored(repo)["groups"], stored(repo)["read_at"]) == (refused, {}, None)
        state["error"] = {}
        sweep(repo, settings, NOW + 3 * sign_in_groups.INTERVAL + _dt.timedelta(minutes=20 + 10 * step))
        assert stored(repo)["groups"]
    store = ProviderConnectionStore(repo)
    store.update(record["id"], store.get(record["id"])["revision"], "admin", status="DISABLED")
    sweep(repo, settings, NOW + 10 * sign_in_groups.INTERVAL)
    assert (stored(repo)["code"], stored(repo)["groups"]) == ("GOOGLE_WORKSPACE_PEOPLE_DIRECTORY_REQUIRED", {})


def test_the_oldest_people_connection_is_read_and_a_slow_read_never_writes_over_a_newer_one(members):
    asked, _state, _answers = members
    repo = InMemoryRepository()
    settings = google_settings()
    sign_in_groups.publish_wanted(repo, settings)
    directory(repo, "acme.com")
    later = directory(repo, "later.example")
    repo.provider_connections[later["id"]]["created_at"] += _dt.timedelta(seconds=1)  # not within the same clock tick
    sweep(repo, settings, NOW)
    assert {domain for domain, _admin, _groups in asked} == {"acme.com"}
    newer = stored(repo)
    # A read that began before the one stored ends late: what it found is not written over the newer membership.
    sign_in_groups._write(repo, NOW - _dt.timedelta(minutes=3), lambda current: {**current, "groups": {}})
    assert stored(repo) == newer
    # A stamp from a clock far ahead blocks nothing: the next read stores its own.
    repo.put_setting(sign_in_groups.KEY, {**newer, "tried_at": (NOW + _dt.timedelta(days=30)).isoformat()}, "worker")
    assert sweep(repo, settings, NOW + sign_in_groups.INTERVAL) is True
    assert stored(repo)["tried_at"] == (NOW + sign_in_groups.INTERVAL).isoformat()


def test_a_sign_in_gets_the_groups_its_verified_workspace_address_is_in(members):
    repo = InMemoryRepository()
    settings = google_settings()
    sign_in_groups.publish_wanted(repo, settings)
    directory(repo)
    sweep(repo, settings, NOW)
    lookup = sign_in_groups.Lookup(repo, settings, now=lambda: NOW + _dt.timedelta(minutes=30))
    dana = {"email": "Dana@acme.com", "email_verified": True, "hd": "ACME.com"}
    assert lookup(dana) == (ADMINS, VIEWERS)
    assert lookup({**dana, "email": "eve@acme.com"}) == (VIEWERS,)
    for claims in ({**dana, "email_verified": False}, {**dana, "email_verified": "true"}, {**dana, "hd": "other.com"},
                   {k: v for k, v in dana.items() if k != "hd"}, {**dana, "email": "mallory@acme.com"},
                   {**dana, "email": "ｄａｎａ@acme.com"}):
        assert lookup(claims) == (), claims
    # A read stamped well ahead of now (a clock that ran ahead), or kept under another key, grants nothing.
    ahead = sign_in_groups.Lookup(repo, settings, now=lambda: NOW - _dt.timedelta(minutes=10))
    assert ahead(dana) == ()
    repo.put_setting(sign_in_groups.KEY, {**stored(repo), "key_id": "0" * 64}, "worker")
    assert sign_in_groups.Lookup(repo, settings, now=lambda: NOW)(dana) == ()


class GoogleIssuer(FakeIssuer):
    """The synthetic issuer, published as Google's."""

    def get(self, url, **kwargs):
        assert kwargs.get("follow_redirects", False) is False
        self.calls.append(url)
        if url == GOOGLE + "/.well-known/openid-configuration":
            return FakeResp(200, {"issuer": GOOGLE, "jwks_uri": GOOGLE + "/jwks"})
        return super().get(url.replace(GOOGLE, "https://idp.test"), **kwargs)


def test_a_google_sign_in_reaches_the_console_with_the_role_of_its_groups(members):
    repo = InMemoryRepository()
    settings = google_settings()
    issuer = GoogleIssuer()
    client = TestClient(create_app(repo=repo, settings=settings, oidc_http_client=issuer))
    assert repo.get_setting(sign_in_groups.WANTED)["value"]["groups"] == [ADMINS, VIEWERS]

    def bearer(email, **extra):
        token = issuer.mint(sub=str(uuid.uuid4()), groups=(), issuer=GOOGLE, audience=AUDIENCE,
                            extra={"email": email, "email_verified": True, "hd": "acme.com", **extra})
        return {"Authorization": "Bearer " + token}

    assert client.get("/api/v1/session", headers=bearer("dana@acme.com")).status_code == 403  # nothing read yet
    directory(repo)
    sign_in_groups.sweep(repo, settings, Resolver(), lambda: None)
    client = TestClient(create_app(repo=repo, settings=settings, oidc_http_client=issuer))  # a fresh lookup cache
    assert client.get("/api/v1/session", headers=bearer("dana@acme.com")).json()["role"].lower() == "admin"
    assert client.get("/api/v1/session", headers=bearer("eve@acme.com")).json()["role"].lower() == "viewer"
    assert client.get("/api/v1/session", headers=bearer("mallory@acme.com")).status_code == 403
    # A groups claim a token might carry is not what Google sign-in is judged by.
    assert client.get("/api/v1/session", headers=bearer("mallory@acme.com", groups=[ADMINS])).status_code == 403
    view = client.get("/api/v1/settings/sign-in", headers=bearer("dana@acme.com")).json()["role_groups"]
    assert view["source"] == "WORKSPACE_GROUPS" and view["domain"] == "acme.com" and view["code"] is None
    assert view["groups"] == {"viewer": {"group": VIEWERS, "members": 2, "code": None},
                              "admin": {"group": ADMINS, "members": 1, "code": None}}
    # An owner approval link opens only for an account of that Workspace: a consumer account on the company's address
    # is refused before the link is even looked up; a Workspace account reaches the lookup (and this link is no link).
    link = "/api/v1/owner-approvals/view"
    consumer = client.post(link, headers=bearer("kim@acme.com", hd=""), json={"token": "x" * 43})
    assert (consumer.status_code, consumer.json()["detail"]) == (403, "OWNER_APPROVAL_EMAIL_UNVERIFIED")
    workspace = client.post(link, headers=bearer("kim@acme.com"), json={"token": "x" * 43})
    assert (workspace.status_code, workspace.json()["detail"]) == (404, "OWNER_APPROVAL_LINK_INVALID")
    assert sign_in_groups.company_account(repo, settings, {"email_verified": True, "hd": "acme.com"})
    assert not sign_in_groups.company_account(repo, settings, {"email_verified": True})
    assert not sign_in_groups.company_account(repo, settings, {"email_verified": "true", "hd": "acme.com"})
    assert sign_in_groups.company_account(repo, oidc_settings(FINGERPRINT_KEY=KEY), {})
