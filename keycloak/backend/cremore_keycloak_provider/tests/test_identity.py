"""Keycloak users and admin events through the shared identity collector, against a synthetic realm."""

import base64
import json
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from cremore.coverage.metadata_models import RECORD_ADAPTER, MetadataConnectionSpec
from cremore.identity.keys import Digester
from cremore_keycloak_provider import adapter

ORIGIN = "https://sso.acme.test"
SECRETS = {"client_id": "cremore-reader", "client_secret": "s3cr3t-value-for-tests"}
DIGEST = Digester(b"k" * 32)
U1, U2, U3 = ("11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222",
              "33333333-3333-4333-8333-333333333333")


def spec(audit=False, **overrides):
    body = {"name": "kc", "provider": "keycloak", "origin": ORIGIN, "edition": "self_managed", "tenant": "corp",
            "tenant_confirmed": True, "scopes": [{"kind": "realm", "id": "corp"}],
            "capabilities": ["identity_status", "audit"] if audit else ["identity_status"],
            "auth_type": "oauth_client",
            "secret_refs": {"client_id": "vault://kc/id", "client_secret": "vault://kc/secret"},
            "options": {"page_size": 2, "api_path": "/auth", "include_audit_events": audit}}
    body.update(overrides)
    return MetadataConnectionSpec.model_validate(body)


USERS = [
    {"id": U1, "username": "alice", "email": "alice@acme.test", "emailVerified": True, "enabled": True},
    {"id": U2, "username": "bob", "email": "bob@acme.test", "emailVerified": False, "enabled": False},
    {"id": "44444444-4444-4444-8444-444444444444", "username": "service-account-cremore", "enabled": True},
]
EVENTS = [
    {"id": "e1", "time": 1788000000000, "operationType": "UPDATE", "resourceType": "USER",
     "resourcePath": f"users/{U2}", "representation": json.dumps({"enabled": False})},
    {"id": "e2", "time": 1788000100000, "operationType": "DELETE", "resourceType": "USER",
     "resourcePath": f"users/{U3}"},
    {"id": "e3", "time": 1788000200000, "operationType": "UPDATE", "resourceType": "USER",
     "resourcePath": f"users/{U1}"},  # no representation: says nothing about enabled
]


def test_a_profile_names_the_person_and_only_a_verified_email_to_write_to():
    from cremore_keycloak_provider import identity

    alice = {**USERS[0], "firstName": "Alice", "lastName": "Kim"}
    assert dict(identity.user(spec(), "users", alice).profile) == {"display_name": "Alice Kim",
                                                                   "email": "alice@acme.test"}
    assert dict(identity.user(spec(), "users", {**USERS[1], "firstName": "Bob"}).profile) == {"display_name": "Bob"}


class Realm:
    def __init__(self, *, expire_once=False, users=None):
        self.calls, self.tokens, self.expire_once = [], 0, expire_once
        self.users = USERS if users is None else users

    def __call__(self, request):
        self.calls.append(request)
        if request.url.path == "/auth/realms/corp/protocol/openid-connect/token":
            expected = base64.b64encode(b"cremore-reader:s3cr3t-value-for-tests").decode()
            assert request.headers["Authorization"] == "Basic " + expected
            self.tokens += 1
            return httpx.Response(200, json={"access_token": f"kc-token-{self.tokens}", "token_type": "Bearer",
                                             "expires_in": 300})
        if self.expire_once and self.tokens == 1:
            return httpx.Response(401)
        if request.url.path == "/auth/admin/realms/corp/users/count":
            return httpx.Response(200, json=len(self.users))
        query = parse_qs(urlsplit(str(request.url)).query)
        first, size = int(query["first"][0]), int(query["max"][0])
        if request.url.path == "/auth/admin/realms/corp/users":
            assert query["briefRepresentation"] == ["true"]
            return httpx.Response(200, json=self.users[first:first + size])
        assert request.url.path == "/auth/admin/realms/corp/admin-events"
        assert query["operationTypes"] == ["UPDATE", "DELETE"] and query["direction"] == ["asc"]
        return httpx.Response(200, json=EVENTS[first:first + size])


def run(connection, realm):
    committed, final = [], None
    for page in adapter.collect_pages(connection, secrets=SECRETS, checkpoint={}, check=lambda: None,
                                      identity_digest=DIGEST, client=httpx.Client(transport=httpx.MockTransport(realm)),
                                      sleep=lambda _s: None):
        committed.extend(item.model_dump() for item in page.records)
        final = page
    return committed, final


def test_users_skip_service_accounts_and_keep_only_verified_emails():
    records, final = run(spec(), Realm())
    assert final.status == "COMPLETE"
    users = {r["identity"]["object_id"]: r for r in records if r["record_type"] == "entity_observation"}
    assert set(users) == {"user:" + U1, "user:" + U2}
    assert users["user:" + U2]["normalized_state"] == "DISABLED"
    kinds = {k["kind"] for k in users["user:" + U2]["identity_keys"]}
    assert kinds == {"IDP_USER_ID", "LOGIN"}  # bob's email is unverified
    events = [r for r in records if r["record_type"] == "provider_event"]
    assert events == []  # admin events are opt-in


def test_a_users_listing_that_shifted_or_came_up_short_is_partial():
    def statuses(records):
        return {r["provenance"]["operation"]: (r["status"], r["proves_completeness"], r["reasons"])
                for r in records if r["record_type"] == "operation_report"}

    people = [{"id": f"{n:08x}-0000-4000-8000-000000000000", "username": f"u{n}", "enabled": True} for n in range(5)]
    # The full listing ends on an empty page and names everyone the realm counted.
    records, final = run(spec(), Realm(users=list(people)))
    assert final.status == "COMPLETE" and statuses(records)["keycloak.users"] == ("COMPLETE", True, [])

    # u0 is deleted after the first page: everyone after it moves up one offset and u2 is never read.
    class Shifting(Realm):
        def __call__(self, request):
            if request.url.path.endswith("/users") and "first=2" in str(request.url) and people[0] in self.users:
                self.users.remove(people[0])
            return super().__call__(request)

    records, final = run(spec(), Shifting(users=list(people)))
    read = {r["identity"]["object_id"] for r in records if r["record_type"] == "entity_observation"}
    assert "user:" + people[2]["id"] not in read
    assert final.status == "PARTIAL"
    assert statuses(records)["keycloak.users"] == ("PARTIAL", False, ["KEYCLOAK_USER_COUNT_MISMATCH"])

    # A federated realm drops a user its LDAP no longer holds from a page: a short page mid-list is not the end.
    class Federated(Realm):
        def __call__(self, request):
            response = super().__call__(request)
            if request.url.path.endswith("/users"):
                return httpx.Response(200, json=[u for u in response.json() if u["username"] != "u1"])
            return response

    records, final = run(spec(), Federated(users=list(people)))
    read = {r["identity"]["object_id"] for r in records if r["record_type"] == "entity_observation"}
    assert {"user:" + u["id"] for u in people if u["username"] != "u1"} <= read  # read on past the short page
    assert statuses(records)["keycloak.users"] == ("PARTIAL", False, ["KEYCLOAK_USER_COUNT_MISMATCH"])


@pytest.mark.parametrize("resume", [False, True])
def test_a_user_renamed_while_the_listing_pages_is_partial(resume):
    """a..d read [a, b]; a is renamed z, so offset 2 holds [d, z]: c is never read, yet rows read and both counts are
    4. The second sighting of a's id is what says the list moved -- also when it comes after a resume."""
    people = [{"id": f"{n:08x}-0000-4000-8000-000000000000", "username": name, "enabled": True}
              for n, name in enumerate("abcd")]

    class Renamed(Realm):
        down = resume  # one 503 at offset 2: the run waits and resumes from its checkpoint

        def __call__(self, request):
            if request.url.path.endswith("/users") and "first=2" in str(request.url):
                if self.down:
                    self.down = False
                    return httpx.Response(503)
                if self.users[0]["username"] == "a":
                    self.users = sorted([*self.users[1:], {**self.users[0], "username": "z"}],
                                        key=lambda user: user["username"])
            return super().__call__(request)

    realm, committed, checkpoint, final = Renamed(users=list(people)), [], {}, None
    while final is None or final.status == "WAITING":
        for page in adapter.collect_pages(spec(), secrets=SECRETS, checkpoint=checkpoint, check=lambda: None,
                                          read_records=lambda: list(committed), identity_digest=DIGEST,
                                          client=httpx.Client(transport=httpx.MockTransport(realm)),
                                          sleep=lambda _s: None):
            committed.extend(item.model_dump() for item in page.records)
            checkpoint, final = page.checkpoint, page
    read = {r["identity"]["object_id"] for r in committed if r["record_type"] == "entity_observation"}
    assert not realm.down and "user:" + people[2]["id"] not in read
    report, = [r for r in committed if r["record_type"] == "operation_report"
               and r["provenance"]["operation"] == "keycloak.users"]
    assert (final.status, report["status"], report["proves_completeness"], report["reasons"]) == (
        "PARTIAL", "PARTIAL", False, ["KEYCLOAK_LISTING_SHIFTED"])


def test_admin_events_date_disables_and_deletes():
    records, final = run(spec(audit=True, options={"page_size": 2, "api_path": "/auth", "include_audit_events": True,
                                                   "audit_lookback_days": 30}), Realm())
    assert final.status == "COMPLETE"
    events = {(r["subject"]["object_id"], r["event_type"], r["occurred_at"]) for r in records
              if r["record_type"] == "provider_event"}
    assert events == {("user:" + U2, "user.disabled", "2026-08-29T10:40:00+00:00"),
                      ("user:" + U3, "user.deleted", "2026-08-29T10:41:40+00:00")}
    for item in records:
        assert adapter.validate_record(spec(audit=True, options={"page_size": 2, "api_path": "/auth",
                                                                 "include_audit_events": True,
                                                                 "audit_lookback_days": 30}),
                                       RECORD_ADAPTER.validate_python(item))


CLIENTS = [
    {"id": "55555555-5555-4555-8555-555555555555", "clientId": "account-console", "name": "${client_account-console}",
     "enabled": True, "publicClient": True},
    # Before 26.8.0 view-clients is answered with the secret and private-key attributes too.
    {"id": "66666666-6666-4666-8666-666666666666", "clientId": "https://github.com/orgs/acme", "name": "GitHub",
     "enabled": True, "secret": "kept-nowhere-secret", "attributes": {
         "client.secret.rotated": "kept-nowhere-rotated", "saml.signing.private.key": "kept-nowhere-key"}},
    {"id": "77777777-7777-4777-8777-777777777777", "clientId": "urn:amazon:webservices", "name": "", "enabled": False},
]


def test_the_client_list_is_a_collection_of_its_own_and_keeps_only_names_and_state():
    def realm(request):
        if request.url.path == "/auth/realms/corp/protocol/openid-connect/token":
            return httpx.Response(200, json={"access_token": "kc-token", "token_type": "Bearer", "expires_in": 300})
        assert request.url.path == "/auth/admin/realms/corp/clients"
        query = parse_qs(urlsplit(str(request.url)).query)
        first, size = int(query["first"][0]), int(query["max"][0])
        return httpx.Response(200, json=CLIENTS[first:first + size])

    connection = spec(options={"page_size": 2, "api_path": "/auth", "sources": ["apps"]})
    records, final = run(connection, realm)
    assert final.status == "COMPLETE"
    apps = {r["identity"]["object_id"]: (r["identity"]["kind"], r["normalized_state"],
                                         {fact["name"]: fact["value"] for fact in r["facts"]})
            for r in records if r["record_type"] == "entity_observation"}
    # The realm's own account console is no service; a client with no name is called by its client ID.
    assert apps == {
        "app:66666666-6666-4666-8666-666666666666": (
            "installation", "ACTIVE", {"display_name": "GitHub", "client_id": "https://github.com/orgs/acme"}),
        "app:77777777-7777-4777-8777-777777777777": (
            "installation", "DISABLED", {"display_name": "urn:amazon:webservices", "client_id": "urn:amazon:webservices"})}
    assert "kept-nowhere" not in json.dumps(records)
    reports = {r["provenance"]["operation"]: r["status"] for r in records if r["record_type"] == "operation_report"}
    assert reports == {"keycloak.users": "NOT_REQUESTED", "keycloak.admin_events": "NOT_REQUESTED",
                       "keycloak.clients": "COMPLETE"}
    for item in records:
        assert adapter.validate_record(connection, RECORD_ADAPTER.validate_python(item))
    with pytest.raises(ValueError, match="KEYCLOAK_COLLECTION_OPTION_NOT_SUPPORTED"):
        adapter.validate_spec(spec(options={"page_size": 2, "sources": ["apps"], "keep_profiles": True}))


def test_a_client_named_like_a_secret_is_called_by_its_client_id_and_master_keeps_no_realm_clients():
    from cremore_keycloak_provider import identity

    rows = [{"id": "88888888-8888-4888-8888-888888888888", "clientId": "slack", "name": "Bearer " + "x" * 24,
             "enabled": True},
            {"id": "99999999-9999-4999-8999-999999999999", "clientId": "corp-realm", "name": "corp Realm", "enabled": True}]

    def realm(request):
        if request.url.path.endswith("/protocol/openid-connect/token"):
            return httpx.Response(200, json={"access_token": "kc-token", "token_type": "Bearer", "expires_in": 300})
        return httpx.Response(200, json=rows)

    master = spec(tenant="master", scopes=[{"kind": "realm", "id": "master"}],
                  options={"page_size": 5, "api_path": "", "sources": ["apps"]})
    records, final = run(master, realm)
    apps = {r["identity"]["object_id"]: {fact["name"]: fact["value"] for fact in r["facts"]}
            for r in records if r["record_type"] == "entity_observation"}
    # The master realm's "<realm>-realm" clients administer other realms; only master has them.
    assert final.status == "COMPLETE" and apps == {
        "app:88888888-8888-4888-8888-888888888888": {"display_name": "slack", "client_id": "slack"}}
    assert identity.app(spec(), "clients", rows[1]).key == "corp-realm"  # elsewhere it is a client like any


def test_an_expired_token_is_renewed_once():
    realm = Realm(expire_once=True)
    _records, final = run(spec(), realm)
    assert final.status == "COMPLETE" and realm.tokens == 2


@pytest.mark.parametrize("overrides, code", [
    ({"tenant": "other"}, "KEYCLOAK_TENANT_IS_THE_REALM"),
    ({"auth_type": "bearer", "secret_refs": {"token": "vault://kc/t"}}, "KEYCLOAK_SERVICE_ACCOUNT_CLIENT_REQUIRED"),
    ({"scopes": [{"kind": "organization", "id": "corp"}]}, "KEYCLOAK_ONE_REALM_SCOPE"),
])
def test_the_spec_is_refused_outside_one_realm_service_account(overrides, code):
    with pytest.raises(ValueError, match=code):
        adapter.validate_spec(spec(**overrides))


def test_audit_capability_and_option_must_agree():
    with pytest.raises(ValueError, match="IDENTITY_AUDIT_OPTION_MISMATCH"):
        adapter.validate_spec(spec(capabilities=["identity_status", "audit"]))
