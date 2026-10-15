"""GitHub SAML/SCIM external identities through the shared identity collector."""

import base64
import json

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cremore.coverage.metadata_models import RECORD_ADAPTER, MetadataConnectionSpec
from cremore.identity.keys import Digester
from cremore_github_provider.identity import adapter, directory

DIGEST = Digester(b"k" * 32)
TOKEN = "ghp_" + "a" * 36
PEM = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
APP = {"app_id": "12345", "installation_id": "678", "private_key": base64.b64encode(PEM).decode()}
INSTALLATION_TOKEN = "ghs_" + "i" * 36


def spec(**overrides):
    body = {"name": "gh saml", "provider": "github_identity", "origin": "https://github.com",
            "edition": "enterprise_cloud", "scopes": [{"kind": "organization", "id": "Acme-Corp"}],
            "capabilities": ["identity_status"], "auth_type": "bearer", "secret_refs": {"token": "vault://gh/owner"},
            "options": {"page_size": 2}}
    body.update(overrides)
    return MetadataConnectionSpec.model_validate(body)


def node(login, name_id, *, scim=None, emails=()):
    return {"samlIdentity": {"nameId": name_id, "username": None, "emails": [{"value": e} for e in emails]},
            "scimIdentity": scim, "user": {"login": login} if login else None}


def page(nodes, *, after=None):
    return httpx.Response(200, json={"data": {"organization": {"samlIdentityProvider": {"externalIdentities": {
        "pageInfo": {"hasNextPage": after is not None, "endCursor": after}, "nodes": nodes}}}}})


def run(connection, handler, secrets=None):
    committed, final = [], None
    for item in adapter.collect_pages(connection, secrets=secrets or {"token": TOKEN}, checkpoint={}, check=lambda: None,
                                      identity_digest=DIGEST, client=httpx.Client(transport=httpx.MockTransport(handler)),
                                      sleep=lambda _s: None):
        committed.extend(record.model_dump() for record in item.records)
        final = item
    return committed, final


def test_claimed_identities_become_logins_with_digested_saml_and_scim_values():
    def handler(request):
        assert str(request.url) == "https://api.github.com/graphql"
        assert request.headers["Authorization"] == "bearer " + TOKEN
        body = json.loads(request.content)
        assert body["variables"]["org"] == "Acme-Corp"
        if body["variables"]["after"] is None:
            return page([node("Octo-Cat", "octo@acme.test", scim={"username": "00u1okta", "emails": []},
                              emails=["octo@acme.test"]), node(None, "pending@acme.test")], after="c1")
        return page([node("hubot", "hubot@acme.test")])

    records, final = run(spec(), handler)
    assert final.status == "COMPLETE"
    accounts = {r["identity"]["object_id"]: r for r in records if r["record_type"] == "entity_observation"}
    assert set(accounts) == {"user:octo-cat", "user:hubot"}
    keys = {(k["kind"], k["digest"]) for k in accounts["user:octo-cat"]["identity_keys"]}
    assert keys == {("IDP_USER_ID", DIGEST("octo-cat")), ("SAML_NAME_ID", DIGEST("octo@acme.test")),
                    ("SCIM_EXTERNAL_ID", DIGEST("00u1okta")), ("VERIFIED_EMAIL", DIGEST("octo@acme.test"))}
    assert "acme.test" not in json.dumps(records)
    for item in records:
        assert adapter.validate_record(spec(), RECORD_ADAPTER.validate_python(item))


def test_the_provisioned_name_and_email_speak_for_the_person():
    from cremore_github_provider.identity import directory

    row = {"user": {"login": "Ada-L"},
           "samlIdentity": {"nameId": "ada@acme.test", "givenName": "A.", "familyName": "L.",
                            "emails": [{"value": "ada.saml@acme.test"}]},
           "scimIdentity": {"username": "ada", "givenName": "Ada", "familyName": "Lovelace",
                            "emails": [{"value": "ada@acme.test"}, {"value": "ada.alt@acme.test"}]}}
    found = directory.user(None, "identities", row)
    assert found.id == "ada-l" and dict(found.profile) == {"display_name": "Ada Lovelace", "email": "ada@acme.test"}
    saml_only = directory.user(None, "identities", {**row, "scimIdentity": None})
    assert dict(saml_only.profile) == {"display_name": "A. L.", "email": "ada.saml@acme.test"}


def test_an_organization_without_saml_is_a_failed_read_not_an_empty_list():
    def handler(request):
        return httpx.Response(200, json={"data": {"organization": {"samlIdentityProvider": None}}})

    _records, final = run(spec(), handler)
    assert final.status == "FAILED" and "GITHUB_IDENTITY_SAML_NOT_ENABLED" in final.reasons


def test_a_token_without_owner_rights_is_reported():
    def handler(request):
        return httpx.Response(200, json={"errors": [{"type": "FORBIDDEN", "message": "no"}]})

    _records, final = run(spec(), handler)
    assert "GITHUB_IDENTITY_FORBIDDEN" in final.reasons


def app_spec(**overrides):
    return spec(**{"auth_type": "github_app", "secret_refs": dict.fromkeys(APP, "vault://gh/app"), **overrides})


def app_github(held, graphql=None):
    """GitHub answering the App: its installation on the organization, a token for what was asked, then GraphQL."""
    calls, asked = [], []

    def handler(request):
        calls.append((request.method, request.url.path))
        if request.url.path == "/orgs/Acme-Corp/installation":
            return httpx.Response(200, json={"id": 678, "app_id": 12345, "account": {"login": "Acme-Corp"},
                                             "target_type": "Organization", "permissions": dict.fromkeys(held, "read")})
        if request.url.path == "/app/installations/678/access_tokens":
            asked.append(json.loads(request.content)["permissions"])
            if set(asked[-1]) - set(held):
                return httpx.Response(422, json={"message": "synthetic-not-granted"})
            return httpx.Response(201, json={"token": INSTALLATION_TOKEN, "expires_at": "2099-01-01T00:00:00Z",
                                             "permissions": asked[-1]})
        assert request.headers["Authorization"] == "bearer " + INSTALLATION_TOKEN
        return graphql(json.loads(request.content))
    return handler, calls, asked


def test_an_app_with_members_read_reads_the_organization_s_identities():
    """GitHub shows an organization's SAML identities to an App installation with Members (read): the token comes from
    the organization's own installation, holds that permission alone, and serves every page."""
    def graphql(body):
        assert body["variables"]["org"] == "Acme-Corp"
        if body["variables"]["after"] is None:
            return page([node("Octo-Cat", "octo@acme.test")], after="c1")
        return page([node("hubot", "hubot@acme.test")])

    handler, calls, asked = app_github(("members", "contents"), graphql)
    records, final = run(app_spec(), handler, APP)
    assert final.status == "COMPLETE"
    assert {r["identity"]["object_id"] for r in records if r["record_type"] == "entity_observation"} == {
        "user:octo-cat", "user:hubot"}
    assert calls == [("GET", "/orgs/Acme-Corp/installation"), ("POST", "/app/installations/678/access_tokens"),
                     ("POST", "/graphql"), ("POST", "/graphql")]
    assert asked == [{"members": "read"}]
    assert INSTALLATION_TOKEN not in json.dumps(records) and APP["private_key"][:40] not in json.dumps(records)


def test_an_app_without_members_read_gets_no_token_and_reads_nothing():
    handler, calls, _asked = app_github(("contents",))
    records, final = run(app_spec(), handler, APP)
    assert final.status == "FAILED" and final.reasons == ["GITHUB_IDENTITY_APP_REJECTED"]
    assert ("POST", "/graphql") not in calls and "synthetic-not-granted" not in json.dumps(records)


def test_an_app_installed_elsewhere_fails_and_github_down_waits():
    def installation(login):
        return httpx.Response(200, json={"id": 678, "app_id": 12345, "account": {"login": login},
                                         "target_type": "Organization", "permissions": {"members": "read"}})

    def elsewhere(request):
        assert request.url.path == "/orgs/Acme-Corp/installation"  # never a token for another account's installation
        return installation("Other-Org")

    def down(request):
        return installation("Acme-Corp") if request.url.path == "/orgs/Acme-Corp/installation" else httpx.Response(502)

    _records, final = run(app_spec(), elsewhere, APP)
    assert (final.status, final.reasons) == ("FAILED", ["GITHUB_IDENTITY_APP_INSTALLATION_MISMATCH"])
    _records, final = run(app_spec(), down, APP)
    assert (final.status, final.reasons) == ("WAITING", ["GITHUB_IDENTITY_APP_UNAVAILABLE"])


def test_the_budget_is_checked_before_an_app_token_is_minted():
    class Spent:
        def before(self):
            raise directory.ReadError("REQUEST_BUDGET_EXCEEDED")

    handler, calls, _asked = app_github(("members",))
    connection = app_spec()
    reader = directory.Reader(connection, APP, httpx.Client(transport=httpx.MockTransport(handler)), Spent())
    with pytest.raises(directory.ReadError, match="REQUEST_BUDGET_EXCEEDED"):
        reader.read(connection.scopes[0], "external_identities", None)
    assert calls == []


def test_an_app_never_reads_an_enterprise_and_needs_its_three_values():
    with pytest.raises(ValueError, match="GITHUB_IDENTITY_ENTERPRISE_NEEDS_AN_OWNER_TOKEN"):
        adapter.validate_spec(app_spec(edition="enterprise_cloud", scopes=[{"kind": "enterprise", "id": "acme"}]))
    with pytest.raises(ValueError, match="GITHUB_IDENTITY_APP_CREDENTIAL_REQUIRED"):
        adapter.validate_spec(app_spec(secret_refs={"token": "vault://gh/app"}))
    with pytest.raises(ValueError, match="GITHUB_IDENTITY_OWNER_TOKEN_REQUIRED"):
        adapter.validate_spec(spec(secret_refs=dict.fromkeys(APP, "vault://gh/app")))


@pytest.mark.parametrize("origin, url", [
    ("https://github.com", "https://api.github.com/graphql"),
    ("https://ghes.acme.test", "https://ghes.acme.test/api/graphql"),
    ("https://acme.ghe.com", "https://api.acme.ghe.com/graphql"),
])
def test_graphql_endpoint_per_github_edition(origin, url):
    assert directory.graphql_url(origin) == url


def enterprise_page(nodes, *, provider="oidcProvider", after=None):
    identities = {"externalIdentities": {"pageInfo": {"hasNextPage": after is not None, "endCursor": after},
                                         "nodes": nodes}}
    return httpx.Response(200, json={"data": {"enterprise": {"ownerInfo": {
        "samlIdentityProvider": None, "oidcProvider": None, provider: identities}}}})


def test_managed_users_of_an_enterprise_link_their_logins_to_what_the_idp_provisioned():
    """EMU: the enterprise's OIDC (or SAML) provider names, per managed login, the SCIM user name and emails."""
    def handler(request):
        body = json.loads(request.content)
        assert "enterprise(slug: $enterprise)" in body["query"] and body["variables"]["enterprise"] == "acme"
        if body["variables"]["after"] is None:
            return enterprise_page([node("Dana_ACME", None, scim={"username": "dana@acme.test", "emails": [
                {"value": "dana@acme.test"}]}), node(None, None, scim={"username": "pending@acme.test", "emails": []})],
                after="c1")
        assert body["variables"]["after"] == "c1"
        return enterprise_page([node("acme_admin", None, scim={"username": "ops@acme.test", "emails": []})])

    connection = spec(scopes=[{"kind": "enterprise", "id": "acme"}])
    records, final = run(connection, handler)
    assert final.status == "COMPLETE"
    accounts = {r["identity"]["object_id"]: r for r in records if r["record_type"] == "entity_observation"}
    assert set(accounts) == {"user:dana_acme", "user:acme_admin"}  # managed logins: handle_shortcode
    keys = {(k["kind"], k["digest"]) for k in accounts["user:dana_acme"]["identity_keys"]}
    assert keys == {("IDP_USER_ID", DIGEST("dana_acme")), ("SCIM_EXTERNAL_ID", DIGEST("dana@acme.test")),
                    ("VERIFIED_EMAIL", DIGEST("dana@acme.test"))}
    assert "acme.test" not in json.dumps(records)
    for item in records:
        assert adapter.validate_record(connection, RECORD_ADAPTER.validate_python(item))
    # SAML set on the enterprise answers through its SAML provider.
    _records, final = run(connection, lambda request: enterprise_page([node("ed_acme", "ed@acme.test")],
                                                                      provider="samlIdentityProvider"))
    assert final.status == "COMPLETE"


@pytest.mark.parametrize("scope, answer, code", [
    ("enterprise", {"data": {"enterprise": None}, "errors": [
        {"type": "NOT_FOUND", "path": ["enterprise"], "message": "Could not resolve to an Enterprise."}]},
     "GITHUB_IDENTITY_ENTERPRISE_NOT_FOUND"),
    ("organization", {"data": {"organization": None}, "errors": [
        {"type": "NOT_FOUND", "path": ["organization"], "message": "Could not resolve to an Organization."}]},
     "GITHUB_IDENTITY_ORGANIZATION_NOT_FOUND"),
    ("enterprise", {"data": {"enterprise": None}}, "GITHUB_IDENTITY_ENTERPRISE_NOT_FOUND"),
    ("enterprise", {"data": {"enterprise": {"ownerInfo": None}}}, "GITHUB_IDENTITY_FORBIDDEN"),
    ("enterprise", {"data": {"enterprise": {"ownerInfo": {"samlIdentityProvider": None, "oidcProvider": None}}}},
     "GITHUB_IDENTITY_SAML_NOT_ENABLED"),
])
def test_a_read_says_why_it_found_nobody(scope, answer, code):
    _records, final = run(spec(scopes=[{"kind": scope, "id": "acme"}]), lambda request: httpx.Response(200, json=answer))
    assert final.status == "FAILED" and code in final.reasons


@pytest.mark.parametrize("scope, path", [("enterprise", ["organization"]), ("organization", ["enterprise"]),
                                       ("enterprise", None), ("organization", None)])
def test_not_found_elsewhere_does_not_claim_the_requested_identity_target_is_missing(scope, path):
    error = {"type": "NOT_FOUND", "message": "synthetic-private-error"}
    if path is not None:
        error["path"] = path
    answer = {"data": {scope: None}, "errors": [error]}
    records, final = run(spec(scopes=[{"kind": scope, "id": "acme"}]), lambda request: httpx.Response(200, json=answer))
    assert final.status == "FAILED" and final.reasons == ["GITHUB_IDENTITY_QUERY_FAILED"]
    assert error["message"] not in json.dumps(records)


@pytest.mark.parametrize("status, headers, answer", [
    # The primary limit: 200, an error, and no points left.
    (200, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "9999999999"},
     {"errors": [{"type": "RATE_LIMITED", "message": "API rate limit exceeded for user ID 1."}]}),
    # A secondary limit, as 200 or 403, with retry-after; or as 403 with only its message.
    (200, {"retry-after": "120"}, {"errors": [{"message": "You have exceeded a secondary rate limit."}]}),
    (403, {"retry-after": "120"}, {"message": "You have exceeded a secondary rate limit."}),
    (403, {}, {"message": "You have exceeded a secondary rate limit. Please wait a few minutes."}),
    (429, {}, None),
])
def test_a_graphql_rate_limit_waits_instead_of_failing(status, headers, answer):
    respond = (lambda request: httpx.Response(status, headers=headers, json=answer)) if answer is not None \
        else (lambda request: httpx.Response(status, headers=headers))
    _records, final = run(spec(), respond)
    assert (final.status, final.reasons) == ("WAITING", ["GITHUB_IDENTITY_RATE_LIMITED"])


def test_a_refusal_is_still_a_refusal_and_a_last_point_page_still_counts():
    _records, final = run(spec(), lambda request: httpx.Response(403, json={"message": "Must have admin rights."}))
    assert (final.status, final.reasons) == ("FAILED", ["GITHUB_IDENTITY_ACCESS_DENIED"])
    spent = page([node("hubot", "hubot@acme.test")])
    spent.headers["x-ratelimit-remaining"] = "0"
    _records, final = run(spec(), lambda request: spent)
    assert final.status == "COMPLETE"


def test_a_server_reads_its_instance_saml_as_the_enterprise_and_never_asks_for_oidc():
    """Enterprise Server: SAML is set on the instance and GraphQL answers it as the enterprise's; its schema has no
    ``oidcProvider``, so asking for it would fail every read."""
    def handler(request):
        assert str(request.url) == "https://ghes.acme.test/api/graphql"
        body = json.loads(request.content)
        assert body["variables"]["enterprise"] == "acme" and "oidcProvider" not in body["query"]
        return httpx.Response(200, json={"data": {"enterprise": {"ownerInfo": {"samlIdentityProvider": {
            "externalIdentities": {"pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [
                node("chulsoo-kim", "chulsoo.kim@acme.test", scim={"username": "chulsoo.kim@acme.test", "emails": []}),
                node(None, "pending@acme.test")]}}}}}})

    connection = spec(edition="enterprise_server", origin="https://ghes.acme.test",
                      scopes=[{"kind": "enterprise", "id": "acme"}])
    records, final = run(connection, handler)
    assert final.status == "COMPLETE"
    accounts = {r["identity"]["object_id"]: r for r in records if r["record_type"] == "entity_observation"}
    assert set(accounts) == {"user:chulsoo-kim"}  # the login GitHub names, never one computed from the user name
    keys = {(k["kind"], k["digest"]) for k in accounts["user:chulsoo-kim"]["identity_keys"]}
    assert keys == {("IDP_USER_ID", DIGEST("chulsoo-kim")), ("SAML_NAME_ID", DIGEST("chulsoo.kim@acme.test")),
                    ("SCIM_EXTERNAL_ID", DIGEST("chulsoo.kim@acme.test"))}
    _records, final = run(connection, lambda request: httpx.Response(200, json={"data": {"enterprise": {
        "ownerInfo": {"samlIdentityProvider": None}}}}))
    assert final.status == "FAILED" and "GITHUB_IDENTITY_SAML_NOT_ENABLED" in final.reasons


def test_an_enterprise_is_read_alone_and_on_an_enterprise_edition_only():
    with pytest.raises(ValueError, match="ENTERPRISE_SCOPE_NEEDS_ENTERPRISE_CLOUD"):
        adapter.validate_spec(spec(edition="cloud", scopes=[{"kind": "enterprise", "id": "acme"}]))
    adapter.validate_spec(spec(edition="enterprise_server", origin="https://ghes.acme.test",
                               scopes=[{"kind": "enterprise", "id": "acme"}]))
    for scopes in ([{"kind": "enterprise", "id": "a"}, {"kind": "enterprise", "id": "b"}],
                   [{"kind": "organization", "id": "acme"}, {"kind": "enterprise", "id": "acme"}]):
        with pytest.raises(ValueError, match="ENTERPRISE_SCOPE_ALONE"):
            adapter.validate_spec(spec(scopes=scopes))
    adapter.validate_spec(spec(scopes=[{"kind": "organization", "id": "a"}, {"kind": "organization", "id": "b"}]))
    for login, ok in (("dana_acme", True), ("dana-x_ac1", True), ("acme_admin", True), ("a" * 34 + "_acme", True),
                      ("dana_", False), ("_acme", False), ("a" * 35 + "_acme", False), ("dana_ab", False),
                      ("octo-cat", True)):
        assert bool(directory.USER_ID.fullmatch(login)) is ok, login
