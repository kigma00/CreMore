"""Okta user status through the shared identity collector, against a synthetic org."""

import base64
import hashlib
import json
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cremore.coverage.metadata_models import RECORD_ADAPTER, MetadataConnectionSpec
from cremore.identity.keys import Digester
from cremore_okta_provider import adapter

ORIGIN = "https://acme.okta.com"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PEM = KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption()).decode()
SECRETS = {"client_id": "0oa1serviceapp", "private_key": PEM}
DIGEST = Digester(b"k" * 32)


def spec(**overrides):
    body = {"name": "okta", "provider": "okta", "origin": ORIGIN, "edition": "cloud", "tenant": "acme.okta.com",
            "tenant_confirmed": True, "scopes": [{"kind": "organization", "id": "acme.okta.com"}],
            "capabilities": ["identity_status"], "auth_type": "private_key_jwt",
            "secret_refs": {"client_id": "vault://okta/id", "private_key": "vault://okta/key"},
            "options": {"page_size": 2}}
    body.update(overrides)
    return MetadataConnectionSpec.model_validate(body)


def users_page(*rows, after=None):
    headers = {"link": f'<{ORIGIN}/api/v1/users?limit=2&after={after}>; rel="next"'} if after else {}
    return httpx.Response(200, json=list(rows), headers=headers)


def row(ident, status, *, email=None, login=None, changed="2026-09-01T00:00:00.000Z"):
    return {"id": ident, "status": status, "statusChanged": changed,
            "profile": {"login": login or f"{ident}@acme.test", "email": email or f"{ident}@acme.test"}}


class Org:
    """A synthetic Okta org: a token endpoint and two pages of users."""

    def __init__(self, pages, *, dpop=False):
        self.pages, self.dpop, self.seen = pages, dpop, []

    def __call__(self, request):
        self.seen.append(request)
        if request.url.path == "/oauth2/v1/token":
            form = parse_qs(request.content.decode())
            assertion = jwt.decode(form["client_assertion"][0], KEY.public_key(), algorithms=["RS256"],
                                   audience=ORIGIN + "/oauth2/v1/token")
            assert assertion["iss"] == assertion["sub"] == SECRETS["client_id"]
            assert form["scope"] == ["okta.users.read"]
            if self.dpop:
                proof = request.headers.get("DPoP")
                if not proof:
                    return httpx.Response(400, json={"error": "invalid_dpop_proof"})
                claims = jwt.decode(proof, options={"verify_signature": False})
                if "nonce" not in claims:
                    return httpx.Response(400, json={"error": "use_dpop_nonce"}, headers={"dpop-nonce": "n-1"})
                return httpx.Response(200, json={"access_token": "t0k3n.dpop", "token_type": "DPoP", "expires_in": 3600})
            return httpx.Response(200, json={"access_token": "t0k3n.plain", "token_type": "Bearer", "expires_in": 3600})
        assert request.url.path == "/api/v1/users"
        query = parse_qs(urlsplit(str(request.url)).query)
        assert 'status eq "DEPROVISIONED"' in query["filter"][0]
        if self.dpop:
            assert request.headers["Authorization"] == "DPoP t0k3n.dpop"
            claims = jwt.decode(request.headers["DPoP"], options={"verify_signature": False})
            assert claims["htu"] == ORIGIN + "/api/v1/users" and claims["htm"] == "GET"
            ath = base64.urlsafe_b64encode(hashlib.sha256(b"t0k3n.dpop").digest()).rstrip(b"=").decode()
            assert claims["ath"] == ath
        else:
            assert request.headers["Authorization"] == "Bearer t0k3n.plain"
        return self.pages[query.get("after", [""])[0]]


def run(connection, org, *, checkpoint=None, committed=None):
    client = httpx.Client(transport=httpx.MockTransport(org))
    committed = committed if committed is not None else []
    pages = adapter.collect_pages(connection, secrets=SECRETS, checkpoint=checkpoint or {}, check=lambda: None,
                                  read_records=(lambda: iter(committed)) if checkpoint else None,
                                  identity_digest=DIGEST, client=client, sleep=lambda _s: None)
    final = None
    for page in pages:
        committed.extend(item.model_dump() for item in page.records)
        final = page
    return committed, final


PAGES = {"": users_page(row("00uactive01", "ACTIVE"), row("00ususpend1", "SUSPENDED"), after="p2"),
         "p2": users_page(row("00udeprov01", "DEPROVISIONED", changed="2026-09-10T08:00:00.000Z"),
                          row("00ustaged01", "STAGED"))}


def test_every_status_is_listed_and_only_digests_leave_the_collector():
    records, final = run(spec(), Org(PAGES))
    assert final.status == "COMPLETE"
    users = {r["identity"]["object_id"]: r for r in records if r["record_type"] == "entity_observation"}
    assert {k: (v["provider_state"], v["normalized_state"]) for k, v in users.items()} == {
        "user:00uactive01": ("ACTIVE", "ACTIVE"), "user:00ususpend1": ("SUSPENDED", "DISABLED"),
        "user:00udeprov01": ("DEPROVISIONED", "DISABLED"), "user:00ustaged01": ("STAGED", "PENDING")}
    departed = users["user:00udeprov01"]
    assert departed["effective_at"] == "2026-09-10T08:00:00+00:00"
    assert {(k["kind"], k["digest"]) for k in departed["identity_keys"]} == {
        ("IDP_USER_ID", DIGEST("00udeprov01")), ("LOGIN", DIGEST("00udeprov01@acme.test")),
        ("EMAIL", DIGEST("00udeprov01@acme.test"))}
    assert departed["identity_key_id"] == DIGEST.key_id
    assert "@acme.test" not in json.dumps(records)
    report = next(r for r in records if r["record_type"] == "operation_report")
    assert report["proves_completeness"] is True and report["saved_records"] == 4
    for item in records:
        assert adapter.validate_record(spec(), RECORD_ADAPTER.validate_python(item))
        assert not adapter.validate_machine_record(spec(), RECORD_ADAPTER.validate_python(item))


def test_a_profile_is_kept_when_the_collection_asks_and_matching_still_uses_digests():
    from cremore_okta_provider import identity

    person = {"id": "00uactive01", "status": "ACTIVE", "profile": {
        "login": "ada@acme.test", "email": "ada@acme.test", "firstName": "Ada", "lastName": "Lovelace",
        "department": "Platform", "title": "Engineer"}}
    assert dict(identity.user(spec(), "users", person).profile) == {
        "display_name": "Ada Lovelace", "email": "ada@acme.test", "department": "Platform", "title": "Engineer"}
    named = {**person, "profile": {**person["profile"], "displayName": "Ada L."}}
    assert dict(identity.user(spec(), "users", named).profile)["display_name"] == "Ada L."
    kept = spec(options={"page_size": 2, "keep_profiles": True})
    records, final = run(kept, Org(PAGES))
    assert final.status == "COMPLETE"
    active = next(r for r in records if r["identity"]["object_id"] == "user:00uactive01")
    assert {fact["name"]: fact["value"] for fact in active["facts"]} == {"email": "00uactive01@acme.test"}
    assert {key["kind"] for key in active["identity_keys"]} == {"IDP_USER_ID", "LOGIN", "EMAIL"}


def test_a_service_app_that_requires_dpop_gets_proofs_with_the_nonce_and_token_hash():
    org = Org(PAGES, dpop=True)
    _records, final = run(spec(), org)
    assert final.status == "COMPLETE"
    token_calls = [r for r in org.seen if r.url.path == "/oauth2/v1/token"]
    assert len(token_calls) == 3  # plain, proof without nonce, proof with nonce


def test_a_rate_limit_waits_and_the_run_resumes_from_its_checkpoint():
    pages = dict(PAGES)
    pages["p2"] = httpx.Response(429, headers={"retry-after": "7"})
    records, waiting = run(spec(), Org(pages))
    assert waiting.status == "WAITING" and waiting.retry_after_seconds == 7
    records, final = run(spec(), Org(PAGES), checkpoint=waiting.checkpoint, committed=records)
    assert final.status == "COMPLETE"
    assert len([r for r in records if r["record_type"] == "entity_observation"]) == 4


def test_the_record_budget_counts_the_reports_of_sources_the_collection_does_not_read():
    # Four people and their listing's report fill five records; the app list's not-requested reports would pass the
    # budget, which the store holds every run to, so the run stops short of them as partial. The people listing
    # itself was complete and says so.
    records, final = run(spec(max_records=5), Org(PAGES))
    assert final.status == "PARTIAL" and final.reasons == ["RECORD_BUDGET_EXCEEDED"] and len(records) == 5
    assert next(r for r in records if r["record_type"] == "operation_report")["proves_completeness"] is True
    records, final = run(spec(max_records=7), Org(PAGES))
    assert final.status == "COMPLETE" and len(records) == 7


def test_a_next_link_to_another_host_is_refused_and_the_listing_is_partial():
    pages = dict(PAGES)
    pages[""] = httpx.Response(200, json=[row("00uactive01", "ACTIVE")],
                               headers={"link": '<https://evil.example/api/v1/users?after=x>; rel="next"'})
    records, final = run(spec(), Org(pages))
    assert final.status == "FAILED" and "OKTA_INVALID_CURSOR" in final.reasons
    report = next(r for r in records if r["record_type"] == "operation_report")
    assert report["proves_completeness"] is False


SLACK = {"id": "0oaslack00001", "name": "slack", "label": "Slack", "status": "ACTIVE", "signOnMode": "SAML_2_0",
         "credentials": {"signing": {"kid": "kid-1"}, "userNameTemplate": {"template": "${source.email}"}},
         "settings": {"app": {"optionalField1Value": "kept-nowhere-1"}}}
AWS = {"id": "0oaaws000001", "name": "amazon_aws", "label": "AWS Prod", "status": "ACTIVE", "signOnMode": "SAML_2_0",
       "credentials": {"oauthClient": {"client_id": "kept-nowhere-2"}}}
UNLABELLED = {"id": "0oabookmark1", "name": "bookmark", "label": "", "status": "ACTIVE"}
OLD = {"id": "0oaold000001", "name": "github_enterprise_cloud", "label": "Old GitHub", "status": "INACTIVE"}
ACTIVE, INACTIVE = 'status eq "ACTIVE"', 'status eq "INACTIVE"'
APP_PAGES = {(ACTIVE, ""): httpx.Response(200, json=[SLACK, AWS],
                                          headers={"link": f'<{ORIGIN}/api/v1/apps?after=a2&limit=2>; rel="next"'}),
             (ACTIVE, "a2"): httpx.Response(200, json=[UNLABELLED]),
             (INACTIVE, ""): httpx.Response(200, json=[OLD])}
APPS_SPEC = {"options": {"page_size": 2, "sources": ["apps"]}}


def apps_org(pages=None, seen=None):
    """A synthetic Okta org answering the app list's token request and its Apps API pages."""
    pages = APP_PAGES if pages is None else pages

    def org(request):
        if seen is not None:
            seen.append(request)
        if request.url.path == "/oauth2/v1/token":  # a token holding only the app list's scope
            assert parse_qs(request.content.decode())["scope"] == ["okta.apps.read"]
            return httpx.Response(200, json={"access_token": "t0k3n.apps", "token_type": "Bearer", "expires_in": 3600})
        assert request.url.path == "/api/v1/apps"
        query = parse_qs(urlsplit(str(request.url)).query)
        return pages[(query["filter"][0], query.get("after", [""])[0])]
    return org


def test_the_app_list_is_a_collection_of_its_own_and_keeps_only_names_and_status():
    seen = []
    connection = spec(**APPS_SPEC)
    records, final = run(connection, apps_org(seen=seen))
    assert final.status == "COMPLETE"
    apps = {r["identity"]["object_id"]: (r["identity"]["kind"], r["normalized_state"],
                                         {fact["name"]: fact["value"] for fact in r["facts"]})
            for r in records if r["record_type"] == "entity_observation"}
    assert apps == {"app:0oaslack00001": ("installation", "ACTIVE", {"display_name": "Slack", "app_slug": "slack"}),
                    "app:0oaaws000001": ("installation", "ACTIVE", {"display_name": "AWS Prod", "app_slug": "amazon_aws"}),
                    "app:0oaold000001": ("installation", "DISABLED",
                                         {"display_name": "Old GitHub", "app_slug": "github_enterprise_cloud"})}
    # An app's credentials and settings are never read out of its row; an app without a label is no service.
    assert "kept-nowhere" not in json.dumps(records) and "userNameTemplate" not in json.dumps(records)
    # The people listing is the other collection's; nothing here can make it partial.
    reports = {r["provenance"]["operation"]: (r["status"], r["proves_completeness"])
               for r in records if r["record_type"] == "operation_report"}
    assert reports == {"okta.users": ("NOT_REQUESTED", False), "okta.apps": ("COMPLETE", False),
                       "okta.inactive_apps": ("COMPLETE", False)}
    for item in records:
        assert adapter.validate_record(connection, RECORD_ADAPTER.validate_python(item))
    # The scope also opens the client secrets endpoint, which is never called.
    assert not any("/credentials" in request.url.path for request in seen)


@pytest.mark.parametrize("link", [f"{ORIGIN}/api/v1/users?after=u2", f"{ORIGIN}/api/v1/apps/0oaslack00001?after=a2",
                                  "https://evil.example/api/v1/apps?after=a2"])
def test_an_app_list_next_link_off_its_own_listing_is_refused(link):
    pages = {**APP_PAGES, (ACTIVE, ""): httpx.Response(200, json=[SLACK], headers={"link": f'<{link}>; rel="next"'})}
    records, final = run(spec(**APPS_SPEC), apps_org(pages))
    assert final.status == "PARTIAL" and "OKTA_INVALID_CURSOR" in final.reasons
    assert not any(record.get("identity", {}).get("object_id", "").startswith("user:") for record in records)


@pytest.mark.parametrize("overrides, code", [
    ({"auth_type": "bearer", "secret_refs": {"token": "vault://okta/t"}}, "OKTA_SERVICE_APP_PRIVATE_KEY_JWT_REQUIRED"),
    ({"tenant": "other.okta.com"}, "OKTA_TENANT_IS_THE_ORG_HOST"),
    ({"scopes": [{"kind": "organization", "id": "other.okta.com"}]}, "OKTA_ONE_ORGANIZATION_SCOPE"),
    ({"capabilities": ["inventory"]}, "IDENTITY_STATUS_CAPABILITY_REQUIRED"),
    ({"options": {"sources": ["users"]}}, "OKTA_COLLECTION_OPTION_NOT_SUPPORTED"),
    ({"options": {"sources": ["apps"], "keep_profiles": True}}, "OKTA_COLLECTION_OPTION_NOT_SUPPORTED"),
])
def test_the_spec_is_refused_outside_a_least_privilege_service_app(overrides, code):
    with pytest.raises(ValueError, match=code):
        adapter.validate_spec(spec(**overrides))


def test_collection_refuses_to_start_without_the_identity_key():
    with pytest.raises(ValueError, match="IDENTITY_KEY_UNAVAILABLE"):
        next(adapter.collect_pages(spec(), secrets=SECRETS, checkpoint={}, check=lambda: None))
