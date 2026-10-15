"""Google Workspace users through the shared identity collector, against a synthetic Google: a service account's
delegated token (the key file's own token address is never used) and the Directory API's user and deleted-user
listings."""

import json
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cremore.coverage.metadata_models import RECORD_ADAPTER, MetadataConnectionSpec
from cremore.identity.idp import ReadError
from cremore.identity.keys import Digester
from cremore_gcp_provider.workspace import adapter, identity, onboarding

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PEM = KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption()).decode()
ACCOUNT = "cremore-directory@acme-idp.iam.gserviceaccount.com"
KEY_FILE = json.dumps({"type": "service_account", "project_id": "acme-idp", "private_key_id": "a" * 40,
                       "private_key": PEM, "client_email": ACCOUNT, "client_id": "112233445566778899001",
                       "token_uri": "https://token.attacker.test/token"})  # never used
SECRETS = {"private_key": KEY_FILE, "username": "admin@acme.com"}
DIGEST = Digester(b"k" * 32)


def spec(**overrides):
    body = {"name": "Google Workspace", "provider": "google_workspace", "origin": identity.ORIGIN, "edition": "cloud",
            "tenant": "acme.com", "tenant_confirmed": True, "scopes": [{"kind": "organization", "id": "acme.com"}],
            "capabilities": ["identity_status"], "auth_type": "private_key_jwt",
            "secret_refs": {"private_key": "vault://gws/key", "username": "vault://gws/key"}, "options": {"page_size": 3}}
    body.update(overrides)
    return MetadataConnectionSpec.model_validate(body)


def person(number, **fields):
    return {"id": f"1000000000000000000{number:02d}", "primaryEmail": f"user{number}@acme.com", **fields}


PAGES = {
    ("", False): {"users": [person(1, name={"fullName": "김개발"}, aliases=["dev@acme.com"],
                                   organizations=[{"primary": True, "department": "플랫폼", "title": "엔지니어"}]),
                            person(2, suspended=True), person(3, archived=True)], "nextPageToken": "p2"},
    ("p2", False): {"users": [person(4)]},
    ("", True): {"users": [person(5, deletionTime="2026-09-20T08:00:00.000Z")]},
}


class Google:
    """The token endpoint and the Directory API, as the delegated service account sees them."""

    def __init__(self, token_error=None, *, admin=True, refuse=None):
        self.token_error, self.admin, self.refuse, self.seen = token_error, admin, refuse or {}, []

    def __call__(self, request):
        self.seen.append(str(request.url))
        if request.url.host == "oauth2.googleapis.com":
            form = parse_qs(request.content.decode())
            assert form["grant_type"] == ["urn:ietf:params:oauth:grant-type:jwt-bearer"]
            claims = jwt.decode(form["assertion"][0], KEY.public_key(), algorithms=["RS256"], audience=identity.TOKEN_URL)
            assert (claims["iss"], claims["sub"], claims["scope"]) == (ACCOUNT, "admin@acme.com", identity.SCOPE)
            assert jwt.get_unverified_header(form["assertion"][0])["kid"] == "a" * 40
            assert claims["exp"] - claims["iat"] <= 300
            if self.token_error == "infinite_lifetime":
                return httpx.Response(200, content=b'{"access_token": "ya29.synthetic", "expires_in": 1e999}',
                                      headers={"Content-Type": "application/json"})
            if self.token_error:
                return httpx.Response(400, json={"error": self.token_error, "error_description": "Client is unauthorized"})
            return httpx.Response(200, json={"access_token": "ya29.synthetic", "token_type": "Bearer", "expires_in": 3599})
        assert str(request.url).startswith(identity.USERS_URL) and request.headers["Authorization"] == "Bearer ya29.synthetic"
        query = parse_qs(urlsplit(str(request.url)).query)
        if request.url.path == "/admin/directory/v1/users/admin@acme.com":
            assert query == {"fields": ["isAdmin"]}
            return httpx.Response(200, json={"isAdmin": self.admin})
        listing = "deleted_users" if query.get("showDeleted") == ["true"] else "users"
        if listing in self.refuse:
            return httpx.Response(self.refuse[listing][0], json=self.refuse[listing][1])
        assert query["customer"] == ["my_customer"] and query["projection"] == ["basic"]
        return httpx.Response(200, json=PAGES[(query.get("pageToken", [""])[0], listing == "deleted_users")])


def run(connection, google, *, secrets=SECRETS):
    client = httpx.Client(transport=httpx.MockTransport(google))
    records = []
    final = None
    for page in adapter.collect_pages(connection, secrets=secrets, checkpoint={}, check=lambda: None, read_records=None,
                                      identity_digest=DIGEST, client=client, sleep=lambda _s: None):
        records.extend(item.model_dump() for item in page.records)
        final = page
    return records, final


def test_every_user_is_listed_with_its_status_and_only_digests_leave_the_collector():
    google = Google()
    records, final = run(spec(), google)
    assert final.status == "COMPLETE"
    assert not any("attacker" in url for url in google.seen)  # the key file's token address is not used
    listings = [url for url in google.seen if url.startswith(identity.USERS_URL + "?")]
    assert "showDeleted=true" in listings[0] and "showDeleted" not in listings[1]  # deletions are read first
    assert sum("/users/admin@acme.com?" in url for url in google.seen) == 1  # super administrator, asked once
    users = {r["identity"]["object_id"]: r for r in records if r["record_type"] == "entity_observation"}
    assert {k: (v["provider_state"], v["normalized_state"]) for k, v in users.items()} == {
        "user:100000000000000000001": ("ACTIVE", "ACTIVE"), "user:100000000000000000002": ("SUSPENDED", "DISABLED"),
        "user:100000000000000000003": ("ARCHIVED", "DISABLED"), "user:100000000000000000004": ("ACTIVE", "ACTIVE"),
        "user:100000000000000000005": ("DELETED", "DELETED")}
    assert users["user:100000000000000000005"]["effective_at"] == "2026-09-20T08:00:00+00:00"
    first = users["user:100000000000000000001"]
    assert {(k["kind"], k["digest"]) for k in first["identity_keys"]} == {
        ("IDP_USER_ID", DIGEST("100000000000000000001")), ("EMAIL", DIGEST("user1@acme.com")),
        ("EMAIL", DIGEST("dev@acme.com"))}
    assert "@acme.com" not in json.dumps(records) and "김개발" not in json.dumps(records)  # no profiles unless asked
    reports = [r for r in records if r["record_type"] == "operation_report"]
    assert any(r["proves_completeness"] for r in reports)
    for item in records:
        assert adapter.validate_record(spec(), RECORD_ADAPTER.validate_python(item))
        assert not adapter.validate_machine_record(spec(), RECORD_ADAPTER.validate_python(item))


def test_people_details_are_kept_only_when_asked():
    records, _final = run(spec(options={"page_size": 3, "keep_profiles": True}), Google())
    first = next(r for r in records if r.get("identity", {}).get("object_id") == "user:100000000000000000001")
    facts = {fact["name"]: fact["value"] for fact in first["facts"]}
    assert facts == {"display_name": "김개발", "email": "user1@acme.com", "department": "플랫폼", "title": "엔지니어"}


def test_an_administrator_who_is_not_a_super_administrator_lists_nobody():
    # Limited to some organizational units, its complete listing would make everyone else look gone.
    google = Google(admin=False)
    records, final = run(spec(), google)
    assert final.status == "FAILED" and "GOOGLE_WORKSPACE_ADMIN_NOT_SUPER_ADMIN" in final.reasons
    assert not [r for r in records if r["record_type"] == "entity_observation"]
    assert not any(r.get("proves_completeness") for r in records)
    assert sum("/users/admin@acme.com?" in url for url in google.seen) == 1
    assert not [url for url in google.seen if url.startswith(identity.USERS_URL + "?")]


def test_a_record_budget_met_inside_the_full_listing_still_leaves_the_deletions_read():
    records, final = run(spec(max_records=4), Google())
    assert final.status == "PARTIAL" and "RECORD_BUDGET_EXCEEDED" in final.reasons
    users = {r["identity"]["object_id"]: r["normalized_state"] for r in records if r["record_type"] == "entity_observation"}
    assert users == {"user:100000000000000000005": "DELETED"}
    assert not any(r.get("proves_completeness") for r in records)


FORBIDDEN = {"error": {"code": 403, "message": "Not Authorized to access this resource/api",
                       "errors": [{"reason": "forbidden"}]}}


@pytest.mark.parametrize(("status", "body", "code", "retryable"), [
    (403, {"error": {"code": 403, "errors": [{"domain": "usageLimits", "reason": "userRateLimitExceeded"}]}},
     "GOOGLE_WORKSPACE_RATE_LIMITED", True),
    (403, {"error": {"code": 403, "errors": [{"reason": "quotaExceeded"}]}}, "GOOGLE_WORKSPACE_RATE_LIMITED", True),
    (429, {"error": {"code": 429, "errors": [{"reason": "rateLimitExceeded"}]}}, "GOOGLE_WORKSPACE_RATE_LIMITED", True),
    (403, {"error": {"code": 403, "status": "PERMISSION_DENIED", "errors": [{"reason": "accessNotConfigured"}],
                     "details": [{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "SERVICE_DISABLED"}]}},
     "GOOGLE_WORKSPACE_API_NOT_ENABLED", False),
    (403, FORBIDDEN, "GOOGLE_WORKSPACE_ACCESS_DENIED", False),
    (403, {"error": {"errors": "userRateLimitExceeded"}}, "GOOGLE_WORKSPACE_ACCESS_DENIED", False),
])
def test_google_403s_are_told_apart_by_their_reason(status, body, code, retryable):
    from cremore.identity.idp import Pacer

    connection = spec()
    read = identity.reader(connection, SECRETS, httpx.Client(transport=httpx.MockTransport(
        Google(refuse={"users": (status, body)}))), Pacer(connection, lambda: None))
    with pytest.raises(ReadError) as refused:
        read.read(connection.scopes[0], "users", None)
    assert (refused.value.code, refused.value.retryable) == (code, retryable)


@pytest.mark.parametrize(("secrets", "error", "code"), [
    (SECRETS, "unauthorized_client", "GOOGLE_WORKSPACE_DELEGATION_NOT_ALLOWED"),
    (SECRETS, "access_denied", "GOOGLE_WORKSPACE_DELEGATION_NOT_ALLOWED"),
    (SECRETS, "invalid_grant", "GOOGLE_WORKSPACE_TOKEN_REFUSED"),
    ({**SECRETS, "private_key": KEY_FILE.replace("service_account", "authorized_user")}, None, "GOOGLE_WORKSPACE_KEY_INVALID"),
    ({**SECRETS, "private_key": "{not json"}, None, "GOOGLE_WORKSPACE_KEY_INVALID"),
    ({**SECRETS, "private_key": "[" * 16000}, None, "GOOGLE_WORKSPACE_KEY_INVALID"),
    (SECRETS, "infinite_lifetime", "GOOGLE_WORKSPACE_TOKEN_REFUSED"),
    ({**SECRETS, "username": "admin"}, None, "GOOGLE_WORKSPACE_ADMIN_INVALID"),
    ({**SECRETS, "username": "admin@other-corp.example"}, None, "GOOGLE_WORKSPACE_ADMIN_OUTSIDE_DOMAIN"),
])
def test_a_refused_or_broken_sign_in_is_a_code(secrets, error, code):
    from cremore.identity.idp import Pacer

    connection = spec()
    read = identity.reader(connection, secrets, httpx.Client(transport=httpx.MockTransport(Google(error))),
                           Pacer(connection, lambda: None))
    with pytest.raises(ReadError) as refused:
        read.read(connection.scopes[0], "users", None)
    assert refused.value.code == code


@pytest.mark.parametrize("change", [
    {"origin": "https://admin.googleapis.com.attacker.test"}, {"scopes": [{"kind": "organization", "id": "acme"}]},
    {"tenant": "other.com"}, {"auth_type": "oauth_client", "secret_refs": {"client_id": "vault://x", "client_secret": "vault://y"}},
    {"options": {"page_size": 501}},
])
def test_a_collection_is_one_domain_through_the_admin_api(change):
    with pytest.raises(ValueError):
        adapter.validate_spec(spec(**change))


def test_the_wizard_names_the_domain_checks_the_key_and_says_which_client_to_allow():
    assert onboarding.target("google_workspace", "cloud", {"domain": " https://ACME.com/ "}) == {"domain": "acme.com"}
    for values in ({"domain": "acme"}, {"domain": "acme.com/path"}):
        with pytest.raises(onboarding.OnboardingValueError):
            onboarding.target("google_workspace", "cloud", values)
    assert onboarding.credential("google_workspace", "service_account_delegation",
                                 {"username": " admin@ACME.com ", "private_key": KEY_FILE}) == {
        "credential": {"private_key": KEY_FILE, "username": "admin@acme.com"}}
    with pytest.raises(onboarding.OnboardingValueError) as refused:
        onboarding.credential("google_workspace", "service_account_delegation", {"username": "admin@acme.com", "private_key": PEM})
    assert refused.value.code == "GOOGLE_WORKSPACE_KEY_INVALID"

    class Context:
        def __init__(self, google):
            self.google = google

        def http_client(self):
            return httpx.Client(transport=httpx.MockTransport(self.google))

    connection = {"target": {"domain": "acme.com"}}
    envelope = {"credential": SECRETS}
    assert onboarding.check(connection, "identity", envelope, Context(Google())) == [{"permission": "users_read", "status": "GRANTED"}]
    assert onboarding.check(connection, "identity", envelope, Context(Google("unauthorized_client"))) == [
        {"permission": "users_read", "status": "MISSING", "detail": "GOOGLE_WORKSPACE_DELEGATION_NOT_ALLOWED",
         "subject": "112233445566778899001"}]
    assert onboarding.check(connection, "identity", envelope, Context(Google(admin=False))) == [
        {"permission": "users_read", "status": "MISSING", "detail": "GOOGLE_WORKSPACE_ADMIN_NOT_SUPER_ADMIN"}]
    # A collection reads the deletions too: the check answers for both listings.
    assert onboarding.check(connection, "identity", envelope, Context(Google(refuse={"deleted_users": (403, FORBIDDEN)}))) == [
        {"permission": "users_read", "status": "MISSING", "detail": "GOOGLE_WORKSPACE_ACCESS_DENIED"}]
    [child] = onboarding.children(connection, "identity", {"schedule_minutes": 120, "people_details": True})
    made = MetadataConnectionSpec.model_validate({**child["spec"], "secret_refs": {
        "private_key": "vault://x", "username": "vault://x"}})
    adapter.validate_spec(made)
    assert made.options.keep_profiles is True and child["secret_slots"] == {"private_key": "credential", "username": "credential"}
    assert made.max_records == identity.MAX_RECORDS == 250000  # a large directory still completes


def groups_google(seen, pages):
    """The token endpoint and the Members API, as the delegated service account sees them for the role groups."""

    def handler(request):
        seen.append(request)
        if request.url.host == "oauth2.googleapis.com":
            claims = jwt.decode(parse_qs(request.content.decode())["assertion"][0], KEY.public_key(), algorithms=["RS256"],
                                audience=identity.TOKEN_URL)
            assert claims["scope"] == identity.GROUP_SCOPE  # a token of its own, with the group member scope alone
            return httpx.Response(200, json={"access_token": "ya29.groups", "token_type": "Bearer", "expires_in": 3599})
        query = parse_qs(urlsplit(str(request.url)).query)
        assert query["includeDerivedMembership"] == ["true"] and request.headers["Authorization"] == "Bearer ya29.groups"
        return pages[(request.url.path, query.get("pageToken", [""])[0])]
    return handler


def test_the_role_groups_name_their_people_nested_groups_included_and_nothing_else():
    members = "/admin/directory/v1/groups/cremore-admins@acme.com/members"
    pages = {(members, ""): httpx.Response(200, json={"members": [
                {"email": "dana@acme.com", "type": "USER"}, {"email": "security@acme.com", "type": "GROUP"},
                {"email": "CUSTOMER", "type": "CUSTOMER"}], "nextPageToken": "m2"}),
             (members, "m2"): httpx.Response(200, json={"members": [{"email": "eve@acme.com", "type": "USER"}]}),
             ("/admin/directory/v1/groups/nobody@acme.com/members", ""): httpx.Response(404, json={})}
    seen = []
    client = httpx.Client(transport=httpx.MockTransport(groups_google(seen, pages)))
    connection = {"target": {"domain": "acme.com"}}
    found = onboarding.role_group_members(connection, {"credential": SECRETS}, client, ["cremore-admins@acme.com"])
    assert found == {"cremore-admins@acme.com": ["dana@acme.com", "eve@acme.com"]}
    assert not any("/users" in request.url.path for request in seen)  # nothing of the people listing is asked
    with pytest.raises(ReadError) as missing:
        onboarding.role_group_members(connection, {"credential": SECRETS}, client, ["nobody@acme.com"])
    assert missing.value.code == "GOOGLE_WORKSPACE_HTTP_404"
    reader = identity.Reader(spec(), SECRETS, client, None)
    with pytest.raises(ValueError, match="OUT_OF_SCOPE"):
        reader.group_members("cremore-admins@acme.com")  # a people reader's token never lists groups