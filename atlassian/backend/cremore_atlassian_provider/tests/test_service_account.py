"""A Confluence Cloud service account's OAuth client against a synthetic Atlassian: the token comes from
auth.atlassian.com, every read goes to the api.atlassian.com gateway for the site's cloud ID, and the site
itself is asked only for that ID, without a credential."""

import datetime as _dt
from urllib.parse import parse_qs

import httpx
import pytest

from cremore.collectors.base import CollectorError, RequestBudget, RequestBudgetExceeded
from cremore.onboarding import catalog
from cremore.onboarding.check import clean
from cremore.secretstore.resolver import SecretRefError, inject_secret
from cremore_atlassian_provider import cloud_api, confluence_content, onboarding
from cremore_atlassian_provider.confluence_changes import changes_since_batch
from cremore_atlassian_provider.confluence_context import read

CLOUD = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
GATEWAY = f"/ex/confluence/{CLOUD}/wiki"
CLIENT_ID = "SyntheticClient0001"
# Built at run time: a secret-shaped literal never sits in the source.
SECRET = "".join(["ATOA", "synthetic", "-" * 4, "0" * 24])
TOKEN = "synthetic-access-token-" + "1" * 16
CREDENTIAL = {"auth_kind": "atlassian_oauth", "client_id": CLIENT_ID, "client_secret": SECRET}
PAYLOAD = {"edition": "cloud", "base_url": "https://acme.atlassian.net/wiki", "space": "98765", "provider": "confluence"}


def forget():
    """A new worker process: no cloud ID, token or refusal remembered."""
    for name in ("_CLOUD_IDS", "_TOKENS", "_FAILED"):
        getattr(cloud_api, name).clear()


@pytest.fixture(autouse=True)
def fresh_process(monkeypatch):
    for name in ("_CLOUD_IDS", "_TOKENS", "_FAILED"):
        monkeypatch.setattr(cloud_api, name, {})
    # The download's redirect target resolves to a public address (a hop off the site is pinned to it).
    monkeypatch.setattr(confluence_content, "_resolve", lambda host, _port: {"93.184.216.34"}
                        if host == "media.example.test" else pytest.fail(f"unexpected lookup of {host}"))


def atlassian(seen, *, tenant=200, token=200, space=200, pages=200, scopes=cloud_api.SCOPES):
    def handler(request):
        seen.append(request)
        host, path = request.headers["host"], request.url.path  # a pinned hop dials the address, names the host
        if host == "auth.atlassian.com":
            assert request.method == "POST" and path == "/oauth/token"
            form = parse_qs(request.content.decode())
            assert form == {"grant_type": ["client_credentials"], "client_id": [CLIENT_ID], "client_secret": [SECRET]}
            return httpx.Response(token, json={"access_token": TOKEN, "expires_in": 3600, "token_type": "Bearer"})
        if host == "acme.atlassian.net":
            assert path == "/_edge/tenant_info" and "authorization" not in request.headers
            return httpx.Response(tenant, json={"cloudId": CLOUD})
        if host == "media.example.test":  # where the download redirects: the bytes, for no token
            assert path == "/file/att7" and "authorization" not in request.headers
            return httpx.Response(200, content=b"synthetic attachment")
        assert host == "api.atlassian.com" and path.startswith(GATEWAY), request.url
        assert request.headers["authorization"] == "Bearer " + TOKEN
        route = path[len(GATEWAY):]
        need = {"/api/v2/spaces/98765": "read:space:confluence", "/api/v2/spaces/98765/pages": "read:page:confluence",
                "/api/v2/pages/123": "read:page:confluence", "/api/v2/pages/123/attachments": "read:attachment:confluence",
                "/rest/api/content/123/child/attachment/att7/download": "read:attachment:confluence",
                "/api/v2/attachments/att7": "read:attachment:confluence",
                "/rest/api/content/search": "read:content-details:confluence",
                "/rest/api/user": "read:content-details:confluence"}.get(route)
        if need is None:
            return httpx.Response(404)
        if need not in scopes:
            return httpx.Response(401, json={"message": "Unauthorized; scope does not match"})
        if route == "/api/v2/spaces/98765":
            return httpx.Response(space, json={"id": "98765", "key": "ENG"})
        if route == "/api/v2/spaces/98765/pages":
            return httpx.Response(pages, json={"results": [{"id": "123"}]})
        if route == "/api/v2/pages/123":
            return httpx.Response(200, json={"id": "123", "spaceId": "98765", "version": {
                "number": 4, "authorId": "712020:author", "createdAt": "2026-09-28T00:00:00.000Z"},
                "body": {"storage": {"value": "<p>release notes</p>"}}})
        if route == "/api/v2/pages/123/attachments":
            return httpx.Response(200, json={"results": [{"id": "att7", "version": {"number": 1},
                                                          "downloadLink": "/download/attachments/123/notes.txt"}]})
        if route == "/rest/api/content/123/child/attachment/att7/download":
            assert request.url.params["version"] == "1"
            return httpx.Response(302, headers={"location": "https://media.example.test/file/att7"})
        if route == "/api/v2/attachments/att7":
            return httpx.Response(200, json={"id": "att7", "pageId": "123", "version": {"authorId": "712020:author"}})
        if route == "/rest/api/content/search":
            assert "space" not in request.url.params["cql"] or 'space = "ENG"' in request.url.params["cql"]
            return httpx.Response(200, json={"results": [{"id": "123", "version": {"number": 5}}]})
        return httpx.Response(200, json={"accountId": "712020:author", "displayName": "Synthetic Author"})
    return httpx.Client(transport=httpx.MockTransport(handler))


def scan_payload(seen, **extra):
    client = atlassian(seen, **extra)
    return {**PAYLOAD, "token": cloud_api.ContentToken(CREDENTIAL, client=client)}, client


def grants(seen):
    return sum(request.url.host == "auth.atlassian.com" for request in seen)


def test_the_credential_is_the_client_and_its_secret_only():
    assert onboarding.credential("confluence", "service_account", {"client_id": f" {CLIENT_ID} ", "client_secret": SECRET}) \
        == {"credential": CREDENTIAL}
    for fields in ({"client_id": "short", "client_secret": SECRET}, {"client_id": CLIENT_ID, "client_secret": "x"},
                   {"client_id": "bad id with spaces", "client_secret": SECRET}):
        with pytest.raises(ValueError, match="ATLASSIAN_OAUTH_CLIENT_INVALID"):
            onboarding.credential("confluence", "service_account", fields)


def test_one_token_serves_every_task_of_the_process():
    seen = []
    client = atlassian(seen)
    first, second = cloud_api.ClientToken(CREDENTIAL, client=client), cloud_api.ContentToken(CREDENTIAL, client=client)
    assert first.stale() and first() == TOKEN and second() == TOKEN and not second.stale()
    assert grants(seen) == 1


def test_concurrent_scan_readers_ask_for_one_grant():
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    seen, lock = [], threading.Lock()

    def slow(request):
        assert request.url.host == "auth.atlassian.com" and request.url.path == "/oauth/token"
        with lock:
            seen.append(request)
        time.sleep(0.05)  # the other readers arrive while this one waits on Atlassian
        return httpx.Response(200, json={"access_token": TOKEN, "expires_in": 3600, "token_type": "Bearer"})

    token = cloud_api.ContentToken(CREDENTIAL, client=httpx.Client(transport=httpx.MockTransport(slow)))
    with ThreadPoolExecutor(8) as pool:
        assert list(pool.map(lambda _: token(), range(8))) == [TOKEN] * 8
    assert grants(seen) == 1


def test_a_refusal_or_an_outage_is_its_own_code_and_waits_a_minute():
    seen = []
    refused = cloud_api.ClientToken(CREDENTIAL, client=atlassian(seen, token=401))
    for _attempt in range(3):
        with pytest.raises(cloud_api.CloudError) as caught:
            refused()
        assert caught.value.code == "ATLASSIAN_OAUTH_TOKEN_REFUSED" and SECRET not in repr(caught.value)
    assert grants(seen) == 1  # Atlassian is asked again only after the minute
    forget()
    busy = cloud_api.ClientToken(CREDENTIAL, client=atlassian([], token=503))
    with pytest.raises(cloud_api.CloudError, match="ATLASSIAN_OAUTH_UNAVAILABLE"):
        busy()


def test_the_gateway_address_keeps_the_site_path_and_only_a_confluence_gateway_address_is_kept():
    seen = []
    client = atlassian(seen)
    assert cloud_api.api_site("https://acme.atlassian.net/wiki", client) == "https://api.atlassian.com" + GATEWAY
    assert cloud_api.api_site("https://acme.atlassian.net/wiki", client) == "https://api.atlassian.com" + GATEWAY
    assert len(seen) == 1  # the cloud ID is asked once per site
    given = "https://api.atlassian.com" + GATEWAY
    assert cloud_api.api_site(given, client) == given
    for other in (f"https://api.atlassian.com/ex/jira/{CLOUD}/wiki", "https://api.atlassian.com:8443" + GATEWAY):
        with pytest.raises(cloud_api.CloudError, match="CONFLUENCE_GATEWAY_ADDRESS_INVALID"):
            cloud_api.api_site(other, client)
    forget()
    with pytest.raises(cloud_api.CloudError, match="CONFLUENCE_CLOUD_ID_UNAVAILABLE"):
        cloud_api.api_site("https://acme.atlassian.net/wiki", atlassian([], tenant=404))


def test_a_spent_budget_is_a_budget_stop_not_a_missing_cloud_id():
    budget = RequestBudget(1)
    budget.consume()
    with pytest.raises(RequestBudgetExceeded):
        cloud_api.api_site("https://acme.atlassian.net/wiki", atlassian([]), budget)
    # The cloud ID, the token grant and the read are three requests of the scan's budget.
    payload, client = scan_payload([])
    http = confluence_content.SourceHTTP(payload, client, budget=RequestBudget(2))
    with pytest.raises(RequestBudgetExceeded):
        http.get("/spaces/98765")
    forget()
    http = confluence_content.SourceHTTP(payload, client, budget=RequestBudget(3))
    assert http.get("/spaces/98765")[0]["id"] == "98765" and http.budget.used == 3
    # Once both are known the process asks for neither again.
    http = confluence_content.SourceHTTP(payload, client, budget=RequestBudget(3))
    assert http.get("/spaces/98765")[0]["id"] == "98765" and http.budget.used == 1


def test_a_scan_reads_the_page_and_its_attachment_through_the_gateway_only():
    seen = []
    payload, client = scan_payload(seen)
    collector = confluence_content.build(payload, client)
    objects = {item.resource.location: item for item in collector.collect()}
    assert set(objects) == {"body", "attachments/att7"}
    assert objects["attachments/att7"].read() == b"synthetic attachment"
    assert {request.headers["host"] for request in seen} == {"auth.atlassian.com", "acme.atlassian.net",
                                                              "api.atlassian.com", "media.example.test"}
    assert next(r for r in seen if r.headers["host"] == "media.example.test").url.host == "93.184.216.34"
    # The site is asked only for its cloud ID and the download's redirect target gets no token: the access
    # token goes to the gateway alone.
    assert all("authorization" not in r.headers for r in seen if r.headers["host"] != "api.atlassian.com")
    assert grants(seen) == 1


def test_the_change_feed_and_the_author_go_through_the_gateway():
    seen = []
    payload, client = scan_payload(seen)
    state = {"cursor": "v4", "checked_at": _dt.datetime.now(_dt.UTC) - _dt.timedelta(minutes=10)}
    root = {"resource_id": "r1", "provider_resource_id": "123"}
    changes = changes_since_batch(payload, [root], {"r1": state}, http_client=lambda: client, request_budget=None)
    assert changes["r1"].reason == "CONFLUENCE_PAGE_MODIFIED"
    forget()  # a fresh process: the author lookup also asks for the cloud ID and a token, within its budget
    found = read(payload, {"repository": "123", "path": "attachments/att7"}, http_client=client)
    assert found["author"]["name"] == "Synthetic Author"
    assert {r.url.path for r in seen if r.url.host == "api.atlassian.com"} >= {
        GATEWAY + "/rest/api/content/search", GATEWAY + "/rest/api/user"}


def test_a_missing_cloud_id_or_token_stops_the_scan_with_its_code():
    payload, client = scan_payload([], tenant=404)
    with pytest.raises(CollectorError) as caught:
        list(confluence_content.build(payload, client).collect())
    assert caught.value.code == "CONFLUENCE_CLOUD_ID_UNAVAILABLE"
    payload, client = scan_payload([], token=400)
    with pytest.raises(CollectorError) as caught:
        list(confluence_content.build(payload, client).collect())
    assert caught.value.code == "ATLASSIAN_OAUTH_TOKEN_REFUSED"


def test_the_resolver_gives_the_sealed_client_to_confluence_only(monkeypatch):
    def no_real_client(*args, **kwargs):
        raise AssertionError("a test must not reach Atlassian")

    monkeypatch.setattr(httpx, "Client", no_real_client)

    class Resolver:
        def resolve(self, ref):
            return dict(CREDENTIAL)

    merged = inject_secret("confluence", {**PAYLOAD, "secret_ref": "vault://onboarding/x"}, Resolver())
    assert isinstance(merged["token"], cloud_api.ContentToken) and merged["token"].gateway
    # Another source's reference that resolves to this envelope would send the token to that source's host.
    with pytest.raises(SecretRefError, match="ATLASSIAN_OAUTH_NOT_FOR_THIS_SOURCE"):
        inject_secret("bitbucket", {"provider": "bitbucket", "workspace": "acme", "secret_ref": "vault://kv/x"}, Resolver())
    broken = type("Broken", (), {"resolve": lambda self, ref: {**CREDENTIAL, "client_id": "no"}})()
    with pytest.raises(SecretRefError, match="ATLASSIAN_OAUTH_CLIENT_INVALID"):
        inject_secret("confluence", {**PAYLOAD, "secret_ref": "vault://onboarding/x"}, broken)


def check(target=None, **answers):
    forget()
    seen = []
    ctx = type("Context", (), {"http_client": staticmethod(lambda: atlassian(seen, **answers)), "memo": {}})()
    target = target or {"base_url": PAYLOAD["base_url"], "space": "98765"}
    connection = {"provider": "confluence", "edition": "cloud", "auth_method": "service_account", "target": target,
                  "purposes": ["exposure"]}
    items = onboarding.check(connection, "exposure", {"credential": dict(CREDENTIAL)}, ctx)
    items = clean(items, catalog.permissions_for("confluence", "exposure", "service_account", target))
    return {item["permission"]: (item["status"], item.get("detail")) for item in items}, seen


def test_the_check_asks_each_scope_through_the_gateway():
    status, seen = check()
    assert status == {scope: ("GRANTED", None) for scope in cloud_api.SCOPES}
    assert {r.url.host for r in seen} == {"auth.atlassian.com", "acme.atlassian.net", "api.atlassian.com"}
    status, _seen = check(scopes=("read:space:confluence", "read:page:confluence"))
    assert status["read:attachment:confluence"] == ("MISSING", "HTTP_401")
    assert status["read:content-details:confluence"] == ("MISSING", "HTTP_401")
    status, _seen = check(space=404)
    assert status["read:space:confluence"] == ("MISSING", "CONFLUENCE_SPACE_NOT_VISIBLE")
    status, _seen = check(pages=403)
    assert status["read:attachment:confluence"] == ("NOT_REPORTED", "NOT_CHECKED")
    status, _seen = check(target={"space": "98765"})
    assert set(status.values()) == {("ERROR", "TARGET_INCOMPLETE")}
    with pytest.raises(ValueError, match="ATLASSIAN_OAUTH_TOKEN_REFUSED"):
        check(token=401)
    with pytest.raises(ValueError, match="ATLASSIAN_OAUTH_UNAVAILABLE"):
        check(token=502)


def test_the_token_method_keeps_its_own_permissions_and_address():
    assert [p["id"] for p in catalog.permissions_for("confluence", "exposure", "token")] == ["read_space", "read_content"]
    assert [p["id"] for p in catalog.permissions_for("confluence", "exposure", "service_account")] == list(cloud_api.SCOPES)
    methods = {m["id"]: m for m in catalog.descriptor("confluence")["auth_methods"]}
    assert methods["service_account"]["editions"] == ["cloud"] and methods["service_account"]["reference"] is False
