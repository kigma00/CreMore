"""Provider connection routes: everyone reads, administrators connect (design 4.4)."""

from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.conftest import oidc_settings
from cremore.db.repository import InMemoryRepository
from cremore.onboarding.onboarding_test import PEM


def _bearer(issuer, sub, group):
    return {"Authorization": "Bearer " + issuer.mint(sub=sub, groups=(group,))}


def client(issuer, repo=None):
    app = create_app(repo=repo or InMemoryRepository(), settings=oidc_settings(FINGERPRINT_KEY="ab" * 32),
                     oidc_http_client=issuer)
    return TestClient(app)


BODY = {"provider": "github", "edition": "cloud", "purposes": ["exposure"], "auth_method": "github_app",
        "target": {"organization": "acme"}, "credential": {"app_id": "1", "installation_id": "2", "private_key": PEM}}


def test_feature_switch_requires_admin_revision_and_keeps_the_configured_plan(issuer):
    from cremore.onboarding import service
    from cremore.onboarding.features_test import connect

    repo = InMemoryRepository()
    made = connect(repo, BODY, {"exposure": {}})
    c = client(issuer, repo)
    admin = _bearer(issuer, "admin", "g-admins")
    url = f"/api/v1/provider-connections/{made['id']}/features/exposure"
    body = {"enabled": False, "expected_revision": service.get(repo, made["id"])["revision"]}
    assert c.put(url, json=body).status_code == 401
    assert c.put(url, json=body, headers=_bearer(issuer, "analyst", "g-analysts")).status_code == 403
    assert c.put(url, json={"enabled": False}, headers=admin).status_code == 422
    changed = c.put(url, json=body, headers=admin)
    assert changed.status_code == 200 and changed.headers["cache-control"] == "no-store"
    assert changed.json()["feature_enabled"] == {"exposure": False}
    assert changed.json()["plans"] == made["plans"]
    assert c.put(url, json=body, headers=admin).status_code == 409


def test_authentication_drafts_require_admin_actor_browser_and_revision(issuer):
    c = client(issuer)
    admin = _bearer(issuer, "d", "g-admins")
    body = {"provider": "notion", "auth_method": "integration", "browser_key": "a" * 43,
            "credential": {"token": "synthetic-notion-token"}}
    base = "/api/v1/onboarding-sessions"
    assert c.post(base, json=body).status_code == 401
    assert c.post(base, headers=_bearer(issuer, "a", "g-analysts"), json=body).status_code == 403
    response = c.post(base, headers=admin, json=body)
    assert response.status_code == 202 and response.headers["cache-control"] == "no-store"
    assert "synthetic-notion-token" not in response.text and "sealed:" not in response.text
    view = response.json()
    url = f"{base}/{view['id']}"
    binding = {"browser_key": body["browser_key"], "expected_revision": view["revision"]}
    assert c.post(url + "/read", headers=_bearer(issuer, "other", "g-admins"), json=binding).status_code == 404
    assert c.post(url + "/read", headers=admin, json={**binding, "browser_key": "b" * 43}).status_code == 404
    assert c.post(url + "/complete", headers=admin, json={**binding, "name": "Too early"}).status_code == 409
    assert c.post(url + "/discover", headers=admin, json={**binding, "expected_revision": 0, "purposes": ["exposure"]}).status_code == 409
    assert c.post(url + "/cancel", headers=admin, json=binding).json()["state"] == "CANCELLED"
    assert c.post(url + "/discover", headers=admin, json={**binding, "purposes": ["exposure"]}).status_code == 409


def test_every_role_reads_the_catalog_and_only_an_administrator_connects(issuer):
    c = client(issuer)
    viewer, analyst, admin = (_bearer(issuer, "v", "g-viewers"), _bearer(issuer, "a", "g-analysts"),
                              _bearer(issuer, "d", "g-admins"))
    catalog = c.get("/api/v1/provider-connections/catalog", headers=viewer).json()
    assert catalog["purposes"] == ["exposure", "inventory", "vault", "identity", "remediation"]
    github = next(item for item in catalog["providers"] if item["provider"] == "github")
    assert [method["id"] for method in github["auth_methods"]] == ["github_app", "token"]
    assert c.post("/api/v1/provider-connections", headers=analyst, json=BODY).status_code == 403
    created = c.post("/api/v1/provider-connections", headers=admin, json=BODY)
    assert created.status_code == 201 and created.headers["cache-control"] == "no-store"
    body = created.json()
    assert body["status"] == "DRAFT" and "PRIVATE KEY" not in created.text and "sealed:" not in created.text
    assert [item["id"] for item in c.get("/api/v1/provider-connections", headers=viewer).json()] == [body["id"]]
    assert c.get(f"/api/v1/provider-connections/{body['id']}", headers=viewer).json()["name"] == "GitHub · acme"
    assert c.post(f"/api/v1/provider-connections/{body['id']}/check", headers=analyst).status_code == 403
    queued = c.post(f"/api/v1/provider-connections/{body['id']}/check", headers=admin)
    assert queued.status_code == 202 and queued.json()["status"] == "CHECKING"
    # The logs name the provider connection a permission check is for; nothing else from its payload.
    [check] = [run for run in c.get("/api/v1/scan-runs", headers=viewer).json() if run["kind"] == "provider-check"]
    assert check["provider_connection_id"] == body["id"] and "digest" not in check and "payload" not in check
    assert "coverage_connection_id" not in check and check["connection_id"] is None


def test_a_team_install_names_its_sign_in_idp_and_takes_no_other_people_directory(issuer):
    """The fake issuer is no IdP CreMore reads people from: every directory is refused, GitHub's identity link is not."""
    from cremore.config import Settings

    c = client(issuer)
    admin = _bearer(issuer, "d", "g-admins")
    catalog = c.get("/api/v1/provider-connections/catalog", headers=_bearer(issuer, "v", "g-viewers")).json()
    assert catalog["sign_in_idp"] == {"issuer": "https://idp.test", "provider": None, "target": None, "exempt": ["github"]}
    okta = {"provider": "okta", "purposes": ["identity"], "auth_method": "made_key",
            "target": {"organization": "acme.okta.com"}, "credential": {"client_id": "0oa1serviceapp"}}
    refused = c.post("/api/v1/provider-connections", headers=admin, json=okta)
    assert refused.status_code == 409 and refused.json()["error"] == "PEOPLE_DIRECTORY_SIGN_IN_IDP_UNKNOWN"
    github = {**BODY, "purposes": ["identity"], "auth_method": "token", "credential": {"token": "ghp_" + "x" * 36}}
    assert c.post("/api/v1/provider-connections", headers=admin, json=github).status_code == 201
    token = "local-admin-" + "t" * 32
    solo = TestClient(create_app(repo=InMemoryRepository(), settings=Settings(AUTH_MODE="local", API_TOKEN=token,
                                                                             FINGERPRINT_KEY="ab" * 32)),
                      headers={"Authorization": "Bearer " + token})
    assert solo.get("/api/v1/provider-connections/catalog").json()["sign_in_idp"] is None
    assert solo.post("/api/v1/provider-connections", json=okta).status_code == 201


def test_refusals_are_stable_codes(issuer):
    c = client(issuer)
    admin = _bearer(issuer, "d", "g-admins")
    r = c.post("/api/v1/provider-connections", headers=admin, json={**BODY, "purposes": ["inventory"], "auth_method": "token",
                                                                    "credential": {"token": "ghp_" + "x" * 36}})
    assert r.status_code == 422 and r.json()["error"] == "AUTH_METHOD_NOT_FOR_PURPOSES"
    missing = c.get("/api/v1/provider-connections/00000000-0000-0000-0000-000000000000", headers=admin)
    assert missing.status_code == 404
    draft = c.post("/api/v1/provider-connections", headers=admin, json=BODY).json()
    early = c.post(f"/api/v1/provider-connections/{draft['id']}/activate", headers=admin,
                   json={"purposes": {"exposure": {}}})
    assert early.status_code == 409 and early.json()["error"] == "PROVIDER_CONNECTION_NOT_CHECKED"
    assert c.delete(f"/api/v1/provider-connections/{draft['id']}", headers=admin).status_code == 204


def test_only_an_administrator_can_add_features_to_an_existing_connection(issuer):
    c = client(issuer)
    admin = _bearer(issuer, "d", "g-admins")
    made = c.post("/api/v1/provider-connections", headers=admin, json=BODY).json()
    url = f"/api/v1/provider-connections/{made['id']}/purposes"
    body = {"purposes": ["exposure", "inventory"], "expected_revision": made["revision"]}
    assert c.put(url, json=body).status_code == 401
    assert c.put(url, headers=_bearer(issuer, "a", "g-analysts"), json=body).status_code == 403
    result = c.put(url, headers=admin, json=body)
    assert result.status_code == 200 and result.json()["purposes"] == body["purposes"]
    assert result.json()["checks"]["stale"]
    assert "PRIVATE KEY" not in result.text and "sealed:" not in result.text
    assert c.put(url, headers=admin, json=body).status_code == 409


def test_an_administrator_changes_an_active_plan(issuer):
    from cremore.onboarding.fixtures_test import grant_access

    repo = InMemoryRepository()
    c = client(issuer, repo)
    analyst, admin = _bearer(issuer, "a", "g-analysts"), _bearer(issuer, "d", "g-admins")
    body = {"provider": "gitlab", "purposes": ["inventory"], "auth_method": "token",
            "target": {"scope": "group", "id": "7"}, "credential": {"token": "glpat-" + "p" * 20}}
    made = c.post("/api/v1/provider-connections", headers=admin, json=body).json()
    url = f"/api/v1/provider-connections/{made['id']}/plans/inventory"
    early = c.put(url, headers=admin, json={"plan": {}})
    assert early.status_code == 409 and early.json()["error"] == "PROVIDER_CONNECTION_NOT_ACTIVE"
    grant_access(repo, made["id"], {"inventory": {}})
    assert c.post(f"/api/v1/provider-connections/{made['id']}/activate", headers=admin, json={"purposes": {"inventory": {}}}).status_code == 200
    assert c.put(url, headers=analyst, json={"plan": {"audit_events": True}}).status_code == 403
    assert c.put(url, headers=admin, json={"plan": {"audit_events": True}}).status_code == 409
    grant_access(repo, made["id"], {"inventory": {"audit_events": True}})
    changed = c.put(url, headers=admin, json={"plan": {"audit_events": True}})
    assert changed.status_code == 200 and changed.headers["cache-control"] == "no-store"
    assert changed.json()["plans"]["inventory"]["audit_events"] is True and len(changed.json()["changed"]) == 1
    assert "glpat-" not in changed.text and "sealed:" not in changed.text


def test_a_github_app_from_a_manifest_is_an_administrators_and_never_shows_the_key(issuer):
    import httpx

    def github(request):
        if request.url.path.startswith("/app-manifests/"):
            return httpx.Response(201, json={"id": 7, "slug": "cremore-acme", "name": "CreMore acme", "pem": PEM,
                                             "owner": {"login": "acme"}, "client_secret": "x", "webhook_secret": "y"})
        return httpx.Response(200, json=[{"id": 70, "account": {"login": "acme"}, "target_type": "Organization"}])

    c = client(issuer)
    c.app.state.github_app_http_client = lambda: httpx.Client(transport=httpx.MockTransport(github))
    analyst, admin = _bearer(issuer, "a", "g-analysts"), _bearer(issuer, "d", "g-admins")
    body = {"browser_key": "b" * 43, "purposes": ["exposure"], "target": {"organization": "acme"}}
    assert c.post("/api/v1/github/app-manifest/start", headers=analyst, json=body).status_code == 403
    started = c.post("/api/v1/github/app-manifest/start", headers=admin, json=body)
    assert started.status_code == 200 and started.headers["cache-control"] == "no-store"
    flow = started.json()
    session = {"session_id": flow["session_id"], "browser_key": "b" * 43}
    converted = c.post("/api/v1/github/app-manifest/convert", headers=admin,
                       json={**session, "state": flow["state"], "code": "abc"})
    assert converted.status_code == 200 and "PRIVATE KEY" not in converted.text
    assert converted.json()["install_url"] == "https://github.com/apps/cremore-acme/installations/new"
    done = c.post("/api/v1/github/app-manifest/complete", headers=admin, json=session)
    assert done.status_code == 200
    view = c.get(f"/api/v1/provider-connections/{done.json()['provider_connection_id']}", headers=admin).json()
    assert view["auth_method"] == "github_app" and view["status"] == "CHECKING"
    again = c.post("/api/v1/github/app-manifest/convert", headers=admin,
                   json={**session, "state": flow["state"], "code": "abc"})
    assert again.status_code == 409 and again.json()["error"] == "GITHUB_APP_SESSION_STAGE"


def test_suggestions_are_an_administrators_and_not_a_connection_id(issuer):
    c = client(issuer)
    assert c.get("/api/v1/provider-connections/suggestions", headers=_bearer(issuer, "v", "g-viewers")).status_code == 403
    answer = c.get("/api/v1/provider-connections/suggestions", headers=_bearer(issuer, "d", "g-admins"))
    assert answer.status_code == 200 and answer.json() == {"items": []}


def test_putting_the_app_on_the_enterprise_organizations_is_an_administrators_and_shows_no_key(issuer):
    from cremore.onboarding.github_enterprise_test import TOKEN, GitHub, checked

    repo = InMemoryRepository()
    c = client(issuer, repo)
    github = GitHub()
    c.app.state.github_app_http_client = github.client
    analyst, admin = _bearer(issuer, "a", "g-analysts"), _bearer(issuer, "d", "g-admins")
    made = c.post("/api/v1/provider-connections", headers=admin, json={
        **BODY, "edition": "enterprise_cloud", "purposes": ["exposure"], "target": {"organization": "acme", "enterprise": "acme-corp"},
        "credential": {"app_id": "12345", "installation_id": "678", "private_key": PEM}}).json()
    checked(repo, made["id"])
    path = f"/api/v1/provider-connections/{made['id']}/github-enterprise"
    assert c.get(path, headers=analyst).status_code == 403
    assert c.post(path + "/install", headers=analyst, json={"organizations": ["acme-labs"]}).status_code == 403
    status = c.get(path, headers=admin)
    assert status.status_code == 200 and status.headers["cache-control"] == "no-store"
    assert status.json()["state"] == "READY" and [row["organization"] for row in status.json()["organizations"]] == ["acme", "acme-labs", "acme-data"]
    assert "PRIVATE KEY" not in status.text and TOKEN not in status.text
    # The same question within half a minute is answered without asking GitHub again.
    assert c.get(path, headers=admin).json() == status.json() and github.minted == 1
    # Not collecting yet: nothing is installed with plans it does not have.
    refused = c.post(path + "/install", headers=admin, json={"organizations": ["acme-labs"]})
    assert refused.status_code == 409 and "GITHUB_ENTERPRISE_SOURCE_NOT_ACTIVE" in refused.text
    from cremore.onboarding import service
    from cremore.onboarding.onboarding_test import SETTINGS

    service.activate(repo, SETTINGS, made["id"], {"purposes": {"exposure": {}}}, "admin")
    queued = c.post(path + "/install", headers=admin, json={"organizations": ["acme-labs", "acme-data"]})
    assert queued.status_code == 202 and queued.json() == {"requested": ["acme-labs", "acme-data"], "unchanged": []}
    assert c.post(path + "/install", headers=admin, json={"organizations": ["../x"]}).status_code == 422
    cancelled = c.post(path + "/cancel", headers=admin, json={"organizations": ["acme-data"]})
    assert cancelled.status_code == 200 and cancelled.json() == {"cancelled": ["acme-data"]}
    assert c.post(path + "/cancel", headers=analyst, json={"organizations": ["acme-labs"]}).status_code == 403
    assert c.put(path + "/auto", headers=admin, json={"enabled": "yes"}).status_code == 422
    assert c.put(path + "/auto", headers=admin, json={"enabled": True}).json() == {"auto": True}
    rows = {row["organization"]: row for row in c.get(path, headers=admin).json()["organizations"]}
    assert rows["acme-labs"]["requested"] is True and rows["acme-labs"]["result"]["state"] == "REQUESTED"
    assert rows["acme-data"]["requested"] is False and rows["acme-data"]["result"] is None
    assert github.minted == 2  # a change forgets the cached answer


def test_a_recognized_sign_in_idp_is_offered_and_its_people_collection_stays_on_it():
    """Signing in through an Okta organization: the catalog names it, another organization is refused over HTTP, and
    the collection the connection made cannot be pointed at another directory through the coverage API."""
    from cremore.api.conftest import AUDIENCE, FakeIssuer, FakeResp

    okta_issuer = "https://acme.okta.com/oauth2/default"

    class OktaIssuer(FakeIssuer):
        def get(self, url, **kwargs):
            assert kwargs.get("follow_redirects", False) is False
            if url == okta_issuer + "/.well-known/openid-configuration":
                return FakeResp(200, {"issuer": okta_issuer, "jwks_uri": okta_issuer + "/v1/keys"})
            return super().get(url.replace(okta_issuer + "/v1/keys", "https://idp.test/jwks"), **kwargs)

    fake = OktaIssuer()
    repo = InMemoryRepository()
    c = TestClient(create_app(repo=repo, settings=oidc_settings(FINGERPRINT_KEY="ab" * 32, OIDC_ISSUER_URL=okta_issuer),
                              oidc_http_client=fake))
    admin = {"Authorization": "Bearer " + fake.mint(sub="d", groups=("g-admins",), issuer=okta_issuer, audience=AUDIENCE)}
    response = c.get("/api/v1/provider-connections/catalog", headers=admin)
    assert response.status_code == 200, response.text
    hint = response.json()["sign_in_idp"]
    assert hint == {"issuer": okta_issuer, "provider": "okta", "target": {"organization": "acme.okta.com"},
                    "exempt": ["github"]}
    body = {"provider": "okta", "purposes": ["identity"], "auth_method": "made_key",
            "target": {"organization": "other.okta.com"}, "credential": {"client_id": "0oa1serviceapp"}}
    other = c.post("/api/v1/provider-connections", headers=admin, json=body)
    assert other.status_code == 409 and other.json()["error"] == "PEOPLE_DIRECTORY_NOT_SIGN_IN_IDP"
    made = c.post("/api/v1/provider-connections", headers=admin, json={**body, "target": {"organization": "acme.okta.com"}})
    assert made.status_code == 201
    from cremore.onboarding.fixtures_test import grant_access

    grant_access(repo, made.json()["id"], {"identity": {}})
    [child] = c.post(f"/api/v1/provider-connections/{made.json()['id']}/activate", headers=admin,
                     json={"purposes": {"identity": {}}}).json()["created"]
    collection = c.get(f"/api/v2/coverage/connections/{child['id']}", headers=admin).json()
    spec = {key: value for key, value in collection["spec"].items() if key != "secret_refs"}
    moved = {**spec, "origin": "https://other.okta.com", "tenant": "other.okta.com",
             "scopes": [{"kind": "organization", "id": "other.okta.com"}]}
    refused = c.patch(f"/api/v2/coverage/connections/{child['id']}", headers=admin,
                      json={"revision": collection["revision"], "spec": moved})
    assert refused.status_code == 409 and refused.json()["error"] == "PEOPLE_DIRECTORY_BELONGS_TO_PROVIDER_CONNECTION"
    path = c.patch(f"/api/v2/coverage/connections/{child['id']}", headers=admin, json={
        "revision": collection["revision"], "spec": {**spec, "options": {**spec["options"], "api_path": "/other"}}})
    assert path.status_code == 409 and path.json()["error"] == "PEOPLE_DIRECTORY_BELONGS_TO_PROVIDER_CONNECTION"
    renamed = c.patch(f"/api/v2/coverage/connections/{child['id']}", headers=admin,
                      json={"revision": collection["revision"], "spec": {**spec, "name": "Okta people"}})
    assert renamed.status_code == 200, renamed.text
    # Stopped with its provider connection, the collection is not turned back on behind the connection's back.
    assert c.post(f"/api/v1/provider-connections/{made.json()['id']}/disable", headers=admin).status_code == 200
    stopped = c.get(f"/api/v2/coverage/connections/{child['id']}", headers=admin).json()
    back = c.patch(f"/api/v2/coverage/connections/{child['id']}", headers=admin,
                   json={"revision": stopped["revision"], "enabled": True})
    assert back.status_code == 409 and back.json()["error"] == "PEOPLE_DIRECTORY_BELONGS_TO_PROVIDER_CONNECTION"
