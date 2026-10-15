"""CreMore's App installing itself on an enterprise's organizations, against a synthetic GitHub: the App is found
with its JWT, its enterprise installation's token lists and installs, and each refusal is a code."""

import base64
import json

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cremore_github_provider import enterprise_install
from cremore_github_provider.github_auth import GitHubAuthError

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PEM = KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                        serialization.NoEncryption())
KEY64 = base64.b64encode(PEM).decode()
# Built at run time: nothing token-shaped sits in the source.
TOKEN = "ghs_" + "e" * 36


class GitHub:
    """Answers the App endpoints; ``refuse`` maps a path to a status."""

    def __init__(self, orgs=("acme", "acme-labs", "acme-data"), refuse=None):
        self.orgs, self.refuse, self.calls, self.installed = list(orgs), refuse or {}, [], {"acme": 11}

    def __call__(self, request):
        self.calls.append((request.method, request.url.path, request.headers.get("authorization", "")))
        path = request.url.path
        if path in self.refuse:
            return httpx.Response(self.refuse[path], json={"message": "synthetic"})
        if path == "/app":
            claims = jwt.decode(request.headers["authorization"].removeprefix("Bearer "), KEY.public_key(), algorithms=["RS256"])
            assert claims["iss"] == "424242"
            return httpx.Response(200, json={"id": 424242, "client_id": "Iv23liCREMORE", "slug": "cremore-acme",
                                             "name": "CreMore acme", "owner": {"slug": "acme-corp", "type": "Enterprise"},
                                             "permissions": {"contents": "read"}})
        if path == "/app/installations":
            rows = [{"id": 99, "target_type": "Enterprise", "account": {"slug": "acme-corp", "name": "Acme"}}]
            rows += [{"id": value, "target_type": "Organization", "account": {"login": login}} for login, value in self.installed.items()]
            return httpx.Response(200, json=rows)
        if path == "/app/installations/99/access_tokens":
            return httpx.Response(201, json={"token": TOKEN, "expires_at": "2099-01-01T00:00:00Z", "permissions": {}})
        assert request.headers["authorization"] == "Bearer " + TOKEN
        if path == "/installation/token":
            assert request.method == "DELETE"
            return httpx.Response(204)
        if path == "/enterprises/acme-corp/apps/installable_organizations":
            page = int(request.url.params["page"])
            chunk = self.orgs[(page - 1) * 100:page * 100]
            return httpx.Response(200, json=[{"id": n, "login": login} for n, login in enumerate(chunk, 1)])
        if path.startswith("/enterprises/acme-corp/apps/organizations/") and path.endswith("/installations"):
            org = path.split("/")[5]
            assert request.method == "POST"
            body = json.loads(request.content)
            assert body == {"client_id": "Iv23liCREMORE", "repository_selection": "all"}
            existing = self.installed.get(org)
            self.installed[org] = existing or 500 + len(self.installed)
            return httpx.Response(200 if existing else 201, json={"id": self.installed[org], "app_slug": "cremore-acme"})
        raise AssertionError(path)


def client(github):
    return httpx.Client(transport=httpx.MockTransport(github))


def test_the_app_finds_itself_its_enterprise_installation_and_the_organizations_it_is_on():
    github = GitHub()
    with client(github) as http:
        found = enterprise_install.app(http, "", "424242", KEY64)
        assert (found["client_id"], found["slug"], found["owner"], found["owner_type"]) == ("Iv23liCREMORE", "cremore-acme", "acme-corp", "Enterprise")
        where = enterprise_install.installations(http, "", "424242", KEY64)
    assert where == {"enterprises": {"acme-corp": "99"}, "organizations": {"acme": "11"}}


def test_the_enterprise_installation_lists_organizations_and_installs_the_app_on_each():
    github = GitHub(orgs=[f"org-{n}" for n in range(150)])
    with client(github) as http:
        token = enterprise_install.enterprise_token(lambda: client(github), "", "424242", "99", KEY64)
        orgs = enterprise_install.installable_organizations(http, "", token, "acme-corp")
        assert len(orgs) == 150  # two pages
        first = enterprise_install.install(http, "", token, "acme-corp", "org-7", "Iv23liCREMORE")
        again = enterprise_install.install(http, "", token, "acme-corp", "org-7", "Iv23liCREMORE")
    assert first == again  # already installed: GitHub answers with the same installation
    # The token went only to the enterprise endpoints; the App's JWT only to the App's.
    for method, path, auth in github.calls:
        if path.startswith("/enterprises/"):
            assert auth == "Bearer " + TOKEN
        else:
            assert TOKEN not in auth


def test_the_enterprise_token_request_has_the_short_limit_too():
    github, limits = GitHub(), {}

    def seen(request):
        limits[request.url.path] = request.extensions["timeout"]
        return github(request)

    token = enterprise_install.enterprise_token(lambda: httpx.Client(transport=httpx.MockTransport(seen), timeout=30),
                                                "", "424242", "99", KEY64)
    assert token == TOKEN
    assert limits["/app/installations/99/access_tokens"] == {"connect": 5.0, "read": 10.0, "write": 10.0, "pool": 10.0}


def test_a_list_longer_than_ten_pages_stops_rather_than_reads_as_complete():
    github = GitHub(orgs=[f"org-{n}" for n in range(1000)])  # ten full pages: an eleventh may exist
    with client(github) as http, pytest.raises(GitHubAuthError) as cut:
        enterprise_install.installable_organizations(http, "", TOKEN, "acme-corp")
    assert cut.value.code == "GITHUB_LIST_TRUNCATED"
    github = GitHub(orgs=[f"org-{n}" for n in range(999)])
    with client(github) as http:
        assert len(enterprise_install.installable_organizations(http, "", TOKEN, "acme-corp")) == 999


def test_a_used_token_is_revoked_and_odd_accounts_are_skipped():
    github = GitHub()
    github.installed[123] = 12  # a login that is not a string
    with client(github) as http:
        where = enterprise_install.installations(http, "", "424242", KEY64)
        enterprise_install.revoke(http, "", TOKEN)
    assert where["organizations"] == {"acme": "11"}
    assert ("DELETE", "/installation/token", "Bearer " + TOKEN) in github.calls
    # A failing revoke is not an error: the token lapses within the hour anyway.
    with client(GitHub(refuse={"/installation/token": 500})) as http:
        enterprise_install.revoke(http, "", TOKEN)


@pytest.mark.parametrize(("status", "code"), [(403, "GITHUB_ENTERPRISE_PERMISSION_REQUIRED"),
                                              (404, "GITHUB_ENTERPRISE_NOT_FOUND"),
                                              (422, "GITHUB_ENTERPRISE_INSTALL_REFUSED"),
                                              (502, "GITHUB_APP_UNAVAILABLE")])
def test_each_refusal_is_its_own_code(status, code):
    path = "/enterprises/acme-corp/apps/organizations/acme-labs/installations"
    github = GitHub(refuse={path: status, "/enterprises/acme-corp/apps/installable_organizations": status})
    with client(github) as http, pytest.raises(GitHubAuthError) as refused:
        enterprise_install.install(http, "", TOKEN, "acme-corp", "acme-labs", "Iv23liCREMORE")
    assert refused.value.code == code
    with client(github) as http, pytest.raises(GitHubAuthError) as listed:
        enterprise_install.installable_organizations(http, "", TOKEN, "acme-corp")
    assert listed.value.code == code


def test_names_are_checked_before_any_call_and_servers_get_their_own_api():
    github = GitHub()
    with client(github) as http:
        for bad in ("acme/../x", "", "-acme"):
            with pytest.raises(GitHubAuthError):
                enterprise_install.install(http, "", TOKEN, bad, "acme", "Iv23liCREMORE")
            with pytest.raises(GitHubAuthError):
                enterprise_install.install(http, "", TOKEN, "acme-corp", bad, "Iv23liCREMORE")
    assert github.calls == []
    seen = []

    def server(request):
        seen.append(str(request.url))
        return httpx.Response(200, json=[])

    with httpx.Client(transport=httpx.MockTransport(server)) as http:
        enterprise_install.installable_organizations(http, "github.example.com", TOKEN, "acme-corp")
    assert seen[0].startswith("https://github.example.com/api/v3/enterprises/acme-corp/apps/installable_organizations")
