"""Actual inventory reads, including optional OAuth, drive permission evidence."""

from types import SimpleNamespace

import httpx
import pytest

from cremore_atlassian_provider import onboarding
from cremore_atlassian_provider.metadata.specs import DEFAULT_SOURCES, SOURCES


@pytest.mark.parametrize("selected", [False, True])
def test_oauth_option_reaches_inventory_and_missing_listing_permission(monkeypatch, selected):
    organization = "11111111-2222-4333-8444-555555555555"
    plan = {"oauth_clients": selected}
    record = {"provider": "atlassian", "edition": "cloud", "auth_method": "api_key",
              "target": {"organization": organization}, "purposes": ["inventory"],
              "plans": {"inventory": plan}}
    seen = []

    def handler(request):
        seen.append(request.url.path)
        assert request.method == "GET" and request.url.host == "api.atlassian.com"
        return httpx.Response(403 if "oauth-clients" in request.url.path else 200, json={})

    ctx = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    rows = onboarding.check(record, "inventory", {"credential": {"token": "synthetic"}}, ctx)
    sources = [*DEFAULT_SOURCES, *(["service-account-oauth-clients", "org-oauth-clients"] if selected else [])]
    # The API-access listings the collector reads (developer.atlassian.com/cloud/admin/api-access), not /admin/v1.
    assert seen == [f"/admin/api-access/v1/orgs/{organization}/{SOURCES[s]['path']}" for s in sources]
    assert [r["status"] for r in rows if r["permission"] == "oauth_clients_read"] == (["MISSING"] * 2 if selected else [])
    [child] = onboarding.children(record, "inventory", plan)
    assert child["spec"]["options"].get("sources", list(DEFAULT_SOURCES)) == sources


@pytest.mark.parametrize("deploy_keys, listing, expected", [
    (403, {"values": [{"slug": "app"}]}, ("MISSING", "HTTP_403")),  # Account read alone: deploy keys need Repositories admin
    (200, {"values": [{"slug": "app"}]}, ("GRANTED", None)),
    (403, {"values": []}, ("GRANTED", None)),  # a validated empty workspace: no repository to ask about
    # A listing that cannot be read never vouches for deploy-key access.
    (200, {}, ("ERROR", "MALFORMED_RESPONSE")),
    (200, {"values": [{}]}, ("ERROR", "MALFORMED_RESPONSE")),
    (200, {"values": {"slug": "app"}}, ("ERROR", "MALFORMED_RESPONSE")),
    (200, {"values": ["app"]}, ("ERROR", "MALFORMED_RESPONSE")),
    (200, [], ("ERROR", "MALFORMED_RESPONSE")),
])
def test_bitbucket_cloud_inventory_check_reads_a_deploy_key_listing(deploy_keys, listing, expected):
    record = {"provider": "bitbucket", "edition": "cloud", "auth_method": "access_token",
              "target": {"workspace": "acme"}, "purposes": ["inventory"]}
    seen = []

    def handler(request):
        seen.append(request.url.path)
        if request.url.path == "/2.0/repositories/acme":
            return httpx.Response(200, json=listing)
        if request.url.path == "/2.0/repositories/acme/app/deploy-keys":
            return httpx.Response(deploy_keys, json={"values": []})
        assert request.url.path == "/2.0/workspaces/acme/permissions"
        return httpx.Response(200, json={"values": []})

    ctx = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    [row] = onboarding.check(record, "inventory", {"credential": {"token": "synthetic"}}, ctx)
    assert (row["permission"], row["status"], row.get("detail")) == ("list_access_tokens", *expected)
    assert ("/2.0/repositories/acme/app/deploy-keys" in seen) == (expected[1] in (None, "HTTP_403")
                                                                   and listing != {"values": []})


def test_oauth_client_type_claims_only_what_every_listing_it_matches_returns():
    from cremore.onboarding.catalog import INVENTORY_FIELDS

    oauth = next(t for t in onboarding.ATLASSIAN_TYPES if t["id"] == "oauth_client")
    support = dict(zip(INVENTORY_FIELDS, oauth["support"], strict=True))
    carried = {"expires": "expiresAt", "scopes": "scopes", "creator": "createdBy.id", "owner": "serviceAccount.id"}
    for field, name in carried.items():
        assert name in SOURCES["service-account-oauth-clients"]["fields"]
        # The organization listing (also matched) never returns it, so it is not kept for every client.
        assert name not in SOURCES["org-oauth-clients"]["fields"]
        assert support[field] == "P" and field in oauth["reasons"], field
