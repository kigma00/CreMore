"""Google protocol tests use synthetic responses; no credentials or network."""

from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from cremore_gcp_provider.gcp_auth import GcpAuthError
from cremore_gcp_provider.oauth import SCOPES, OAuthConfig, exchange, oauth_token, projects

FIELDS = {"client_id": "synthetic.apps.googleusercontent.com", "client_secret": "synthetic-client-secret",
          "refresh_token": "synthetic-refresh", "auth_kind": "google_oauth"}
CONFIG = OAuthConfig(FIELDS["client_id"], FIELDS["client_secret"], "https://dashboard.example/gcp/oauth/callback")


def client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def token(**changes):
    return {"access_token": "synthetic-access", "token_type": "Bearer", "expires_in": 3600,
            "refresh_token": FIELDS["refresh_token"], "scope": " ".join(SCOPES), **changes}


@pytest.mark.parametrize("redirect", ["http://remote.example/gcp/oauth/callback", "https://example/a",
    "https://example/gcp/oauth/callback?next=evil", "https://u:p@example/gcp/oauth/callback"])
def test_redirect_is_fixed_and_secure(redirect):
    with pytest.raises(GcpAuthError, match="GCP_OAUTH_SETUP_REQUIRED"):
        OAuthConfig(FIELDS["client_id"], "secret", redirect).validate()


def test_authorization_uses_state_offline_and_pkce():
    query = parse_qs(urlsplit(CONFIG.authorization_url("binding", "verifier")).query)
    assert query["state"] == ["binding"] and query["access_type"] == ["offline"]
    assert query["code_challenge_method"] == ["S256"] and query["code_challenge"] != ["verifier"]
    assert "client_secret" not in query


def test_exchange_and_identity_without_returning_access_token():
    calls = []
    def respond(request):
        calls.append(request)
        if request.url.path == "/token":
            assert b"code_verifier=verifier" in request.content
            return httpx.Response(200, json=token())
        assert str(request.url) == "https://openidconnect.googleapis.com/v1/userinfo"
        return httpx.Response(200, json={"sub": "123", "email": "tester@example.test", "email_verified": True})
    with client(respond) as http:
        fields, identity = exchange(CONFIG, "synthetic-code", "verifier", http)
    assert fields == FIELDS and identity["email"] == "tester@example.test"
    assert len(calls) == 2 and "access_token" not in fields


@pytest.mark.parametrize("changes,code", [({"scope": "openid email"}, "GCP_OAUTH_SCOPE_REQUIRED"),
    ({"refresh_token": ""}, "GCP_OAUTH_OFFLINE_ACCESS_REQUIRED"), ({"token_type": {}}, "GCP_OAUTH_RESPONSE_INVALID")])
def test_incomplete_consent_fails(changes, code):
    with client(lambda _: httpx.Response(200, json=token(**changes))) as http, pytest.raises(GcpAuthError, match=code):
        exchange(CONFIG, "code", "verifier", http)


def test_refresh_is_cached_per_connection_and_expires():
    now, calls = [0], []
    def factory():
        return client(lambda request: (calls.append(request.content), httpx.Response(200, json=token()))[1])
    read = oauth_token(FIELDS, client_factory=factory, clock=lambda: now[0])
    assert read() == read() == "synthetic-access" and len(calls) == 1
    now[0] = 3541
    assert read() == "synthetic-access" and len(calls) == 2
    other = oauth_token({**FIELDS, "refresh_token": "other-account"}, client_factory=factory)
    other()
    assert b"other-account" in calls[-1] and b"synthetic-refresh" in calls[0]


@pytest.mark.parametrize("status,body,code", [(400, {"error": "invalid_grant", "error_description": "secret-detail"}, "GCP_OAUTH_REAUTH_REQUIRED"),
    (403, {"error": {"message": "secret-detail"}}, "GCP_PERMISSION_DENIED_OR_API_DISABLED"),
    (200, {"access_token": "secret-detail", "token_type": []}, "GCP_OAUTH_RESPONSE_INVALID")])
def test_refresh_failures_are_sanitized(status, body, code):
    read = oauth_token(FIELDS, client_factory=lambda: client(lambda _: httpx.Response(status, json=body)))
    with pytest.raises(GcpAuthError) as caught:
        read()
    assert caught.value.code == code and "secret-detail" not in str(caught.value)


@pytest.mark.parametrize("answer,code,wait", [
    (lambda _: httpx.Response(429, json={"error": "rate_limit_exceeded"}, headers={"Retry-After": "120"}),
     "GCP_OAUTH_RATE_LIMITED", 120.0),
    (lambda _: httpx.Response(503, text="<html>backend error</html>"), "GCP_OAUTH_TEMPORARILY_UNAVAILABLE", None),
    (lambda request: (_ for _ in ()).throw(httpx.ConnectError("unreachable", request=request)),
     "GCP_OAUTH_NETWORK_OR_RESPONSE_FAILED", None)])
def test_refresh_throttling_and_outages_are_transient_and_keep_retry_after(answer, code, wait):
    from cremore_gcp_provider.gcp_auth import TRANSIENT_AUTH_CODES
    read = oauth_token(FIELDS, client_factory=lambda: client(answer))
    with pytest.raises(GcpAuthError) as caught:
        read()
    assert caught.value.code == code and code in TRANSIENT_AUTH_CODES and caught.value.retry_after == wait


def test_reauthorization_and_malformed_answers_are_not_transient():
    from cremore_gcp_provider.gcp_auth import TRANSIENT_AUTH_CODES
    for answer, code in ((httpx.Response(400, json={"error": "invalid_grant"}), "GCP_OAUTH_REAUTH_REQUIRED"),
                         (httpx.Response(200, text="not json"), "GCP_OAUTH_RESPONSE_INVALID")):
        read = oauth_token(FIELDS, client_factory=lambda answer=answer: client(lambda _: answer))
        with pytest.raises(GcpAuthError) as caught:
            read()
        assert caught.value.code == code and code not in TRANSIENT_AUTH_CODES


def test_a_one_time_code_exchange_is_reported_not_retried():
    calls = []
    def unavailable(request):
        calls.append(request.url.path)
        return httpx.Response(503, headers={"Retry-After": "30"})
    with client(unavailable) as http, pytest.raises(GcpAuthError) as caught:
        exchange(CONFIG, "synthetic-code", "verifier", http)
    assert caught.value.code == "GCP_OAUTH_TEMPORARILY_UNAVAILABLE" and calls == ["/token"]


def test_projects_are_paginated_and_exclude_inactive_projects():
    def respond(request):
        if request.url.path == "/token":
            return httpx.Response(200, json=token())
        assert request.url.params["pageToken"] == "cursor" and request.url.host == "cloudresourcemanager.googleapis.com"
        return httpx.Response(200, json={"projects": [
            {"projectId": "demo-project", "displayName": "Demo", "state": "ACTIVE"},
            {"projectId": "deleted-project", "state": "DELETE_REQUESTED"}], "nextPageToken": "next"})
    with client(respond) as http:
        result = projects(FIELDS, http, page_token="cursor")
    assert result == {"items": [{"project_id": "demo-project", "name": "Demo"}], "next_page_token": "next"}


def test_gcs_check_preserves_oauth_evidence_and_requires_reauth_on_revocation():
    from cremore_gcp_provider.credential_check import check_gcp
    with client(lambda _: httpx.Response(200, json={"accounts": []})) as http:
        result = check_gcp({"project": "demo-project", "token": lambda: "synthetic-access"}, http)
        assert result.as_evidence("2026-09-24T00:00:00Z")["credential_mode"] == "GOOGLE_OAUTH"
        assert result.as_evidence("2026-09-24T00:00:00Z")["refresh_supported"] is True
        def revoked():
            raise GcpAuthError("GCP_OAUTH_REAUTH_REQUIRED")
        result = check_gcp({"project": "demo-project", "token": revoked}, http)
        assert result.status == "REJECTED" and result.error == "GCP_OAUTH_REAUTH_REQUIRED"


def test_concurrent_readers_refresh_once_and_take_the_same_token():
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    calls, lock = [], threading.Lock()

    def answer(request):
        with lock:
            calls.append(request.content)
        time.sleep(0.05)  # the other readers arrive while this one waits on Google
        return httpx.Response(200, json=token())

    read = oauth_token(FIELDS, client_factory=lambda: client(answer))
    with ThreadPoolExecutor(8) as pool:
        assert list(pool.map(lambda _: read(), range(8))) == ["synthetic-access"] * 8
    assert len(calls) == 1


def test_an_invalid_refresh_answer_leaves_the_kept_token_as_it_was():
    now, answers = [0], [httpx.Response(200, json=token(access_token="first")),
                         httpx.Response(200, json=token(access_token="half-valid", token_type=[])),
                         httpx.Response(200, json=token(access_token="second"))]
    read = oauth_token(FIELDS, client_factory=lambda: client(lambda _: answers.pop(0)), clock=lambda: now[0])
    assert read() == "first"
    now[0] = 4000
    with pytest.raises(GcpAuthError, match="GCP_OAUTH_RESPONSE_INVALID"):
        read()
    assert read() == "second" and answers == []
