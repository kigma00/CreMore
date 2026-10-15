"""Verification tests. No network: an injected fake client returns canned
responses, and SigV4 is checked for determinism and structure."""

from __future__ import annotations

import datetime

import pytest
from cremore_aws_provider.detection.verify.aws import AWSAccessKeyVerifier
from cremore_aws_provider.detection.verify.sigv4 import sign

from cremore.detection import DetectorInput, Engine
from cremore.detection.engine import EngineConfig
from cremore.detection.verify import (
    VerificationState,
    VerifierConfig,
    load_default_verifiers,
)
from cremore.detection.verify.http import HTTP_VERIFY_SPECS, HTTPVerifier

FIXED = datetime.datetime(2023, 1, 2, 3, 4, 5, tzinfo=datetime.UTC)
AKID = "AKIAZ5X9K2" "MBV7QP3LN6"
SECRET40 = "aB3dE5fG7h" "J9kL1mN2pQ" "4rS6tU8vW0" "xY2zC4dE6f"  # 40 base64 chars
GH = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"  # 36-char body

STS_OK = (
    '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
    "<GetCallerIdentityResult>"
    "<Arn>arn:aws:iam::123456789012:user/demo</Arn>"
    "<UserId>AIDAEXAMPLEUSERID</UserId>"
    "<Account>123456789012</Account>"
    "</GetCallerIdentityResult></GetCallerIdentityResponse>"
)
STS_BAD = (
    '<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error>'
    "<Type>Sender</Type><Code>InvalidClientTokenId</Code>"
    "<Message>The security token included in the request is invalid.</Message>"
    "</Error></ErrorResponse>"
)
STS_EXPIRED = (
    '<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error>'
    "<Type>Sender</Type><Code>ExpiredToken</Code>"
    "<Message>The security token included in the request is expired.</Message>"
    "</Error></ErrorResponse>"
)
ASIA = "ASIA" "Z5X9K2MBV7QP3LN6"
STS_TOKEN = "IQoJb3JpZ2luX2Vj" + "A1b2C3d4E5f6G7h8I9j0K+l/M=n" * 4  # opaque, bounded


class FakeResp:
    def __init__(self, status: int, text: str = "", headers: dict | None = None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


class FakeClient:
    def __init__(self, resp: FakeResp):
        self._resp = resp
        self.calls: list = []

    def post(self, url, headers=None, content=None):
        self.calls.append(("POST", url, headers))
        return self._resp

    def request(self, method, url, headers=None):
        self.calls.append((method, url, headers))
        return self._resp

    def close(self):
        pass


# --- SigV4 -----------------------------------------------------------------

def test_sigv4_deterministic_and_structured():
    kw = {
        "access_key_id": AKID, "secret_access_key": SECRET40, "region": "us-east-1",
        "service": "sts", "host": "sts.amazonaws.com",
        "body": b"Action=GetCallerIdentity&Version=2011-06-15", "now": FIXED,
    }
    a = sign(**kw)
    b = sign(**kw)
    assert a.headers["Authorization"] == b.headers["Authorization"]
    auth = a.headers["Authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 Credential=" + AKID + "/20230102/us-east-1/sts/aws4_request")
    assert "SignedHeaders=content-type;host;x-amz-date" in auth
    assert len(auth.rsplit("Signature=", 1)[1]) == 64  # 32-byte hex
    assert a.headers["X-Amz-Date"] == "20230102T030405Z"
    # A different secret changes the signature.
    other = sign(**{**kw, "secret_access_key": SECRET40[:-1] + "g"})
    assert other.headers["Authorization"] != auth


def test_sigv4_signs_the_security_token_header_when_a_session_token_is_present():
    kw = {
        "access_key_id": ASIA, "secret_access_key": SECRET40, "region": "us-east-1",
        "service": "sts", "host": "sts.amazonaws.com",
        "body": b"Action=GetCallerIdentity&Version=2011-06-15", "session_token": STS_TOKEN, "now": FIXED,
    }
    signed = sign(**kw)
    assert signed.headers["X-Amz-Security-Token"] == STS_TOKEN
    # The token must be a *signed* header, not just sent alongside the request.
    assert "x-amz-security-token" in signed.headers["Authorization"].split("SignedHeaders=", 1)[1]
    # Dropping the token changes the signature (it is part of the signed request).
    assert sign(**{**kw, "session_token": ""}).headers["Authorization"] != signed.headers["Authorization"]


# --- AWS verifier ----------------------------------------------------------

def test_aws_verifier_verified():
    v = AWSAccessKeyVerifier()
    r = v.verify(secret=SECRET40, identifier=AKID, config=VerifierConfig(enabled=True),
                 client=FakeClient(FakeResp(200, STS_OK)))
    assert r.state == VerificationState.VERIFIED
    assert r.facts["account"] == "123456789012"
    assert r.facts["arn"].endswith("user/demo")


def test_aws_verifier_rejected():
    v = AWSAccessKeyVerifier()
    r = v.verify(secret=SECRET40, identifier=AKID, config=VerifierConfig(enabled=True),
                 client=FakeClient(FakeResp(403, STS_BAD)))
    assert r.state == VerificationState.REJECTED
    assert r.error_code == "InvalidClientTokenId"


def test_aws_verifier_disabled_never_calls_network():
    v = AWSAccessKeyVerifier()
    client = FakeClient(FakeResp(200, STS_OK))
    r = v.verify(secret=SECRET40, identifier=AKID, config=VerifierConfig(enabled=False), client=client)
    assert r.state == VerificationState.NOT_ATTEMPTED
    assert client.calls == []


def test_aws_verifier_incomplete_pair_unsupported():
    v = AWSAccessKeyVerifier()
    r = v.verify(secret="tooshort", identifier=AKID, config=VerifierConfig(enabled=True),
                 client=FakeClient(FakeResp(200, STS_OK)))
    assert r.state == VerificationState.UNSUPPORTED


def test_aws_verifier_sts_triple_verified_signs_the_security_token():
    v = AWSAccessKeyVerifier()
    client = FakeClient(FakeResp(200, STS_OK))
    r = v.verify(secret=SECRET40, identifier=ASIA, config=VerifierConfig(enabled=True),
                 client=client, context={"aws_session_token": STS_TOKEN})
    assert r.state == VerificationState.VERIFIED and r.facts["account"] == "123456789012"
    assert client.calls[0][2]["X-Amz-Security-Token"] == STS_TOKEN


def test_aws_verifier_sts_expired_token_is_rejected_with_reason():
    v = AWSAccessKeyVerifier()
    r = v.verify(secret=SECRET40, identifier=ASIA, config=VerifierConfig(enabled=True),
                 client=FakeClient(FakeResp(403, STS_EXPIRED)), context={"aws_session_token": STS_TOKEN})
    assert r.state == VerificationState.REJECTED and r.error_code == "ExpiredToken"


def test_aws_verifier_sts_without_bound_token_is_unsupported_and_silent():
    client = FakeClient(FakeResp(200, STS_OK))
    r = AWSAccessKeyVerifier().verify(secret=SECRET40, identifier=ASIA,
                                      config=VerifierConfig(enabled=True), client=client)
    assert r.state == VerificationState.UNSUPPORTED
    assert r.error_code == "AWS_STS_SESSION_TOKEN_NOT_BOUND" and client.calls == []


def test_aws_verifier_sts_rejects_malformed_context_token_without_calling():
    client = FakeClient(FakeResp(200, STS_OK))
    r = AWSAccessKeyVerifier().verify(secret=SECRET40, identifier=ASIA, config=VerifierConfig(enabled=True),
                                      client=client, context={"aws_session_token": "bad\r\nInjected: 1"})
    assert r.state == VerificationState.UNSUPPORTED and client.calls == []


# --- HTTP verifier ---------------------------------------------------------

def _spec(det_id: str):
    return next(s for s in HTTP_VERIFY_SPECS if s.detector_id == det_id)


def test_http_github_verified_with_scopes():
    v = HTTPVerifier(_spec("github-token-v1"))
    client = FakeClient(FakeResp(200, "{}", {"X-OAuth-Scopes": "repo, read:org"}))
    r = v.verify(secret=GH, identifier="", config=VerifierConfig(enabled=True), client=client)
    assert r.state == VerificationState.VERIFIED
    assert r.facts["scopes"] == "repo, read:org" and r.facts["host"] == "github.com"
    # The token must be sent as "token <secret>" per GitHub docs.
    assert client.calls[0][2]["Authorization"] == f"token {GH}"


def test_http_github_rejected():
    v = HTTPVerifier(_spec("github-token-v1"))
    r = v.verify(secret=GH, identifier="", config=VerifierConfig(enabled=True),
                 client=FakeClient(FakeResp(401)))
    assert r.state == VerificationState.REJECTED


def test_http_slack_body_verdict():
    v = HTTPVerifier(_spec("slack-token-v1"))
    ok = v.verify(secret="xoxb-x", identifier="", config=VerifierConfig(enabled=True),
                  client=FakeClient(FakeResp(200, '{"ok":true,"user":"u"}')))
    assert ok.state == VerificationState.VERIFIED
    bad = v.verify(secret="xoxb-x", identifier="", config=VerifierConfig(enabled=True),
                   client=FakeClient(FakeResp(200, '{"ok":false,"error":"invalid_auth"}')))
    assert bad.state == VerificationState.REJECTED


@pytest.mark.parametrize("body", ['{"ok": false, "error": "ratelimited"}',
                                   '{"nested": {"ok":true}}', '{"ok": "true"}', '[]'])
def test_slack_ambiguous_body_is_inconclusive(body):
    result = HTTPVerifier(_spec("slack-token-v1"))._interpret(FakeResp(200, body))
    assert result.state == VerificationState.INDETERMINATE


def test_slack_json_spacing_does_not_change_the_root_verdict():
    verifier = HTTPVerifier(_spec("slack-token-v1"))
    assert verifier._interpret(FakeResp(200, '{"ok": true}')).state == VerificationState.VERIFIED
    assert verifier._interpret(FakeResp(500, '{"ok":true}')).state == VerificationState.INDETERMINATE


def test_forbidden_does_not_prove_credential_rejection():
    assert HTTPVerifier(_spec("github-token-v1"))._interpret(FakeResp(403)).state == VerificationState.INDETERMINATE


def test_scope_facts_and_aws_error_codes_are_bounded():
    result = HTTPVerifier(_spec("github-token-v1"))._interpret(FakeResp(200, "{}", {"X-OAuth-Scopes": "x" * 257}))
    assert "scopes" not in result.facts
    result = AWSAccessKeyVerifier._interpret(400, '<Error><Code>untrusted raw detail</Code></Error>')
    assert result.error_code == "HTTP_400"


def test_mixed_host_outcomes_cannot_prove_global_rejection():
    verifier = HTTPVerifier(_spec("github-token-v1"))
    result = verifier.verify(secret=GH, identifier="",
        config=VerifierConfig(enabled=True, cross_host=True, known_github_hosts=("ghe.example.com",)),
        client=RoutingClient({("GET", "https://api.github.com/user"): FakeResp(503),
                              ("GET", "https://ghe.example.com/api/v3/user"): FakeResp(401)}))
    assert result.state == VerificationState.INDETERMINATE


def test_http_stripe_uses_basic_auth():
    v = HTTPVerifier(_spec("stripe-secret-key-v1"))
    client = FakeClient(FakeResp(200, "{}"))
    v.verify(secret="sk_live_x", identifier="", config=VerifierConfig(enabled=True), client=client)
    assert client.calls[0][2]["Authorization"].startswith("Basic ")


def test_http_discord_bot_auth_scheme():
    v = HTTPVerifier(_spec("discord-bot-token-v1"))
    client = FakeClient(FakeResp(200, "{}"))
    v.verify(secret="tok", identifier="", config=VerifierConfig(enabled=True), client=client)
    assert client.calls[0][2]["Authorization"] == "Bot tok"


def test_every_http_spec_targets_a_real_detector():
    from cremore.detection.catalog import builtin_definitions

    ids = {d.catalog.id for d in builtin_definitions()}
    for spec in HTTP_VERIFY_SPECS:
        assert spec.detector_id in ids, f"verify spec {spec.detector_id} has no detector"


def test_all_http_specs_have_docs_and_known_auth():
    seen = set()
    for spec in HTTP_VERIFY_SPECS:
        assert spec.detector_id not in seen
        seen.add(spec.detector_id)
        assert spec.doc.startswith("http")
        assert spec.auth in {"bearer", "token", "bot", "header", "basic_user"}
        if spec.auth == "header":
            assert spec.header_name


# --- engine integration ----------------------------------------------------

def test_engine_annotates_verification_state():
    load_default_verifiers()
    client = FakeClient(FakeResp(200, "{}", {"X-OAuth-Scopes": "repo"}))
    engine = Engine(EngineConfig(verify=VerifierConfig(enabled=True), http_client=client))
    dets = engine.scan(DetectorInput(data=f"token: {GH}".encode()))
    gh = [d for d in dets if d.credential_type == "GITHUB_TOKEN"]
    assert gh, "github token not detected"
    assert gh[0].extra_safe_data["verification_state"] == "verified"
    assert gh[0].extra_safe_data["verification_scopes"] == "repo"
    assert gh[0].engine_verified is True


def test_engine_passive_when_verify_disabled():
    engine = Engine(EngineConfig())  # verification off by default
    dets = engine.scan(DetectorInput(data=f"token: {GH}".encode()))
    gh = next(d for d in dets if d.credential_type == "GITHUB_TOKEN")
    assert "verification_state" not in gh.extra_safe_data
    assert gh.engine_verified is None


def test_http_github_verified_records_owner_and_expiry_from_the_same_response():
    body = '{"login": "octo-bot", "id": 42, "type": "User", "email": "hidden@example.com"}'
    client = FakeClient(FakeResp(200, body, {"X-OAuth-Scopes": "repo", "GitHub-Authentication-Token-Expiration": "2026-12-01 09:30:00 UTC"}))
    r = HTTPVerifier(_spec("github-token-v1")).verify(secret=GH, identifier="", config=VerifierConfig(enabled=True), client=client)
    assert r.facts == {"scopes": "repo", "owner_name": "octo-bot", "owner_id": "42", "owner_kind": "User",
                       "expires_at": "2026-12-01T09:30:00+00:00", "host": "github.com"}
    assert len(client.calls) == 1  # nothing extra is requested


class RoutingClient:
    """Returns a FakeResp per (method, url-prefix); records every call."""

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def _resp(self, method, url):
        self.calls.append((method, url))
        # longest matching prefix wins, so /user/repos does not match /user
        best = max(((prefix, resp) for (m, prefix), resp in self.routes.items() if m == method and url.startswith(prefix)),
                   key=lambda pr: len(pr[0]), default=None)
        if best is None:
            raise AssertionError(f"unrouted {method} {url}")
        return best[1]

    def get(self, url, headers=None):
        return self._resp("GET", url)

    def post(self, url, headers=None, content=None):
        return self._resp("POST", url)

    def request(self, method, url, headers=None, content=None):
        return self._resp(method, url)

    def close(self):
        pass


def test_capability_probe_runs_only_when_enabled_and_only_after_a_verify():
    routes = {
        ("GET", "https://api.github.com/user"): FakeResp(200, "{}", {"X-OAuth-Scopes": ""}),
        ("GET", "https://api.github.com/user/repos"): FakeResp(200, "[{}]"),
        ("GET", "https://api.github.com/user/orgs"): FakeResp(403),
        ("GET", "https://api.github.com/gists"): FakeResp(200, "[]"),
    }
    v = HTTPVerifier(_spec("github-token-v1"))
    # off by default: no probe calls, only the verify call
    off = RoutingClient(routes)
    r = v.verify(secret=GH, identifier="", config=VerifierConfig(enabled=True), client=off)
    assert "capabilities" not in r.facts and off.calls == [("GET", "https://api.github.com/user")]
    # enabled: fixed read-only probes recorded as allowed/denied with a bounded count
    on = RoutingClient(routes)
    r = v.verify(secret=GH, identifier="", config=VerifierConfig(enabled=True, probe_capabilities=True), client=on)
    import json
    caps = json.loads(r.facts["capabilities"])
    assert caps == [{"name": "read_repositories", "status": "ALLOWED", "count": 1},
                    {"name": "read_organizations", "status": "DENIED"},
                    {"name": "read_gists", "status": "ALLOWED", "count": 0}]
    assert on.calls[0] == ("GET", "https://api.github.com/user") and len(on.calls) == 4


def test_github_verification_is_directed_at_the_host_the_token_was_found_on():
    v = HTTPVerifier(_spec("github-token-v1"))
    routes = {("GET", "https://ghe.example.com/api/v3/user"): FakeResp(200, "{}", {"X-OAuth-Scopes": "repo"})}
    r = v.verify(secret=GH, identifier="", config=VerifierConfig(enabled=True), client=RoutingClient(routes),
                 context={"github_host": "ghe.example.com"})
    assert r.state == VerificationState.VERIFIED and r.facts["host"] == "ghe.example.com"
    # a probe (if enabled) hits the same enterprise host, not github.com
    routes[("GET", "https://ghe.example.com/api/v3/user/repos")] = FakeResp(200, "[{}]")
    routes[("GET", "https://ghe.example.com/api/v3/user/orgs")] = FakeResp(200, "[]")
    routes[("GET", "https://ghe.example.com/api/v3/gists")] = FakeResp(200, "[]")
    on = RoutingClient(routes)
    r = v.verify(secret=GH, identifier="", config=VerifierConfig(enabled=True, probe_capabilities=True),
                 client=on, context={"github_host": "ghe.example.com"})
    assert all(u.startswith("https://ghe.example.com/api/v3/") for _, u in on.calls)


def test_a_lone_host_rejection_is_not_called_inactive_when_other_hosts_exist():
    v = HTTPVerifier(_spec("github-token-v1"))
    # only github.com known: a github.com rejection is a real rejection
    lone = v.verify(secret=GH, identifier="", config=VerifierConfig(enabled=True),
                    client=RoutingClient({("GET", "https://api.github.com/user"): FakeResp(401)}))
    assert lone.state == VerificationState.REJECTED and lone.facts["host"] == "github.com"
    # a GHES host is also registered: rejection by one host alone is inconclusive, not inactive
    cfg = VerifierConfig(enabled=True, known_github_hosts=("ghe.example.com",))
    unsure = v.verify(secret=GH, identifier="", config=cfg,
                      client=RoutingClient({("GET", "https://ghe.example.com/api/v3/user"): FakeResp(401)}),
                      context={"github_host": "ghe.example.com"})
    assert unsure.state == VerificationState.INDETERMINATE
    assert unsure.error_code == "REJECTED_ON_ghe.example.com_OTHER_HOSTS_UNCHECKED"


def test_cross_host_verification_confirms_a_token_on_another_registered_host():
    v = HTTPVerifier(_spec("github-token-v1"))
    routes = {("GET", "https://ghe.example.com/api/v3/user"): FakeResp(401),
              ("GET", "https://api.github.com/user"): FakeResp(200, "{}", {"X-OAuth-Scopes": "repo"})}
    # off: rejected on the found host, github.com not tried -> inconclusive (other hosts exist)
    off = v.verify(secret=GH, identifier="", config=VerifierConfig(enabled=True, known_github_hosts=("ghe.example.com",)),
                   client=RoutingClient(dict(routes)), context={"github_host": "ghe.example.com"})
    assert off.state == VerificationState.INDETERMINATE
    # on: the token is confirmed live on github.com
    on_client = RoutingClient(dict(routes))
    on = v.verify(secret=GH, identifier="", config=VerifierConfig(enabled=True, cross_host=True, known_github_hosts=("ghe.example.com",)),
                  client=on_client, context={"github_host": "ghe.example.com"})
    assert on.state == VerificationState.VERIFIED and on.facts["host"] == "github.com"
    assert [u for _, u in on_client.calls] == ["https://ghe.example.com/api/v3/user", "https://api.github.com/user"]


def test_host_ambiguous_github_verification_requires_explicit_cross_host_consent():
    v = HTTPVerifier(_spec("github-token-v1"))
    cfg = VerifierConfig(enabled=True, known_github_hosts=("ghe.example.com",))
    blocked = RoutingClient({})
    result = v.verify(secret=GH, identifier="", config=cfg, client=blocked, context={"source_type": "notion"})
    assert result.state == VerificationState.UNSUPPORTED
    assert result.error_code == "GITHUB_ISSUER_HOST_UNCONFIRMED" and not blocked.calls
    public = RoutingClient({("GET", "https://api.github.com/user"): FakeResp(200, "{}")})
    result = v.verify(secret=GH, identifier="", config=cfg, client=public, context={"source_type": "github"})
    assert result.state == VerificationState.VERIFIED and len(public.calls) == 1
    permitted = RoutingClient({("GET", "https://api.github.com/user"): FakeResp(200, "{}")})
    result = v.verify(secret=GH, identifier="", client=permitted, context={"source_type": "notion"},
                      config=VerifierConfig(enabled=True, known_github_hosts=("ghe.example.com",), cross_host=True))
    assert result.state == VerificationState.VERIFIED and len(permitted.calls) == 1


def test_gitlab_facts_keep_normal_names_but_omit_reflected_credentials():
    import json

    v = HTTPVerifier(_spec("gitlab-pat-v1"))
    secret = "synthetic-opaque-check-credential"
    normal = {"id": 42, "user_id": 19, "name": "build pipeline", "scopes": ["read_api"]}
    result = v.verify(secret=secret, identifier="", config=VerifierConfig(enabled=True),
                      client=FakeClient(FakeResp(200, json.dumps(normal))))
    assert result.facts["name"] == "build pipeline" and result.facts["token_id"] == "42"
    reflected = v.verify(secret=secret, identifier="", config=VerifierConfig(enabled=True),
                         client=FakeClient(FakeResp(200, json.dumps({**normal, "name": secret}))))
    assert "name" not in reflected.facts and reflected.facts["scopes"] == "read_api"
    other = v.verify(secret=secret, identifier="", config=VerifierConfig(enabled=True),
                     client=FakeClient(FakeResp(200, json.dumps({**normal, "name": GH}))))
    assert "name" not in other.facts


def test_capability_probe_is_skipped_when_the_credential_is_rejected():
    v = HTTPVerifier(_spec("github-token-v1"))
    client = RoutingClient({("GET", "https://api.github.com/user"): FakeResp(401)})
    r = v.verify(secret=GH, identifier="", config=VerifierConfig(enabled=True, probe_capabilities=True), client=client)
    assert r.state == VerificationState.REJECTED and client.calls == [("GET", "https://api.github.com/user")]


def test_notion_capability_probe_counts_reachable_shared_content():
    v = HTTPVerifier(_spec("notion-token-v1"))
    client = RoutingClient({
        ("GET", "https://api.notion.com/v1/users/me"): FakeResp(200, '{"name": "bot", "type": "bot"}'),
        ("POST", "https://api.notion.com/v1/search"): FakeResp(200, '{"results": [{"id": "p"}], "has_more": true}')})
    import json
    r = v.verify(secret="ntn_" + "a" * 46, identifier="", config=VerifierConfig(enabled=True, probe_capabilities=True), client=client)
    assert json.loads(r.facts["capabilities"]) == [{"name": "read_shared_content", "status": "ALLOWED", "count": 1}]


def test_http_notion_verified_records_bot_and_workspace_only_as_plain_values():
    body = ('{"object": "user", "id": "u-1", "name": "CreMore scan", "type": "bot", '
            r'"bot": {"owner": {"type": "workspace", "workspace": true}, "workspace_name": "Acme\u0000"}}')
    r = HTTPVerifier(_spec("notion-token-v1")).verify(secret="ntn_" + "a" * 46, identifier="",
                                                      config=VerifierConfig(enabled=True), client=FakeClient(FakeResp(200, body)))
    assert r.facts == {"owner_name": "CreMore scan", "owner_id": "u-1", "owner_kind": "bot", "context_owner_kind": "workspace"}
    malformed = HTTPVerifier(_spec("notion-token-v1")).verify(secret="ntn_" + "a" * 46, identifier="",
                                                              config=VerifierConfig(enabled=True), client=FakeClient(FakeResp(200, "not json")))
    assert malformed.state == VerificationState.VERIFIED and malformed.facts == {}
