"""IAM Identity Center sign-in from the dashboard: only on a single operator's install, only in place of a missing
sign-in, only the administrator who started it finishes it, nothing secret reaches the browser, and the approved
sign-in lands in the SSO cache. A synthetic OIDC, a synthetic identity probe and a scratch home: nothing reaches AWS."""

import datetime as _dt
import hashlib
import json
import os

import pytest
from botocore.exceptions import ClientError
from cremore_aws_provider import aws_identity
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.conftest import oidc_settings
from cremore.config import Settings
from cremore.db.repository import InMemoryRepository

TOKEN = "synthetic-admin-" + "x" * 32

SESSION = {"region": "ap-northeast-2", "start_url": "https://d-9067000000.awsapps.com/start", "session_name": "cremore"}
ACCESS = "synthetic-access-" + "b" * 24
APPROVER = "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_SecurityAudit_0123456789abcdef/approver@example.test"


class Oidc:
    def __init__(self):
        self.answers = [ClientError({"Error": {"Code": "AuthorizationPendingException"}}, "CreateToken"),
                        {"accessToken": ACCESS, "expiresIn": 3600, "refreshToken": "synthetic-refresh-" + "c" * 20}]
        self.tokens = 0

    def register_client(self, **kwargs):
        return {"clientId": "client-9", "clientSecret": "client-secret-9",
                "clientSecretExpiresAt": int((_dt.datetime.now(_dt.UTC) + _dt.timedelta(days=90)).timestamp())}

    def start_device_authorization(self, **kwargs):
        return {"deviceCode": "device-9", "userCode": "WXYZ-1234", "verificationUri": "https://device.sso.example/",
                "verificationUriComplete": "https://device.sso.example/?user_code=WXYZ-1234", "expiresIn": 600, "interval": 5}

    def create_token(self, **kwargs):
        self.tokens += 1
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


def _bearer(issuer, sub, group):
    return {"Authorization": "Bearer " + issuer.mint(sub=sub, groups=(group,))}


def stack(issuer, tmp_path, monkeypatch, *, signed_in=False, team=False, repo=None):
    """The API with a scratch home; its AWS identity is signed in once the SSO cache holds a token. A single
    operator's install (local sign-in) unless ``team`` (people sign in through the company IdP), where asking IAM
    Identity Center for anything fails the test. ``repo``: the database of an install that changed its sign-in."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setattr(aws_identity, "local_sso_session", lambda: dict(SESSION))
    cache = tmp_path / ".aws" / "sso" / "cache"

    def probe(**_kwargs):
        if signed_in or (cache.is_dir() and any(cache.iterdir())):
            return {"state": "READY", "kind": "IDENTITY_CENTER", "caller_arn": APPROVER, "account_id": "111111111111"}
        return {"state": "NO_CREDENTIALS", "error_code": "NoCredentialsError"}

    repo = InMemoryRepository() if repo is None else repo
    settings = (oidc_settings(FINGERPRINT_KEY="ab" * 32) if team
                else Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32))
    app = create_app(repo=repo, settings=settings, oidc_http_client=issuer, aws_identity_probe=probe)
    oidc = Oidc()
    app.state.aws_sso_oidc_factory = (lambda region: pytest.fail("IAM Identity Center asked")) if team else (lambda region: oidc)
    return repo, TestClient(app, headers={} if team else {"Authorization": "Bearer " + TOKEN}), oidc, cache


def test_an_administrator_signs_in_to_identity_center_from_the_dashboard(issuer, tmp_path, monkeypatch):
    repo, c, oidc, cache = stack(issuer, tmp_path, monkeypatch)

    started = c.post("/api/v1/aws/sso-login/start")
    assert started.status_code == 200 and started.headers["cache-control"] == "no-store"
    body = started.json()
    assert body["user_code"] == "WXYZ-1234" and body["verification_uri_complete"].endswith("user_code=WXYZ-1234")
    assert "device-9" not in started.text and "client-secret-9" not in started.text
    stored = json.dumps(repo.get_setting("aws_sso_login:" + body["session_id"])["value"])
    assert "device-9" not in stored and "client-secret-9" not in stored  # sealed

    poll = {"session_id": body["session_id"]}
    unknown = {"session_id": "00000000-0000-4000-8000-000000000000"}
    assert c.post("/api/v1/aws/sso-login/poll", json=unknown).status_code == 404
    assert c.post("/api/v1/aws/sso-login/poll", json=poll).json() == {"state": "PENDING", "code": None}
    assert c.post("/api/v1/aws/sso-login/poll", json=poll).json() == {"state": "DONE", "code": None}
    # Saved where `aws sso login` saves it; the flow keeps only its outcome and is not asked again.
    saved = cache / (hashlib.sha1(b"cremore").hexdigest() + ".json")
    assert json.loads(saved.read_text())["accessToken"] == ACCESS
    assert c.post("/api/v1/aws/sso-login/poll", json=poll).json()["state"] == "DONE" and oidc.tokens == 2
    assert "sealed" not in repo.get_setting("aws_sso_login:" + body["session_id"])["value"]
    # Who approved is who CreMore now runs as: the audit names that session.
    events = [(event.event_type, event.note) for event in repo.finding_events.values() if event.target_type == "aws_sso_login"]
    assert events == [("AWS_SSO_LOGIN_STARTED", SESSION["start_url"]), ("AWS_SSO_LOGIN_DONE", APPROVER)]
    # Now signed in: another sign-in is not started from here.
    refused = c.post("/api/v1/aws/sso-login/start")
    assert refused.status_code == 409 and refused.json()["detail"].startswith("AWS_SIGN_IN_PRESENT")


def test_a_team_install_reaches_aws_as_the_server_never_through_a_sign_in_here(issuer, tmp_path, monkeypatch):
    """With people signing in through the company IdP, whoever approved a code would become everyone's AWS identity:
    neither step runs, nothing is kept, and the identity view tells the console not to offer it."""
    repo, c, _oidc, _cache = stack(issuer, tmp_path, monkeypatch, team=True)
    admin, analyst = _bearer(issuer, "d", "g-admins"), _bearer(issuer, "a", "g-analysts")
    assert c.post("/api/v1/aws/sso-login/start", headers=analyst).status_code == 403  # roles first, as everywhere
    for path, body in (("start", None), ("poll", {"session_id": "00000000-0000-4000-8000-000000000000"})):
        refused = c.post(f"/api/v1/aws/sso-login/{path}", headers=admin, json=body)
        assert refused.status_code == 409 and refused.json()["detail"].startswith("AWS_SSO_LOGIN_SOLO_ONLY")
    assert repo.list_settings("aws_sso_login:") == []
    assert not [event for event in repo.finding_events.values() if event.target_type == "aws_sso_login"]
    assert c.get("/api/v1/aws/scanner-identity", headers=analyst).json()["sign_in_here"] is False
    _repo, solo, _oidc, _cache = stack(issuer, tmp_path, monkeypatch)
    assert solo.get("/api/v1/aws/scanner-identity").json()["sign_in_here"] is True


def test_only_the_admin_who_started_an_attempt_finishes_it_and_a_team_install_finishes_none(issuer, tmp_path, monkeypatch):
    """An attempt is bound to who started it; one a single operator's install left before people began signing in
    through the company IdP is redeemed by nobody, its own operator included, and goes once abandoned."""
    repo, solo, oidc, _cache = stack(issuer, tmp_path, monkeypatch)
    session_id = solo.post("/api/v1/aws/sso-login/start").json()["session_id"]
    key, poll = "aws_sso_login:" + session_id, {"session_id": session_id}
    pending = repo.get_setting(key)["value"]
    repo.put_setting(key, {**pending, "actor": "e"}, "e")  # another administrator's attempt
    assert solo.post("/api/v1/aws/sso-login/poll", json=poll).status_code == 404
    assert oidc.tokens == 0 and repo.get_setting(key)["value"]["state"] == "PENDING"
    repo.put_setting(key, pending, pending["actor"])
    _repo, team, _oidc, _cache = stack(issuer, tmp_path, monkeypatch, team=True, repo=repo)
    for sub in ("d", pending["actor"]):  # an IdP subject named as the single operator was gains nothing
        refused = team.post("/api/v1/aws/sso-login/poll", headers=_bearer(issuer, sub, "g-admins"), json=poll)
        assert refused.status_code == 409 and refused.json()["detail"].startswith("AWS_SSO_LOGIN_SOLO_ONLY")
    assert repo.get_setting(key)["value"] == pending
    repo.installation_settings[key]["updated_at"] -= _dt.timedelta(hours=1)  # abandoned
    assert team.post("/api/v1/aws/sso-login/poll", headers=_bearer(issuer, "d", "g-admins"), json=poll).status_code == 409
    assert repo.get_setting(key) is None


def test_a_working_sign_in_is_never_replaced_from_the_dashboard(issuer, tmp_path, monkeypatch):
    _repo, c, oidc, _cache = stack(issuer, tmp_path, monkeypatch, signed_in=True)
    refused = c.post("/api/v1/aws/sso-login/start")
    assert refused.status_code == 409 and refused.json()["detail"].startswith("AWS_SIGN_IN_PRESENT")
    assert oidc.tokens == 0


def test_one_poll_at_a_time_asks_aws_and_a_dead_claim_lets_the_next_in(issuer, tmp_path, monkeypatch):
    repo, c, oidc, _cache = stack(issuer, tmp_path, monkeypatch)
    session_id = c.post("/api/v1/aws/sso-login/start").json()["session_id"]
    key = "aws_sso_login:" + session_id
    pending = repo.get_setting(key)["value"]
    poll = {"session_id": session_id}
    # Another poll holds the attempt: this one answers PENDING and redeems nothing.
    now = _dt.datetime.now(_dt.UTC)
    repo.put_setting(key, {**pending, "state": "POLLING", "claimed_at": now.isoformat()}, "d")
    assert c.post("/api/v1/aws/sso-login/poll", json=poll).json() == {"state": "PENDING", "code": None}
    assert oidc.tokens == 0
    # A claim a minute old belongs to a poll that died: this one takes it over and asks AWS.
    repo.put_setting(key, {**pending, "state": "POLLING", "claimed_at": (now - _dt.timedelta(minutes=1)).isoformat()}, "d")
    assert c.post("/api/v1/aws/sso-login/poll", json=poll).json()["state"] == "PENDING"
    assert oidc.tokens == 1
    kept = repo.get_setting(key)["value"]
    assert kept["state"] == "PENDING" and "sealed" in kept and "claimed_at" not in kept


def test_without_an_identity_center_profile_the_sign_in_says_what_is_missing(issuer, tmp_path, monkeypatch):
    _repo, c, _oidc, _cache = stack(issuer, tmp_path, monkeypatch)
    monkeypatch.setattr(aws_identity, "local_sso_session", lambda: {"region": None, "start_url": None, "session_name": None})
    refused = c.post("/api/v1/aws/sso-login/start")
    assert refused.status_code == 409 and refused.json()["detail"].startswith("AWS_SSO_SESSION_REQUIRED")
    assert os.environ["HOME"] == str(tmp_path)
