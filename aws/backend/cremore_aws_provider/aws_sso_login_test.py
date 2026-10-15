"""IAM Identity Center sign-in from the dashboard against a synthetic SSO OIDC: the device authorization, each
answer the poll can get, and the token saved where botocore reads and refreshes it."""

import datetime as _dt
import hashlib
import json

import botocore.session
import pytest
from botocore.exceptions import ClientError
from botocore.tokens import SSOTokenProvider, _sso_json_dumps
from botocore.utils import JSONFileCache

from cremore_aws_provider import aws_identity, aws_sso_login

SESSION = {"region": "ap-northeast-2", "start_url": "https://d-9067000000.awsapps.com/start", "session_name": "cremore"}
NOW = _dt.datetime(2026, 9, 29, 3, 0, tzinfo=_dt.UTC)
# Built at run time: nothing token-shaped sits in the source.
ACCESS = "synthetic-access-" + "a" * 24
REFRESH = "synthetic-refresh-" + "r" * 24


def refused(code):
    return ClientError({"Error": {"Code": code, "Message": "synthetic"}}, "CreateToken")


class Oidc:
    def __init__(self, answers=()):
        self.answers, self.calls = list(answers), []

    def register_client(self, **kwargs):
        self.calls.append(("register_client", kwargs))
        return {"clientId": "client-1", "clientSecret": "client-secret-1",
                "clientSecretExpiresAt": int((NOW + _dt.timedelta(days=90)).timestamp())}

    def start_device_authorization(self, **kwargs):
        self.calls.append(("start_device_authorization", kwargs))
        return {"deviceCode": "device-1", "userCode": "ABCD-EFGH", "verificationUri": "https://device.sso.ap-northeast-2.amazonaws.com/",
                "verificationUriComplete": "https://device.sso.ap-northeast-2.amazonaws.com/?user_code=ABCD-EFGH",
                "expiresIn": 600, "interval": 5}

    def create_token(self, **kwargs):
        self.calls.append(("create_token", kwargs))
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture(autouse=True)
def profile(monkeypatch):
    monkeypatch.setattr(aws_identity, "local_sso_session", lambda: dict(SESSION))


def test_the_admin_sees_the_code_and_the_link_and_the_rest_stays_on_the_server():
    oidc = Oidc()
    shown, kept = aws_sso_login.begin(oidc_factory=lambda region: oidc, now=lambda: NOW)
    assert shown == {"user_code": "ABCD-EFGH", "verification_uri": "https://device.sso.ap-northeast-2.amazonaws.com/",
                     "verification_uri_complete": "https://device.sso.ap-northeast-2.amazonaws.com/?user_code=ABCD-EFGH",
                     "expires_at": (NOW + _dt.timedelta(minutes=10)).isoformat(), "interval": 5,
                     "start_url": SESSION["start_url"]}
    assert "device-1" not in json.dumps(shown) and "client-secret-1" not in json.dumps(shown)
    assert kept["device_code"] == "device-1" and kept["client_secret"] == "client-secret-1"
    register = dict(oidc.calls)["register_client"]
    assert register == {"clientName": "CreMore-cremore", "clientType": "public", "scopes": ["sso:account:access"]}
    assert dict(oidc.calls)["start_device_authorization"]["startUrl"] == SESSION["start_url"]


def test_each_answer_of_a_poll_is_a_state():
    _shown, kept = aws_sso_login.begin(oidc_factory=lambda region: Oidc(), now=lambda: NOW)
    for code, state in (("AuthorizationPendingException", "PENDING"), ("SlowDownException", "PENDING"),
                        ("ExpiredTokenException", "EXPIRED"), ("AccessDeniedException", "DENIED"),
                        ("InvalidClientException", "FAILED")):
        oidc = Oidc([refused(code)])
        assert aws_sso_login.complete(kept, oidc_factory=lambda region, o=oidc: o, now=lambda: NOW) == state
    later = NOW + _dt.timedelta(minutes=11)
    assert aws_sso_login.complete(kept, oidc_factory=lambda region: Oidc(), now=lambda: later) == "EXPIRED"


def test_an_approved_sign_in_is_saved_where_botocore_reads_and_refreshes_it(tmp_path):
    _shown, kept = aws_sso_login.begin(oidc_factory=lambda region: Oidc(), now=lambda: NOW)
    oidc = Oidc([{"accessToken": ACCESS, "expiresIn": 28800, "refreshToken": REFRESH, "tokenType": "Bearer"}])
    assert aws_sso_login.complete(kept, oidc_factory=lambda region: oidc, cache_dir=str(tmp_path), now=lambda: NOW) == "DONE"
    assert dict(oidc.calls)["create_token"] == {"grantType": "urn:ietf:params:oauth:grant-type:device_code",
                                                "deviceCode": "device-1", "clientId": "client-1",
                                                "clientSecret": "client-secret-1"}
    stored = json.loads((tmp_path / (hashlib.sha1(b"cremore").hexdigest() + ".json")).read_text())
    assert stored["accessToken"] == ACCESS and stored["refreshToken"] == REFRESH and stored["clientId"] == "client-1"
    assert stored["expiresAt"] == "2026-09-29T11:00:00Z" and stored["startUrl"] == SESSION["start_url"]
    # botocore's own token provider, as the worker runs it, finds the saved sign-in.
    config = tmp_path / "config"
    config.write_text("[profile cremore]\nsso_session = cremore\n\n[sso-session cremore]\n"
                      f"sso_start_url = {SESSION['start_url']}\nsso_region = {SESSION['region']}\n"
                      "sso_registration_scopes = sso:account:access\n")
    session = botocore.session.Session(profile="cremore")
    session.set_config_variable("config_file", str(config))
    provider = SSOTokenProvider(session, cache=JSONFileCache(str(tmp_path), dumps_func=_sso_json_dumps),
                                time_fetcher=lambda: NOW, profile_name="cremore")
    assert provider.load_token().get_frozen_token().token == ACCESS


def test_a_profile_without_an_identity_center_session_cannot_start(monkeypatch):
    monkeypatch.setattr(aws_identity, "local_sso_session", lambda: {"region": None, "start_url": None, "session_name": None})
    with pytest.raises(aws_sso_login.LoginError, match="AWS_SSO_SESSION_REQUIRED"):
        aws_sso_login.begin(oidc_factory=lambda region: Oidc())


def test_an_unwritable_cache_is_its_own_code(tmp_path, monkeypatch):
    _shown, kept = aws_sso_login.begin(oidc_factory=lambda region: Oidc(), now=lambda: NOW)

    def refuse(*_args, **_kwargs):
        raise PermissionError(13, "read-only")

    monkeypatch.setattr("botocore.utils.JSONFileCache.__setitem__", refuse)
    oidc = Oidc([{"accessToken": ACCESS, "expiresIn": 3600}])
    with pytest.raises(aws_sso_login.LoginError, match="SSO_CACHE_NOT_WRITABLE"):
        aws_sso_login.complete(kept, oidc_factory=lambda region: oidc, cache_dir=str(tmp_path), now=lambda: NOW)


def test_only_an_https_verification_link_is_shown():
    class Elsewhere(Oidc):
        def start_device_authorization(self, **kwargs):
            return {**super().start_device_authorization(**kwargs), "verificationUriComplete": "http://device.example/?user_code=X"}

    with pytest.raises(aws_sso_login.LoginError, match="AWS_SSO_LOGIN_UNAVAILABLE"):
        aws_sso_login.begin(oidc_factory=lambda region: Elsewhere(), now=lambda: NOW)
