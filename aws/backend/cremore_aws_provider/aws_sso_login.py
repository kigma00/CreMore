"""IAM Identity Center sign-in from the dashboard: what ``aws sso login --use-device-code`` does, run by the API.

The active profile's ``sso-session`` (start URL, Region) comes from the AWS CLI configuration CreMore already
reads. ``begin`` registers a public OIDC client with ``sso:account:access`` (so a refresh token comes back) and
starts a device authorization; the admin opens the verification link, signs in to the AWS access portal and
approves the code. ``complete`` then takes the token and saves it where ``aws sso login`` does -- the session's
file in ``~/.aws/sso/cache``, through botocore's own cache writer -- so every process that reads that cache,
the worker included, uses and refreshes it as before. Nothing is kept in CreMore's database: the pending
authorization's secret part is the caller's to seal until the admin approves.

Docs: https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_StartDeviceAuthorization.html,
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html
"""

from __future__ import annotations

import datetime as _dt
import json
import os

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
SCOPES = ["sso:account:access"]
# The states a poll answers, and those that end the attempt.
PENDING, DONE, EXPIRED, DENIED, FAILED = "PENDING", "DONE", "EXPIRED", "DENIED", "FAILED"


class LoginError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def sso_session() -> dict:
    """The active profile's Identity Center session, whole, or ``AWS_SSO_SESSION_REQUIRED``."""
    from cremore_aws_provider.aws_identity import local_sso_session

    found = local_sso_session()
    if not (found["session_name"] and found["region"] and found["start_url"]):
        raise LoginError("AWS_SSO_SESSION_REQUIRED")
    return found


def _oidc(region, factory=None):
    if factory is not None:
        return factory(region)
    import boto3

    # The SSO OIDC calls here take no AWS credentials.
    return boto3.Session().client("sso-oidc", region_name=region)


def _code(exc) -> str:
    return getattr(exc, "response", {}).get("Error", {}).get("Code", "") if hasattr(exc, "response") else ""


def begin(*, oidc_factory=None, now=None) -> tuple[dict, dict]:
    """``(shown, kept)``: what the admin sees (the code and the link) and what finishes it (the caller seals it)."""
    session = sso_session()
    clock = now or (lambda: _dt.datetime.now(_dt.UTC))
    oidc = _oidc(session["region"], oidc_factory)
    try:
        client = oidc.register_client(clientName=f"CreMore-{session['session_name']}"[:64], clientType="public",
                                      scopes=SCOPES)
        device = oidc.start_device_authorization(clientId=client["clientId"], clientSecret=client["clientSecret"],
                                                 startUrl=session["start_url"])
    except Exception:  # noqa: BLE001 -- an OIDC error can quote the request; only a code leaves
        raise LoginError("AWS_SSO_LOGIN_UNAVAILABLE") from None
    if not all(str(device.get(key) or "https://").startswith("https://") for key in ("verificationUri", "verificationUriComplete")):
        raise LoginError("AWS_SSO_LOGIN_UNAVAILABLE")  # the admin is sent to this link: AWS's, over https only
    started = clock()
    expires = started + _dt.timedelta(seconds=int(device.get("expiresIn") or 600))
    shown = {"user_code": device["userCode"], "verification_uri": device["verificationUri"],
             "verification_uri_complete": device.get("verificationUriComplete") or device["verificationUri"],
             "expires_at": expires.isoformat(), "interval": max(1, int(device.get("interval") or 5)),
             "start_url": session["start_url"]}
    kept = {"client_id": client["clientId"], "client_secret": client["clientSecret"],
            "registration_expires_at": int(client.get("clientSecretExpiresAt") or 0),
            "device_code": device["deviceCode"], "region": session["region"], "start_url": session["start_url"],
            "session_name": session["session_name"], "expires_at": expires.isoformat()}
    return shown, kept


def complete(kept: dict, *, oidc_factory=None, cache_dir=None, now=None) -> str:
    """Ask once whether the admin approved; on approval save the token where ``aws sso login`` does."""
    clock = now or (lambda: _dt.datetime.now(_dt.UTC))
    if clock() >= _dt.datetime.fromisoformat(kept["expires_at"]):
        return EXPIRED
    oidc = _oidc(kept["region"], oidc_factory)
    try:
        answer = oidc.create_token(grantType=DEVICE_GRANT, deviceCode=kept["device_code"],
                                   clientId=kept["client_id"], clientSecret=kept["client_secret"])
    except Exception as exc:  # noqa: BLE001 -- the OIDC errors name the state; nothing else leaves
        return {"AuthorizationPendingException": PENDING, "SlowDownException": PENDING,
                "ExpiredTokenException": EXPIRED, "AccessDeniedException": DENIED}.get(_code(exc), FAILED)
    token = answer.get("accessToken")
    if not isinstance(token, str) or not token:
        return FAILED
    save(kept, answer, cache_dir=cache_dir, now=clock())
    return DONE


def _dumps(token: dict) -> str:
    """JSON with times as botocore writes them in the SSO cache (UTC, ``2026-09-29T11:00:00Z``)."""
    return json.dumps(token, default=lambda value: value.astimezone(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))


def save(kept: dict, answer: dict, *, cache_dir=None, now) -> None:
    """The token as botocore refreshes it (SSOTokenProvider): the session's file, written atomically by its cache."""
    from botocore.utils import JSONFileCache, SSOTokenLoader

    token = {"startUrl": kept["start_url"], "region": kept["region"], "accessToken": answer["accessToken"],
             "expiresAt": now + _dt.timedelta(seconds=int(answer.get("expiresIn") or 3600)),
             "clientId": kept["client_id"], "clientSecret": kept["client_secret"],
             "registrationExpiresAt": _dt.datetime.fromtimestamp(kept["registration_expires_at"], _dt.UTC)}
    if answer.get("refreshToken"):
        token["refreshToken"] = answer["refreshToken"]
    directory = cache_dir or os.path.expanduser(os.path.join("~", ".aws", "sso", "cache"))
    try:
        SSOTokenLoader(cache=JSONFileCache(directory, dumps_func=_dumps)).save_token(
            kept["start_url"], token, session_name=kept["session_name"])
    except OSError:
        # The same read-only cache that stops botocore from refreshing (aws_sso.SsoCacheNotWritable).
        raise LoginError("SSO_CACHE_NOT_WRITABLE") from None
