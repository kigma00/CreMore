"""A GitLab access token that renews itself before it expires (the ``self_rotate`` or ``api`` scope).

GitLab's self-rotate (``POST /groups/:id/access_tokens/self/rotate``, ``/projects/:id/...``, or
``/personal_access_tokens/self/rotate``) revokes the calling token at once and answers with its successor. A
rotation retried with the revoked token revokes the whole token family, the successor included. So:

* the token is asked about itself first (``GET /personal_access_tokens/self``, which rotates nothing) and a
  rotation is attempted only for a token GitLab calls active;
* only a clear refusal (403, 404, 405; 400 for an expiry the instance does not allow) moves on to another endpoint or a
  shorter expiry -- anything else (a timeout, a 5xx, a malformed answer) may have rotated already and stops
  with ``GITLAB_ROTATION_UNCERTAIN``, never trying again with the same token;
* the caller keeps the successor before anything else (cremore.onboarding.renewal marks the attempt first).

Nothing here keeps or reports a token or a response body; a failure is a code.
"""

from __future__ import annotations

import datetime as _dt
import re
from urllib.parse import quote

from cremore.http_client import bounded_request

# ponytail: fixed lifetimes; an instance whose maximum is shorter than 30 days refuses both
# (GITLAB_ROTATION_REFUSED) -- make them a connection option when one does.
LIFETIMES = (90, 30)
_TOKEN = re.compile(r"[\x21-\x7e]{20,255}")


class RotationError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _date(value):
    if value in (None, ""):
        return None
    try:
        return _dt.date.fromisoformat(str(value)[:10]).isoformat()
    except ValueError:
        return None


def _call(client, method, url, token, **kwargs):
    return bounded_request(client, method, url, headers={"PRIVATE-TOKEN": token, "Accept": "application/json"},
                           max_response_bytes=64 << 10, follow_redirects=False, timeout=30, **kwargs)


def inspect(client, origin, token) -> dict:
    """What GitLab says about the token itself: ``{id, expires_at, created_at, scopes, active}``."""
    try:
        response = _call(client, "GET", f"{origin}/api/v4/personal_access_tokens/self", token)
    except Exception:  # noqa: BLE001 -- transport errors can carry the token header
        raise RotationError("GITLAB_UNAVAILABLE") from None
    if response.status_code == 401:
        raise RotationError("GITLAB_TOKEN_REVOKED")  # revoked, expired or wrong: never rotate with it
    if response.status_code != 200:
        raise RotationError("GITLAB_UNAVAILABLE" if response.status_code >= 500 or response.status_code == 429
                            else "GITLAB_TOKEN_UNREADABLE")
    try:
        body = response.json()
        scopes = [scope for scope in body.get("scopes") or [] if isinstance(scope, str)]
        return {"id": body.get("id") if type(body.get("id")) is int else None, "expires_at": _date(body.get("expires_at")),
                "created_at": str(body.get("created_at") or "")[:40] or None, "scopes": scopes,
                "active": body.get("active") is True and body.get("revoked") is not True}
    except (ValueError, AttributeError):
        raise RotationError("GITLAB_TOKEN_UNREADABLE") from None


def rotate(client, origin, token, scope, ident, *, today=None) -> dict:
    """Rotate the token once: ``{token, expires_at, created_at}`` of its successor."""
    today = today or _dt.datetime.now(_dt.UTC).date()
    info = inspect(client, origin, token)
    if not info["active"]:
        raise RotationError("GITLAB_TOKEN_REVOKED")
    if not {"api", "self_rotate"} & set(info["scopes"]):
        raise RotationError("GITLAB_SELF_ROTATE_SCOPE_REQUIRED")
    paths = ([f"/{scope}s/{quote(str(ident), safe='')}/access_tokens/self/rotate"] if scope in ("group", "project") else [])
    paths.append("/personal_access_tokens/self/rotate")
    for path in paths:
        for days in LIFETIMES:
            try:
                response = _call(client, "POST", f"{origin}/api/v4{path}", token,
                                 json={"expires_at": (today + _dt.timedelta(days=days)).isoformat()})
            except Exception:  # noqa: BLE001 -- it may have rotated: the old token is never used again
                raise RotationError("GITLAB_ROTATION_UNCERTAIN") from None
            status = response.status_code
            if status == 400:
                continue  # an expiry the instance does not allow: nothing rotated
            if status in (403, 404, 405):
                break  # not this kind of token, or not allowed here: nothing rotated
            if status not in (200, 201):
                raise RotationError("GITLAB_ROTATION_UNCERTAIN")
            try:
                body = response.json()
                successor = body["token"]
            except (ValueError, KeyError, TypeError, AttributeError):
                raise RotationError("GITLAB_ROTATION_UNCERTAIN") from None
            if not isinstance(successor, str) or not _TOKEN.fullmatch(successor):
                raise RotationError("GITLAB_ROTATION_UNCERTAIN")
            return {"token": successor, "expires_at": _date(body.get("expires_at")),
                    "created_at": str(body.get("created_at") or "")[:40] or None}
    raise RotationError("GITLAB_ROTATION_REFUSED")


def due(kept, now) -> str | None:
    """``inspect`` once a day, ``renew`` in the last third of the token's life (at most its last 30 days)."""
    seen = (kept or {}).get("seen_at")
    try:
        seen_at = _dt.datetime.fromisoformat(seen) if seen else None
    except ValueError:
        seen_at = None
    if seen_at is None or now - seen_at > _dt.timedelta(days=1):
        return "inspect"
    expires = _date((kept or {}).get("expires_at"))
    if not expires:
        return None  # a token without an expiry has nothing to renew before
    until = _dt.datetime.combine(_dt.date.fromisoformat(expires), _dt.time(), tzinfo=_dt.UTC)
    if until <= now:
        return None  # expired: only a new token helps
    try:
        born = _dt.datetime.fromisoformat(str(kept.get("created_at")))
        born = born if born.tzinfo else born.replace(tzinfo=_dt.UTC)
    except (TypeError, ValueError):
        born = until - _dt.timedelta(days=90)
    window = max(_dt.timedelta(days=1), min(_dt.timedelta(days=30), (until - born) / 3))
    return "renew" if until - now <= window else None
