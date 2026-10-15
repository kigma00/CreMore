"""OAuth 2.0 client credentials grant (RFC 6749 section 4.4), shared by callers.

The SIEM HTTPS sink uses it to reach Entra-protected ingestion APIs, and the
token refresher uses it to keep workload tokens current off Kubernetes. A
failure is a ``ValueError`` without the response body, the client secret or
the token, which callers turn into their own fixed codes.
"""

from __future__ import annotations

import base64
import re
from urllib.parse import quote, urlsplit

from cremore.http_client import bounded_request

MAX_RESPONSE_BYTES = 64 << 10
_CLIENT_ID = re.compile(r"[A-Za-z0-9._:@/-]{1,256}\Z")
_SCOPE = re.compile(r"[A-Za-z0-9._:/ -]{1,512}\Z")


class OAuthTokenError(ValueError):
    """``OAUTH_TOKEN_FAILED``; ``retryable`` unless the endpoint refused the client (a 4xx other than 429)."""

    def __init__(self, retryable: bool) -> None:
        super().__init__("OAUTH_TOKEN_FAILED")
        self.retryable = retryable


def https_url(value) -> str:
    parsed = urlsplit(value) if isinstance(value, str) else None
    if (parsed is None or parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.fragment or any(ord(c) < 33 or ord(c) > 126 for c in value)):
        raise ValueError("OAUTH_TOKEN_URL_INVALID")
    return value


class ClientCredentialsGrant:
    def __init__(self, *, token_url, client_id, client_secret, scope=None, audience=None,
                 auth_method="client_secret_post", token_field="access_token"):
        self.token_url = https_url(token_url)
        if not isinstance(client_id, str) or not _CLIENT_ID.fullmatch(client_id):
            raise ValueError("OAUTH_CLIENT_ID_INVALID")
        if auth_method not in ("client_secret_post", "client_secret_basic"):
            raise ValueError("OAUTH_AUTH_METHOD_INVALID")
        if token_field not in ("access_token", "id_token"):
            raise ValueError("OAUTH_TOKEN_FIELD_INVALID")
        self.form = {"grant_type": "client_credentials"}
        for name, value in (("scope", scope), ("audience", audience)):
            if value is not None:
                if not isinstance(value, str) or not _SCOPE.fullmatch(value):
                    raise ValueError("OAUTH_SCOPE_INVALID")
                self.form[name] = value
        self.client_id, self.auth_method, self.token_field = client_id, auth_method, token_field
        self.secret = client_secret  # a string, or a callable read on every request (file rotation)

    def _secret(self) -> str:
        value = self.secret() if callable(self.secret) else self.secret
        if not isinstance(value, str) or not value or len(value) > 8192 or any(not 33 <= ord(c) <= 126 for c in value):
            raise ValueError("OAUTH_CLIENT_SECRET_UNAVAILABLE")
        return value

    def fetch(self, client) -> tuple[str, int]:
        """Return (token, lifetime seconds). Any failure is one fixed ValueError (an ``OAuthTokenError``)."""
        secret = self._secret()
        form, headers = dict(self.form), {"Accept": "application/json"}
        if self.auth_method == "client_secret_basic":
            # RFC 6749 2.3.1: form-encode each part, then HTTP Basic.
            pair = f"{quote(self.client_id, safe='')}:{quote(secret, safe='')}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(pair).decode("ascii")
        else:
            form.update(client_id=self.client_id, client_secret=secret)
        refused = False
        try:
            response = bounded_request(client, "POST", self.token_url, data=form, headers=headers,
                                       max_response_bytes=MAX_RESPONSE_BYTES, retry_429=False, follow_redirects=False)
            if response.status_code != 200:
                refused = response.status_code < 500 and response.status_code != 429
                raise ValueError
            payload = response.json()
            token = payload[self.token_field]
            kind = payload.get("token_type", "Bearer")
            lifetime = payload.get("expires_in")
            if (not isinstance(token, str) or not token or len(token) > 16384
                    or any(not 33 <= ord(c) <= 126 for c in token)
                    or (self.token_field == "access_token" and str(kind).lower() != "bearer")):
                raise ValueError
            lifetime = int(lifetime) if lifetime is not None else 300
            if lifetime <= 0:
                raise ValueError
        except Exception:  # noqa: BLE001 -- token responses can echo credentials.
            raise OAuthTokenError(retryable=not refused) from None
        return token, lifetime
