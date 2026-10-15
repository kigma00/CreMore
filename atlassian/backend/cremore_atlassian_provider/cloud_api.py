"""Confluence Cloud as a service account: its OAuth 2.0 client and the Atlassian API gateway.

A service account's OAuth 2.0 credential (a client ID and secret; Atlassian gives them no expiry) takes a
60-minute access token from ``https://auth.atlassian.com/oauth/token`` with the client credentials grant.
Such a token is answered only at the platform gateway, ``https://api.atlassian.com/ex/confluence/{cloudId}``
followed by the site's own path (``/wiki/api/v2/...``), never at the site's address, so the token goes
nowhere else. A site names its cloud ID, unauthenticated, at ``https://{site}/_edge/tenant_info``.

A worker process keeps one access token per client for every scan task and check that asks (a space scan runs
a task per page), and after a failed grant waits a minute before asking Atlassian again.

Docs: https://support.atlassian.com/user-management/docs/create-oauth-2-0-credential-for-service-accounts/,
https://developer.atlassian.com/cloud/confluence/oauth-2-3lo-apps/,
https://support.atlassian.com/jira/kb/retrieve-my-atlassian-sites-cloud-id/
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
from urllib.parse import urlsplit

from cremore.http_client import bounded_request
from cremore.oauth_client import ClientCredentialsGrant

KIND = "atlassian_oauth"
TOKEN_URL = "https://auth.atlassian.com/oauth/token"
GATEWAY = "https://api.atlassian.com"
# What a scan reads, as the service account's OAuth scopes (granular): the space, its pages and their
# bodies, their attachments, and the change feed (CQL search) with the author of an exposed version.
SCOPES = ("read:space:confluence", "read:page:confluence", "read:attachment:confluence",
          "read:content-details:confluence")
_CLIENT = re.compile(r"[A-Za-z0-9._-]{8,256}")
_SECRET = re.compile(r"[\x21-\x7e]{16,1024}")
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_CLOUD_ID = re.compile(_UUID)
_GATEWAY_PATH = re.compile(f"/ex/confluence/{_UUID}/wiki")
_CLOUD_ID_TTL = 24 * 3600
_RETRY_AFTER = 60
_CAP = 1024
_CLOUD_IDS: dict[str, tuple[str, float]] = {}  # site origin -> (cloud ID, when read)
_TOKENS: dict[str, tuple[str, float]] = {}  # client -> (access token, good until)
_FAILED: dict[str, tuple[str, float]] = {}  # client -> (refusal code, ask again after)
# One grant at a time: a scan's concurrent readers that find the token stale ask Atlassian once.
# ponytail: one lock for every client in the process; per-client locks if many accounts renew at once.
_GRANT = threading.Lock()


class CloudError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _remember(cache, key, value):
    if len(cache) >= _CAP and key not in cache:
        cache.clear()  # ponytail: a full cache starts over; every entry is cheap to ask for again
    cache[key] = value


def envelope(client_id, client_secret) -> dict:
    """The sealed credential of a service account's OAuth client."""
    if not _CLIENT.fullmatch(client_id or "") or not _SECRET.fullmatch(client_secret or ""):
        raise CloudError("ATLASSIAN_OAUTH_CLIENT_INVALID")
    return {"auth_kind": KIND, "client_id": client_id, "client_secret": client_secret}


def cloud_id(client, site, budget=None) -> str:
    parts = urlsplit(site)
    origin = f"{parts.scheme}://{parts.netloc}"
    known = _CLOUD_IDS.get(origin)
    if known and time.monotonic() - known[1] < _CLOUD_ID_TTL:
        return known[0]
    if budget is not None:
        budget.consume()  # outside the try: a spent budget stops the scan as a budget stop
    found = None
    try:
        response = bounded_request(client, "GET", origin + "/_edge/tenant_info", headers={"Accept": "application/json"},
                                   follow_redirects=False, max_response_bytes=16 << 10)
        if response.status_code == 200:
            found = response.json().get("cloudId")
    except Exception:  # noqa: BLE001 -- an unreadable answer is one code
        found = None
    if not isinstance(found, str) or not _CLOUD_ID.fullmatch(found):
        raise CloudError("CONFLUENCE_CLOUD_ID_UNAVAILABLE")
    _remember(_CLOUD_IDS, origin, (found, time.monotonic()))
    return found


def api_site(site, client, budget=None) -> str:
    """Where the site's API answers a service account: the gateway for its cloud ID, with the site's path."""
    parts = urlsplit(site)
    if parts.hostname == urlsplit(GATEWAY).hostname:
        # Already a gateway address: only Confluence's, for one cloud ID.
        if parts.port not in (None, 443) or not _GATEWAY_PATH.fullmatch(parts.path):
            raise CloudError("CONFLUENCE_GATEWAY_ADDRESS_INVALID")
        return site
    return f"{GATEWAY}/ex/confluence/{cloud_id(client, site, budget)}{parts.path}"


class ClientToken:
    """The service account's access token, shared in this process and asked for again shortly before it expires."""

    # A token only the gateway answers (confluence_content.SourceHTTP sends it there, not to the site).
    gateway = True

    def __init__(self, credential, *, client=None, timeout=30):
        credential = credential or {}
        envelope(credential.get("client_id"), credential.get("client_secret"))
        self.credential, self.client, self.timeout = dict(credential), client, timeout
        self.key = hashlib.sha256(f"{credential['client_id']}\0{credential['client_secret']}".encode()).hexdigest()

    def stale(self) -> bool:
        """Whether the next use asks Atlassian for a token (a request a scan's budget counts)."""
        token, until = _TOKENS.get(self.key, (None, 0.0))
        return not token or time.monotonic() >= until

    def __call__(self):
        token, until = _TOKENS.get(self.key, (None, 0.0))
        if token and time.monotonic() < until:
            return token
        with _GRANT:
            return self._grant()

    def _grant(self):
        # Readers that waited for the lock take the token the first of them was granted.
        now = time.monotonic()
        token, until = _TOKENS.get(self.key, (None, 0.0))
        if token and now < until:
            return token
        code, after = _FAILED.get(self.key, (None, 0.0))
        if code and now < after:
            raise CloudError(code)
        client = self.client
        if client is None:
            import httpx

            client = httpx.Client(timeout=self.timeout, follow_redirects=False)
        try:
            grant = ClientCredentialsGrant(token_url=TOKEN_URL, client_id=self.credential["client_id"],
                                           client_secret=self.credential["client_secret"])
            token, seconds = grant.fetch(client)
        except ValueError as exc:
            # A refusal is the client's; no answer, a 429 or a 5xx is Atlassian's (oauth_client.OAuthTokenError).
            code = "ATLASSIAN_OAUTH_UNAVAILABLE" if getattr(exc, "retryable", False) else "ATLASSIAN_OAUTH_TOKEN_REFUSED"
            _remember(_FAILED, self.key, (code, time.monotonic() + _RETRY_AFTER))
            raise CloudError(code) from None
        finally:
            if client is not self.client:
                client.close()
        _FAILED.pop(self.key, None)
        _remember(_TOKENS, self.key, (token, time.monotonic() + max(30, seconds - 300)))
        return token


class ContentToken(ClientToken):
    """The same, for a content scan: a refusal is the scan's error code."""

    def __call__(self):
        from cremore.collectors.base import CollectorError

        try:
            return super().__call__()
        except CloudError as exc:
            raise CollectorError(exc.code) from None


def content_token(provider, credential):
    """A Confluence source's token; any other source refuses the envelope (it would send the token elsewhere)."""
    if provider != "confluence":
        raise CloudError("ATLASSIAN_OAUTH_NOT_FOR_THIS_SOURCE")
    return ContentToken(credential)
