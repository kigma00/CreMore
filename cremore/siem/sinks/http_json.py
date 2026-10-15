"""POST one sanitized event to an operator-configured HTTPS endpoint.

The generic HTTPS path for SIEMs without a dedicated sink. Authentication is one
of: a token with a ``Bearer`` or ``ApiKey`` scheme (``token_env``), an API key
header (``api_key_header``: Datadog ``DD-API-KEY`` and the like), or OAuth 2.0
client credentials (``oauth``: RFC 6749 section 4.4, e.g. Microsoft Sentinel's
Logs Ingestion API with Entra ID). ``headers`` adds header values read from the
environment. ``body: "array"`` wraps the event in a one-element array
(Sentinel), ``query`` adds fixed parameters (``api-version``), and an endpoint
path may carry ``{event_id}`` so a retried event lands on the same document
(Elasticsearch ``_create/{id}``; with ``conflict_is_duplicate`` a 409 means the
first attempt already arrived). Secrets are always environment variable names.
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import Mapping
from urllib.parse import urlsplit

import httpx

from cremore.http_client import HTTPResponseTooLarge, bounded_request
from cremore.oauth_client import ClientCredentialsGrant
from cremore.siem.contract import DeliveryError, SinkProvider
from cremore.siem.sinks._http import MAX_RESPONSE_BYTES, HTTPSink, json_line

_ENV = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_HEADER = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}\Z")
_RESERVED = {"host", "content-length", "content-type", "transfer-encoding", "connection", "authorization"}
_QUERY_KEY = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
_QUERY_VALUE = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_PLACEHOLDER = "{event_id}"
_EXTENDED = {"authorization_scheme", "api_key_header", "headers", "oauth", "body", "query", "conflict_is_duplicate"}


def _secret(name: object, code: str) -> str:
    if not isinstance(name, str) or not _ENV.fullmatch(name):
        raise ValueError(code)
    value = os.environ.get(name, "")
    if not value or len(value) > 8192 or any(not 33 <= ord(c) <= 126 for c in value):
        raise ValueError("SIEM_TOKEN_UNAVAILABLE")
    return value


class OAuthClientCredentials:
    """Fetch and cache an access token; refreshed before expiry and after a 401."""

    def __init__(self, options: object, *, timeout: float, verify, clock=time.monotonic):
        allowed = {"token_url", "client_id", "client_secret_env", "scope", "audience", "auth_method"}
        if not isinstance(options, Mapping) or set(options) - allowed:
            raise ValueError("SIEM_OAUTH_INVALID")
        secret = _secret(options.get("client_secret_env"), "SIEM_OAUTH_INVALID")
        try:
            self._grant = ClientCredentialsGrant(
                token_url=options.get("token_url"), client_id=options.get("client_id"), client_secret=secret,
                scope=options.get("scope"), audience=options.get("audience"),
                auth_method=options.get("auth_method", "client_secret_post"))
        except ValueError:
            raise ValueError("SIEM_OAUTH_INVALID") from None
        self._clock, self._token, self._valid_until = clock, "", 0.0
        try:
            self._client = httpx.Client(timeout=timeout, verify=verify, follow_redirects=False, trust_env=False)
        except Exception:  # noqa: BLE001 -- transport setup must not expose credentials.
            raise ValueError("SIEM_CLIENT_CONFIGURATION_INVALID") from None

    def invalidate(self) -> None:
        self._token, self._valid_until = "", 0.0

    def token(self) -> str:
        now = self._clock()
        if self._token and now < self._valid_until:
            return self._token
        try:
            token, lifetime = self._grant.fetch(self._client)
        except ValueError:
            raise DeliveryError("OAUTH_TOKEN_FAILED") from None
        self._token = token
        self._valid_until = now + lifetime - min(60, lifetime / 2)
        return token

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # noqa: BLE001 -- see HTTPSink.close.
            raise DeliveryError("SINK_CLOSE_FAILED") from None


class HttpJsonSink(HTTPSink):
    def __init__(self, options):
        if not isinstance(options, Mapping) or not options:
            raise ValueError("SIEM_OPTIONS_INVALID")
        base = {key: value for key, value in options.items() if key not in _EXTENDED}
        endpoint = base.get("endpoint")
        self._templated = isinstance(endpoint, str) and _PLACEHOLDER in endpoint
        if self._templated:
            if endpoint.count(_PLACEHOLDER) != 1 or _PLACEHOLDER not in urlsplit(endpoint).path:
                raise ValueError("SIEM_ENDPOINT_INVALID")
            base["endpoint"] = endpoint.replace(_PLACEHOLDER, "00000000-0000-4000-8000-000000000000")
        auth = [key for key in ("token_env", "api_key_header", "oauth") if key in options]
        if len(auth) > 1:
            raise ValueError("SIEM_AUTHENTICATION_AMBIGUOUS")
        scheme = options.get("authorization_scheme", "Bearer")
        if scheme not in ("Bearer", "ApiKey") or (scheme == "ApiKey" and "token_env" not in options):
            # ApiKey is Elasticsearch's "Authorization: ApiKey <base64 id:key>".
            raise ValueError("SIEM_AUTHORIZATION_SCHEME_INVALID")
        # Every option is checked before a client exists, so a refused
        # configuration never opens a connection.
        headers = {}
        if "api_key_header" in options:
            spec = options["api_key_header"]
            if not isinstance(spec, Mapping) or set(spec) != {"name", "value_env"}:
                raise ValueError("SIEM_API_KEY_HEADER_INVALID")
            headers[self._header_name(spec["name"])] = _secret(spec["value_env"], "SIEM_API_KEY_HEADER_INVALID")
        extra = options.get("headers", {})
        if not isinstance(extra, Mapping) or len(extra) > 8:
            raise ValueError("SIEM_HEADERS_INVALID")
        for name, spec in extra.items():
            if not isinstance(spec, Mapping) or set(spec) != {"value_env"}:
                raise ValueError("SIEM_HEADERS_INVALID")
            key = self._header_name(name)
            if key.lower() in {item.lower() for item in headers}:
                raise ValueError("SIEM_HEADERS_INVALID")
            headers[key] = _secret(spec["value_env"], "SIEM_HEADERS_INVALID")
        query = options.get("query", {})
        if (not isinstance(query, Mapping) or len(query) > 8
                or any(not isinstance(k, str) or not _QUERY_KEY.fullmatch(k) or not isinstance(v, str)
                       or not _QUERY_VALUE.fullmatch(v) for k, v in query.items())):
            raise ValueError("SIEM_QUERY_INVALID")
        body = options.get("body", "object")
        if body not in ("object", "array"):
            raise ValueError("SIEM_BODY_INVALID")
        conflict = options.get("conflict_is_duplicate", False)
        if type(conflict) is not bool or (conflict and not self._templated):
            # Only a path naming the event makes a conflict mean "already delivered".
            raise ValueError("SIEM_CONFLICT_OPTION_INVALID")
        super().__init__(base, scheme=scheme)
        self._template = endpoint if self._templated else None
        self._client.headers.update(headers)
        self._query, self._array, self._conflict = dict(query), body == "array", conflict
        self._oauth = None
        if "oauth" in options:
            try:
                self._oauth = OAuthClientCredentials(options["oauth"], timeout=self._client.timeout.read or 10.0,
                                                     verify=True)
            except ValueError:
                self._client.close()
                raise

    @staticmethod
    def _header_name(name) -> str:
        if not isinstance(name, str) or not _HEADER.fullmatch(name) or name.lower() in _RESERVED:
            raise ValueError("SIEM_HEADERS_INVALID")
        return name

    def send(self, event: dict) -> None:
        url = self._endpoint
        if self._templated:
            identifier = str(event.get("event_id", ""))
            if not re.fullmatch(r"[0-9a-f-]{36}", identifier):
                raise DeliveryError("INVALID_EVENT")
            url = self._template.replace(_PLACEHOLDER, identifier)
        payload = [event] if self._array else event
        for attempt in (1, 2):
            headers = {"Authorization": "Bearer " + self._oauth.token()} if self._oauth else None
            response = self._send(url, payload, headers)
            if response.status_code == 401 and self._oauth and attempt == 1:
                self._oauth.invalidate()  # A revoked or rotated token: fetch once more.
                continue
            if 200 <= response.status_code < 300 or (self._conflict and response.status_code == 409):
                return
            if response.status_code in (401, 403):
                raise DeliveryError("AUTH_FAILED")
            raise DeliveryError("HTTP_STATUS_REJECTED")

    def _send(self, url, payload, headers):
        body = json_line(payload).encode("ascii")
        try:
            return bounded_request(self._client, "POST", url, content=body, params=self._query or None,
                                   headers=headers, max_response_bytes=MAX_RESPONSE_BYTES, retry_429=False)
        except HTTPResponseTooLarge:
            raise DeliveryError("RESPONSE_TOO_LARGE") from None
        except Exception:  # noqa: BLE001 -- all transport diagnostics stay behind the sink boundary.
            raise DeliveryError("HTTP_DELIVERY_FAILED") from None

    def close(self) -> None:
        try:
            super().close()
        finally:
            if self._oauth is not None:
                self._oauth.close()


PROVIDER = SinkProvider(id="http_json", build=HttpJsonSink)
