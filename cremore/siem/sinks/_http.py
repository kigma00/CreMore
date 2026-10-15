"""Bounded HTTPS delivery to an operator-configured SIEM endpoint."""

from __future__ import annotations

import json
import os
import re
import ssl
from collections.abc import Mapping
from datetime import datetime
from urllib.parse import urlsplit

import httpx

from cremore.http_client import HTTPResponseTooLarge, bounded_request
from cremore.siem.contract import DeliveryError

MAX_RESPONSE_BYTES = 64 << 10
_OPTIONS = {"endpoint", "token_env", "timeout_seconds", "ca_file"}
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")


def json_line(value: object) -> str:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError):
        raise DeliveryError("INVALID_EVENT") from None


def event_time(event: dict) -> datetime:
    try:
        value = event["occurred_at"]
        if not isinstance(value, str):
            raise TypeError
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError
        return parsed
    except (KeyError, TypeError, ValueError, OverflowError):
        raise DeliveryError("INVALID_EVENT_TIME") from None


def _endpoint(value: object, required_path: str | None) -> str:
    try:
        if not isinstance(value, str) or any(
            char.isspace() or ord(char) < 32 or 127 <= ord(char) <= 159 for char in value
        ) or any(char in value for char in "\\?#"):
            raise ValueError
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or (parsed.port is not None and not 1 <= parsed.port <= 65535)
                or (required_path is not None and parsed.path != required_path)):
            raise ValueError
        httpx.URL(value)
        return value
    except (TypeError, ValueError, httpx.InvalidURL):
        raise ValueError("SIEM_ENDPOINT_INVALID") from None


class HTTPSink:
    def __init__(self, options: Mapping[str, object], *, scheme: str = "Bearer",
                 require_token: bool = False, required_path: str | None = None,
                 allow_scheme: bool = False):
        allowed = _OPTIONS | ({"authorization_scheme"} if allow_scheme else set())
        if not isinstance(options, Mapping) or set(options) - allowed:
            raise ValueError("SIEM_OPTIONS_INVALID")
        if allow_scheme and options.get("authorization_scheme", "Bearer") != "Bearer":
            raise ValueError("SIEM_AUTHORIZATION_SCHEME_INVALID")
        self._endpoint = _endpoint(options.get("endpoint"), required_path)
        timeout = options.get("timeout_seconds", 10)
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not 0 < timeout <= 30):
            raise ValueError("SIEM_TIMEOUT_INVALID")

        headers = {"Content-Type": "application/json"}
        if require_token or "token_env" in options:
            name = options.get("token_env")
            if not isinstance(name, str) or not _ENV_NAME.fullmatch(name):
                raise ValueError("SIEM_TOKEN_ENV_INVALID")
            token = os.environ.get(name, "")
            if not token or len(token) > 8192 or any(not 33 <= ord(c) <= 126 for c in token):
                raise ValueError("SIEM_TOKEN_UNAVAILABLE")
            headers["Authorization"] = f"{scheme} {token}"

        verify: bool | ssl.SSLContext = True
        if "ca_file" in options:
            ca_file = options["ca_file"]
            if (not isinstance(ca_file, str) or not ca_file
                    or any(ord(c) < 32 or ord(c) == 127 for c in ca_file)):
                raise ValueError("SIEM_CA_INVALID")
            try:
                verify = ssl.create_default_context(cafile=ca_file)
            except (OSError, ValueError):
                raise ValueError("SIEM_CA_INVALID") from None
        try:
            self._client = httpx.Client(headers=headers, timeout=float(timeout), verify=verify,
                                        follow_redirects=False, trust_env=False)
        except Exception:  # noqa: BLE001 -- transport setup must not expose credential/config details.
            raise ValueError("SIEM_CLIENT_CONFIGURATION_INVALID") from None

    def _post(self, payload: object, *, status: int | None = None):
        body = json_line(payload).encode("ascii")
        try:
            response = bounded_request(self._client, "POST", self._endpoint, content=body,
                                       max_response_bytes=MAX_RESPONSE_BYTES, retry_429=False)
            accepted = response.status_code == status if status is not None else 200 <= response.status_code < 300
            if not accepted:
                # A refused credential is its own code, so an operator knows to
                # rotate the token rather than look at the receiver.
                raise DeliveryError("AUTH_FAILED" if response.status_code in (401, 403) else "HTTP_STATUS_REJECTED")
            return response
        except DeliveryError:
            raise
        except HTTPResponseTooLarge:
            raise DeliveryError("RESPONSE_TOO_LARGE") from None
        except Exception:  # noqa: BLE001 -- all transport diagnostics stay behind the sink boundary.
            raise DeliveryError("HTTP_DELIVERY_FAILED") from None

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # noqa: BLE001 -- transport cleanup can carry the same sensitive diagnostics.
            raise DeliveryError("SINK_CLOSE_FAILED") from None
