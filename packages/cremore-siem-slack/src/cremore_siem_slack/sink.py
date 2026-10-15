"""Bounded Incoming Webhook delivery using only the public CreMore sink contract.

http.client avoids HTTP client's routine URL logging: a webhook path is a secret.
Each send owns one TLS connection; only the outbox retries and acknowledges.
"""

from __future__ import annotations

import http.client
import json
import math
import os
import re
import ssl
import time
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

from cremore.siem import DeliveryError

MAX_BODY_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 4096
_ENV = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_CODE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,95}\Z")
_WEBHOOK_PATH = re.compile(r"/services/[A-Z0-9]{1,64}/[A-Z0-9]{1,64}/[A-Za-z0-9_-]{1,256}\Z")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_ALERTS = {
    "finding.created": "New credential exposure",
    "finding.reappeared": "Credential exposure reappeared",
    "finding.location_added": "Credential found at a new location",
    "finding.forwarded": "Credential exposure shared for review",
    "siem.test": "CreMore Slack delivery test",
}


def _url(value, *, webhook=False):
    code = "SLACK_WEBHOOK_INVALID" if webhook else "SLACK_DASHBOARD_URL_INVALID"
    try:
        if (not isinstance(value, str) or not value or len(value) > 512
                or any(not 33 <= ord(c) <= 126 for c in value)
                or any(c in value for c in "\\?#<>|\"")):
            raise ValueError
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or (parsed.port is not None and not 1 <= parsed.port <= 65535)):
            raise ValueError
        if webhook:
            if (parsed.hostname not in ("hooks.slack.com", "hooks.slack-gov.com")
                    or parsed.port not in (None, 443) or not _WEBHOOK_PATH.fullmatch(parsed.path)):
                raise ValueError
            return parsed.hostname, parsed.path
        if (parsed.path not in ("", "/") or len(parsed.hostname) > 253
                or not all(_LABEL.fullmatch(label) for label in parsed.hostname.split("."))):
            raise ValueError
        return f"https://{parsed.netloc.lower()}"
    except (TypeError, ValueError):
        raise ValueError(code) from None


def _id(value):
    try:
        if not isinstance(value, str) or len(value) != 36:
            raise ValueError
        return str(uuid.UUID(value))
    except (TypeError, ValueError, AttributeError):
        raise DeliveryError("INVALID_EVENT") from None


def _code(value):
    return value if isinstance(value, str) and _CODE.fullmatch(value) else "UNKNOWN"


def _mapping(value):
    if not isinstance(value, dict):
        raise DeliveryError("INVALID_EVENT")
    return value


def _timestamp(value):
    try:
        if not isinstance(value, str) or len(value) > 40:
            raise ValueError
        stamp = datetime.fromisoformat(value)
        if stamp.tzinfo is None:
            raise ValueError
        return stamp.astimezone(UTC).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError):
        raise DeliveryError("INVALID_EVENT_TIME") from None


def _plain(text):
    return {"type": "plain_text", "text": text, "emoji": False}


def _payload(event, dashboard):
    event = _mapping(event)
    if type(event.get("schema_version")) is not int or event["schema_version"] != 1:
        raise DeliveryError("INVALID_EVENT")
    event_type = event.get("event_type")
    if not isinstance(event_type, str):
        raise DeliveryError("INVALID_EVENT")
    if event_type not in _ALERTS:
        return None  # This destination subscribes only to detection alerts and test events.
    title = _ALERTS[event_type]
    event_id, occurred = _id(event.get("event_id")), _timestamp(event.get("occurred_at"))
    lines = [title, f"Event: {event_type}", f"Observed: {occurred}", f"Event ID: {event_id}"]
    if event.get("installation_id") is not None:
        lines.append(f"Installation: {_id(event['installation_id'])}")
    credential_id = None
    if event_type != "siem.test":
        finding = _mapping(event.get("finding"))
        credential = _mapping(event.get("credential"))
        finding_id = _id(finding.get("id"))
        credential_id = _id(finding.get("credential_id"))
        severity = finding.get("severity")
        severity = severity if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else "UNKNOWN"
        lines += [f"Severity: {severity}", f"Issuer: {_code(credential.get('provider'))}",
                  f"Type: {_code(credential.get('credential_type'))}", f"Finding ID: {finding_id}"]
        if event.get("exposure") is not None:
            exposure = _mapping(event["exposure"])
            lines += [f"Found in: {_code(exposure.get('source_type'))}",
                      f"Exposure ID: {_id(exposure.get('id'))}"]
            if exposure.get("source_connection_id") is not None:
                lines.append(f"Source connection: {_id(exposure['source_connection_id'])}")
            line = exposure.get("line_number")
            if type(line) is int and 0 <= line <= 2**31 - 1:
                lines.append(f"Line: {line}")
        lines.append("Detection is an observation, not proof that the credential is valid.")
    summary = "\n".join(lines)
    blocks = [{"type": "section", "text": _plain(summary)}]
    if credential_id:
        blocks.append({"type": "actions", "elements": [{
            "type": "button", "text": _plain("Open finding in CreMore"),
            "url": f"{dashboard}/?view=exposed&id=credential%3A{credential_id}",
            "action_id": "open_finding",
        }]})
    return {"text": summary, "blocks": blocks, "mrkdwn": False, "parse": "none",
            "link_names": False, "unfurl_links": False, "unfurl_media": False}


def _retry_after(value):
    """Bound a receiver hint; the exporter applies it to durable available_at."""
    if not isinstance(value, str) or len(value) > 128:
        return None
    try:
        seconds = float(value)
    except ValueError:
        try:
            stamp = parsedate_to_datetime(value)
            if stamp.tzinfo is None:
                return None
            seconds = (stamp - datetime.now(UTC)).total_seconds()
        except (TypeError, ValueError, OverflowError):
            return None
    return min(86400, max(0, math.ceil(seconds))) if math.isfinite(seconds) else None


class SlackSink:
    def __init__(self, options: Mapping[str, object]):
        if (not isinstance(options, Mapping)
                or set(options) - {"webhook_url_env", "dashboard_base_url", "timeout_seconds"}):
            raise ValueError("SLACK_OPTIONS_INVALID")
        name = options.get("webhook_url_env")
        if not isinstance(name, str) or not _ENV.fullmatch(name):
            raise ValueError("SLACK_WEBHOOK_ENV_INVALID")
        self._host, self._path = _url(os.environ.get(name), webhook=True)
        self._dashboard = _url(options.get("dashboard_base_url"))
        timeout = options.get("timeout_seconds", 10)
        if type(timeout) not in (int, float) or not 0 < timeout <= 30:
            raise ValueError("SLACK_TIMEOUT_INVALID")
        self._timeout = float(timeout)
        try:
            self._tls = ssl.create_default_context()
            self._tls.minimum_version = ssl.TLSVersion.TLSv1_2
        except (OSError, ValueError):
            raise ValueError("SLACK_TLS_CONFIGURATION_INVALID") from None

    def send(self, event: dict) -> None:
        payload = _payload(event, self._dashboard)
        if payload is None:
            return
        body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        if len(body) > MAX_BODY_BYTES:
            raise DeliveryError("INVALID_EVENT")
        connection = response = None
        try:
            deadline = time.monotonic() + self._timeout
            connection = http.client.HTTPSConnection(self._host, timeout=self._timeout, context=self._tls)
            connection.set_debuglevel(0)
            connection.connect()
            # Retain the socket even when getresponse() handles Connection: close.
            sock = connection.sock
            self._remaining(sock, deadline)
            connection.request("POST", self._path, body, {
                "Content-Type": "application/json; charset=utf-8", "User-Agent": "CreMore-Slack/0.1",
            })
            self._remaining(sock, deadline)
            response = connection.getresponse()
            # Classify status before reading a possible large error body. No response text escapes.
            if response.status == 429:
                raise DeliveryError("DELIVERY_RATE_LIMITED",
                                    retry_after_seconds=_retry_after(response.getheader("Retry-After")))
            if response.status in (401, 403):
                raise DeliveryError("AUTH_FAILED")
            if response.status != 200:
                raise DeliveryError("HTTP_STATUS_REJECTED")
            chunks = bytearray()
            while True:
                self._remaining(sock, deadline)
                chunk = response.read1(min(1024, MAX_RESPONSE_BYTES + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
                if len(chunks) > MAX_RESPONSE_BYTES:
                    raise DeliveryError("RESPONSE_TOO_LARGE")
            if bytes(chunks).strip() != b"ok":
                raise DeliveryError("INVALID_RESPONSE")
        except DeliveryError:
            raise
        except TimeoutError:
            raise DeliveryError("DELIVERY_TIMEOUT") from None
        except Exception:  # noqa: BLE001 -- transport diagnostics may contain the webhook path.
            raise DeliveryError("HTTP_DELIVERY_FAILED") from None
        finally:
            # HTTPResponse can own the last socket reference after Connection: close.
            for resource in (response, connection):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:  # noqa: BLE001, S110 -- never log cleanup diagnostics.
                        pass  # Cleanup must not replace an accepted send or its sanitized error.

    @staticmethod
    def _remaining(sock, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        if sock is not None:
            sock.settimeout(remaining)

    def close(self) -> None:
        return None  # Every send closes its own connection.
