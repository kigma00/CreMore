"""Synthetic transport only: tests cannot send to Slack."""

import copy
import importlib.metadata
import io
import json
import logging
import ssl
import uuid
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import pytest
from cremore_siem_slack import PROVIDER
from cremore_siem_slack import sink as module

from cremore.siem import DeliveryError
from cremore.siem.registry import load_provider

WEBHOOK = "https://hooks.slack.com/services/TTEST/BTEST/syntheticWebhookSecret"
OPTIONS = {"webhook_url_env": "TEST_SLACK_WEBHOOK", "dashboard_base_url": "https://cremore.example.com"}


@pytest.fixture
def event():
    return {
        "schema_version": 1, "event_id": str(uuid.uuid4()), "event_type": "finding.created",
        "occurred_at": "2026-10-06T03:00:00Z", "installation_id": str(uuid.uuid4()),
        "finding": {"id": str(uuid.uuid4()), "credential_id": str(uuid.uuid4()), "severity": "HIGH"},
        "credential": {"provider": "gcp", "credential_type": "GCP_SERVICE_ACCOUNT_KEY"},
        "exposure": {"id": str(uuid.uuid4()), "source_type": "github",
                     "source_connection_id": str(uuid.uuid4()), "line_number": 12},
    }


class Response:
    def __init__(self, status=200, body=b"ok", headers=None):
        self.status, self.body, self.headers = status, body, headers or {}
        self.closed = False

    def getheader(self, name):
        return self.headers.get(name)

    def read1(self, size):
        chunk, self.body = self.body[:size], self.body[size:]
        return chunk

    def close(self):
        self.closed = True


@pytest.fixture
def transport(monkeypatch):
    monkeypatch.setenv("TEST_SLACK_WEBHOOK", WEBHOOK)
    state = {"calls": [], "connections": [], "response": Response(), "error": None}

    class Socket:
        def settimeout(self, seconds):
            assert 0 < seconds <= 30

    class Connection:
        def __init__(self, host, *, timeout, context):
            assert host in ("hooks.slack.com", "hooks.slack-gov.com")
            assert 0 < timeout <= 30
            assert context.verify_mode == ssl.CERT_REQUIRED
            assert context.check_hostname
            assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
            self.sock, self.closed = Socket(), False
            state["connections"].append(self)

        def set_debuglevel(self, level):
            assert level == 0

        def connect(self):
            pass

        def request(self, method, path, body, headers):
            state["calls"].append((method, path, body, headers))
            if state["error"]:
                raise state["error"]

        def getresponse(self):
            self.sock = None  # Simulate Connection: close; retained socket still has a deadline.
            return state["response"]

        def close(self):
            self.closed = True

    monkeypatch.setattr(module.http.client, "HTTPSConnection", Connection)
    return state


def test_installed_entry_point_is_explicitly_enabled():
    entries = list(importlib.metadata.entry_points(group="cremore.siem_sinks", name="slack_alerts"))
    assert len(entries) == 1
    assert entries[0].load() is PROVIDER
    assert PROVIDER.api_version == 1 and PROVIDER.event_schema_versions == (1,)
    with pytest.raises(ValueError, match="^SIEM_PLUGIN_NOT_ENABLED$"):
        load_provider("slack_alerts")
    assert load_provider("slack_alerts", allow_plugins=("slack_alerts",)) is PROVIDER


def test_acceptance_safe_fields_link_and_no_mutation(transport, event):
    original = copy.deepcopy(event)
    sink = PROVIDER.build(OPTIONS)
    sink.send(event)
    sink.close()
    assert event == original
    assert len(transport["calls"]) == 1
    method, path, body, headers = transport["calls"][0]
    payload = json.loads(body)
    assert method == "POST" and path == "/services/TTEST/BTEST/syntheticWebhookSecret"
    assert headers["Content-Type"].startswith("application/json")
    assert "Issuer: gcp" in payload["text"] and "Found in: github" in payload["text"]
    for value in ("HIGH", event["finding"]["id"], event["event_id"], event["occurred_at"],
                  event["exposure"]["id"], event["exposure"]["source_connection_id"]):
        assert value in payload["text"]
    assert payload["blocks"][1]["elements"][0]["url"] == (
        "https://cremore.example.com/?view=exposed&id=credential%3A" + event["finding"]["credential_id"])
    assert len(body) <= module.MAX_BODY_BYTES
    assert transport["connections"][0].closed


def test_ignores_raw_context_and_disables_slack_formatting(transport, event):
    event.update({"text": "raw-secret", "title": "<!channel>", "url": "https://evil.test/raw-secret"})
    event["credential"].update({"token": "raw-secret", "identifier": "raw-secret", "hint": "raw-secret"})
    event["exposure"].update({"path": "raw-secret", "title": "raw-secret", "context": "raw-secret",
                              "url": "https://evil.test/raw-secret", "source_type": "<!everyone>"})
    event["credential"]["provider"] = "<@U123|name>&*spoof*"
    PROVIDER.build(OPTIONS).send(event)
    body = transport["calls"][0][2]
    assert all(value not in body for value in (b"raw-secret", b"evil.test", b"<!", b"<@", b"spoof"))
    payload = json.loads(body)
    assert payload["mrkdwn"] is False and payload["link_names"] is False
    assert payload["parse"] == "none"
    assert payload["unfurl_links"] is False and payload["unfurl_media"] is False
    assert payload["blocks"][0]["text"]["type"] == "plain_text"
    assert "Issuer: UNKNOWN" in payload["text"] and "Found in: UNKNOWN" in payload["text"]


@pytest.mark.parametrize("kind", [
    "finding.created", "finding.reappeared", "finding.location_added", "finding.forwarded", "siem.test",
])
def test_subscribed_events(transport, event, kind):
    event["event_type"] = kind
    if kind == "siem.test":
        event.pop("finding")
        event.pop("credential")
        event.pop("exposure")
    PROVIDER.build(OPTIONS).send(event)
    assert kind in json.loads(transport["calls"][0][2])["text"]


@pytest.mark.parametrize("kind", ["platform.heartbeat", "audit.action", "finding.updated", "collection.failed"])
def test_unsubscribed_event_has_no_request(transport, event, kind):
    event["event_type"] = kind
    PROVIDER.build(OPTIONS).send(event)
    assert not transport["calls"] and not transport["connections"]


@pytest.mark.parametrize(("status", "body", "code"), [
    (200, b"not_ok raw-secret", "INVALID_RESPONSE"), (204, b"", "HTTP_STATUS_REJECTED"),
    (302, b"raw-secret", "HTTP_STATUS_REJECTED"), (401, b"raw-secret", "AUTH_FAILED"),
    (403, b"raw-secret", "AUTH_FAILED"), (500, b"raw-secret", "HTTP_STATUS_REJECTED"),
    (200, b"x" * (module.MAX_RESPONSE_BYTES + 1), "RESPONSE_TOO_LARGE"),
])
def test_status_body_bounds_and_redirects(transport, event, status, body, code):
    transport["response"] = Response(status, body, {"Location": "https://evil.test"})
    with pytest.raises(DeliveryError, match=f"^{code}$"):
        PROVIDER.build(OPTIONS).send(event)
    assert len(transport["calls"]) == 1 and transport["connections"][0].closed
    assert transport["response"].closed


@pytest.mark.parametrize(("hint", "expected"), [
    ("42", 42), ("1.2", 2), ("999999", 86400), ("-4", 0),
    ("NaN", None), ("inf", None), ("secret-value", None), (None, None),
])
def test_rate_limit_hints_without_internal_retry(transport, event, hint, expected):
    transport["response"] = Response(429, b"x" * (module.MAX_RESPONSE_BYTES + 1), {"Retry-After": hint})
    with pytest.raises(DeliveryError, match="^DELIVERY_RATE_LIMITED$") as caught:
        PROVIDER.build(OPTIONS).send(event)
    assert caught.value.retry_after_seconds == expected
    assert len(transport["calls"]) == 1 and transport["connections"][0].closed
    assert transport["response"].closed


def test_http_date_retry_hint():
    later = datetime.now(UTC) + timedelta(seconds=120)
    assert 118 <= module._retry_after(format_datetime(later)) <= 120


@pytest.mark.parametrize(("error", "code"), [
    (TimeoutError(WEBHOOK), "DELIVERY_TIMEOUT"),
    (OSError(WEBHOOK + " raw-secret"), "HTTP_DELIVERY_FAILED"),
    (ssl.SSLError(WEBHOOK), "HTTP_DELIVERY_FAILED"),
])
def test_transport_errors_are_sanitized(transport, event, error, code, caplog, capsys):
    transport["error"] = error
    caplog.set_level(logging.DEBUG)
    with pytest.raises(DeliveryError, match=f"^{code}$") as caught:
        PROVIDER.build(OPTIONS).send(event)
    assert caught.value.__suppress_context__
    assert "syntheticWebhookSecret" not in caplog.text + str(caught.value) + str(capsys.readouterr())
    assert len(transport["calls"]) == 1 and transport["connections"][0].closed


def test_deadline_stops_slow_response(transport, event, monkeypatch):
    ticks = iter((0, 0.1, 0.2, 11))
    monkeypatch.setattr(module.time, "monotonic", lambda: next(ticks))
    with pytest.raises(DeliveryError, match="^DELIVERY_TIMEOUT$"):
        PROVIDER.build(OPTIONS).send(event)
    assert transport["connections"][0].closed


def test_response_loss_retries_keep_stable_event_id(transport, event):
    sink = PROVIDER.build(OPTIONS)
    transport["error"] = TimeoutError()
    with pytest.raises(DeliveryError):
        sink.send(event)
    transport["error"] = None
    sink.send(event)
    assert transport["calls"][0][2] == transport["calls"][1][2]
    assert event["event_id"] in json.loads(transport["calls"][1][2])["text"]


@pytest.mark.parametrize("url", [
    "http://hooks.slack.com/services/T/B/secret", "https://hooks.slack.com.evil.test/services/T/B/secret",
    "https://user:" + "pass@hooks.slack.com/services/T/B/secret", "https://hooks.slack.com:444/services/T/B/secret",
    "https://127.0.0.1/services/T/B/secret", "https://hooks.slack.com/services/T/B/secret?x=1",
    "https://hooks.slack.com/services/T/B/secret#fragment", "https://hooks.slack.com/services/T/B/secret/extra",
    "https://hooks.slack.com/services/T/B/%73ecret", "https://hooks.slack.com/services/T/B/sec\nret",
    "https://hooks.slack.com/services/T/B/sec\\ret", "", None,
])
def test_webhook_destination_restrictions(transport, monkeypatch, url):
    if url is None:
        monkeypatch.delenv("TEST_SLACK_WEBHOOK")
    else:
        monkeypatch.setenv("TEST_SLACK_WEBHOOK", url)
    with pytest.raises(ValueError, match="^SLACK_WEBHOOK_INVALID$"):
        PROVIDER.build(OPTIONS)
    assert not transport["calls"]


def test_govslack_and_ignored_proxy_environment(transport, monkeypatch, event):
    monkeypatch.setenv("TEST_SLACK_WEBHOOK", WEBHOOK.replace("hooks.slack.com", "hooks.slack-gov.com"))
    monkeypatch.setenv("HTTPS_PROXY", "http://untrusted-proxy.example:8080")
    PROVIDER.build(OPTIONS).send(event)
    assert len(transport["calls"]) == 1


@pytest.mark.parametrize("url", [
    "http://cremore.test", "https://user:" + "secret@cremore.test", "https://cremore.test/?view=evil",
    "https://cremore.test/path", "https://cremore.test#part", "https://cremore.test|evil",
    "https://cremore.test\n", "//cremore.test", "https://cremore.test:99999", "https://cremore_test", None,
])
def test_dashboard_must_be_trusted_https_origin(transport, url):
    with pytest.raises(ValueError, match="^SLACK_DASHBOARD_URL_INVALID$"):
        PROVIDER.build({**OPTIONS, "dashboard_base_url": url})


@pytest.mark.parametrize("extra", [
    {"webhook_url": WEBHOOK}, {"channel": "C123"}, {"token": "raw-secret"}, {"verify_tls": False},
    {"timeout_seconds": 0}, {"timeout_seconds": 31}, {"timeout_seconds": True},
    {"timeout_seconds": float("nan")}, {"timeout_seconds": float("inf")},
    {"webhook_url_env": "BAD-NAME"},
])
def test_configuration_is_strict(transport, extra):
    with pytest.raises(ValueError, match="^SLACK_[A-Z_]+$"):
        PROVIDER.build({**OPTIONS, **extra})


@pytest.mark.parametrize("changes", [
    {"schema_version": True}, {"schema_version": 2}, {"schema_version": None},
    {"event_id": "https://evil.test"}, {"occurred_at": "raw-secret"},
    {"occurred_at": "2026-10-06T03:00:00"}, {"finding": {"id": "<!channel>"}},
    {"event_type": []}, {"credential": []},
])
def test_malformed_events_cannot_be_acknowledged_as_sent(transport, event, changes):
    event.update(changes)
    with pytest.raises(DeliveryError, match="^INVALID_EVENT(_TIME)?$"):
        PROVIDER.build(OPTIONS).send(event)
    assert not transport["calls"]


def test_body_budget_checked_before_transport(transport, event, monkeypatch):
    monkeypatch.setattr(module, "MAX_BODY_BYTES", 1)
    with pytest.raises(DeliveryError, match="^INVALID_EVENT$"):
        PROVIDER.build(OPTIONS).send(event)
    assert not transport["calls"]


def test_standard_library_transport_does_not_log_secret_path(monkeypatch, event, caplog, capsys):
    """Exercise real request/response framing with a socket that never touches the network."""
    monkeypatch.setenv("TEST_SLACK_WEBHOOK", WEBHOOK)
    sent = []

    class Socket:
        def sendall(self, value):
            sent.append(value)

        def setsockopt(self, *args):
            pass

        def makefile(self, *args):
            return io.BytesIO(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")

        def settimeout(self, value):
            assert 0 < value <= 10

        def close(self):
            pass

    class TLS:
        def wrap_socket(self, sock, *, server_hostname):
            assert server_hostname == "hooks.slack.com"
            return sock

    def connect(address, timeout, source_address):
        assert address == ("hooks.slack.com", 443) and timeout == 10
        return Socket()

    monkeypatch.setattr(module.ssl, "create_default_context", TLS)
    monkeypatch.setattr(module.http.client.socket, "create_connection", connect)
    monkeypatch.setattr(module.http.client.HTTPConnection, "debuglevel", 1)
    caplog.set_level(logging.DEBUG)
    PROVIDER.build(OPTIONS).send(event)
    assert b"POST /services/TTEST/BTEST/syntheticWebhookSecret HTTP/1.1" in b"".join(sent)
    assert "syntheticWebhookSecret" not in caplog.text + str(capsys.readouterr())
