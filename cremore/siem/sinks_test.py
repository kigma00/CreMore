"""Outbound payload and failure contracts, exercised without external sends."""

from __future__ import annotations

import io
import json
import ssl
import traceback
from types import SimpleNamespace

import httpx
import pytest

from cremore.siem.contract import DeliveryError
from cremore.siem.sinks import _http, http_json, jsonl, logscale, splunk_hec

EVENT = {"schema_version": 1, "event_id": "saved-event-1", "event_type": "finding.created", "finding_id": "finding-1",
         "occurred_at": "1970-01-01T00:00:01Z", "severity": "HIGH", "workflow_status": "OPEN"}
TOKEN_ENV = "CREMORE_TEST_SIEM_TOKEN"
TOKEN = "synthetic-ingest-token"
HTTP_PROVIDERS = [http_json.PROVIDER, splunk_hec.PROVIDER, logscale.PROVIDER]


def options(provider):
    path = {"http_json": "/custom/events", "splunk_hec": "/services/collector/event",
            "logscale": "/api/v1/ingest/humio-structured"}[provider.id]
    return {"endpoint": "https://siem.corp.example:8443" + path, "token_env": TOKEN_ENV}


@pytest.fixture
def wire(monkeypatch):
    real_client = httpx.Client
    state = SimpleNamespace(requests=[], configurations=[], clients=[],
                            response=lambda request: httpx.Response(200, json={"code": 0}))

    def handle(request):
        state.requests.append(request)
        return state.response(request)

    def client(**kwargs):
        state.configurations.append(kwargs.copy())
        result = real_client(**kwargs, transport=httpx.MockTransport(handle))
        state.clients.append(result)
        return result

    monkeypatch.setattr(_http.httpx, "Client", client)
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    yield state
    for client in state.clients:
        client.close()


def test_jsonl_one_compact_line_flushes_without_closing_process_stream(monkeypatch):
    class Output(io.StringIO):
        flushes = 0

        def flush(self):
            self.flushes += 1

    stream = Output()
    monkeypatch.setattr(jsonl.sys, "stdout", stream)
    event = {**EVENT, "display": "한글\nsecond line"}
    sink = jsonl.PROVIDER.build({})
    sink.send(event)
    sink.close()
    assert not stream.closed
    assert stream.flushes == 1
    lines = stream.getvalue().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0]) == event
    assert '\": ' not in lines[0]


def test_jsonl_write_failure_is_safe(monkeypatch):
    class Broken:
        def write(self, line):
            raise OSError("raw-event-and-secret")

    monkeypatch.setattr(jsonl.sys, "stdout", Broken())
    with pytest.raises(DeliveryError, match="^STDOUT_DELIVERY_FAILED$") as caught:
        jsonl.PROVIDER.build({}).send(EVENT)
    assert "raw-event-and-secret" not in "".join(traceback.format_exception(caught.value))


@pytest.mark.parametrize("bad", [{"endpoint": "https://example.com"}, {"token": TOKEN}, None])
def test_jsonl_rejects_configuration(bad):
    with pytest.raises(ValueError, match="^SIEM_OPTIONS_INVALID$"):
        jsonl.PROVIDER.build(bad)


@pytest.mark.parametrize("provider", HTTP_PROVIDERS, ids=lambda p: p.id)
def test_builtin_delivery_payload_auth_and_transport_contract(provider, wire):
    config = options(provider)
    sink = provider.build(config)
    sink.send(EVENT)
    sink.close()
    assert len(wire.requests) == 1
    request = wire.requests[0]
    assert str(request.url) == config["endpoint"]
    assert request.method == "POST"
    assert request.headers["content-type"] == "application/json"
    expected_scheme = "Splunk" if provider.id == "splunk_hec" else "Bearer"
    assert request.headers["authorization"] == f"{expected_scheme} {TOKEN}"
    payload = json.loads(request.content)
    if provider.id == "http_json":
        assert payload == EVENT
    elif provider.id == "splunk_hec":
        assert payload == {"event": EVENT, "time": 1.0, "source": "cremore", "sourcetype": "cremore:finding"}
    else:
        assert payload == [{"tags": {"source": "cremore", "family": "finding"}, "events": [
            {"timestamp": "1970-01-01T00:00:01+00:00", "attributes": EVENT},
        ]}]
    assert EVENT["occurred_at"] == "1970-01-01T00:00:01Z"
    settings = wire.configurations[0]
    assert settings["verify"] is True
    assert settings["timeout"] == 10.0
    assert settings["follow_redirects"] is False
    assert settings["trust_env"] is False
    assert wire.clients[0].is_closed


def test_http_json_optional_auth_and_explicit_bearer(wire):
    sink = http_json.PROVIDER.build({"endpoint": "https://corp.example/receive",
                                     "authorization_scheme": "Bearer", "timeout_seconds": 30})
    wire.response = lambda request: httpx.Response(204)
    sink.send(EVENT)
    assert "authorization" not in wire.requests[0].headers
    assert wire.configurations[0]["timeout"] == 30.0


def test_custom_ca_uses_verifying_context(monkeypatch, wire):
    context = ssl.create_default_context()
    paths = []

    def context_for(*, cafile):
        paths.append(cafile)
        return context

    monkeypatch.setattr(_http.ssl, "create_default_context", context_for)
    http_json.PROVIDER.build({**options(http_json.PROVIDER), "ca_file": "corp-ca.pem"}).send(EVENT)
    assert paths == ["corp-ca.pem"]
    assert wire.configurations[0]["verify"] is context
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


@pytest.mark.parametrize("endpoint", [
    "http://siem.example/events", "https:///events", "https://user:secret@siem.example/events",
    "https://siem.example/events?token=secret", "https://siem.example/events?",
    "https://siem.example/events#fragment", "https://siem.example/events#",
    "https://siem.example/\nevents", " https://siem.example/events",
    "https://siem.example/events\t", "https://siem.example:0/events",
    "https://siem.example:65536/events", "https://siem.example:bad/events",
    "https://siem.example\\@other.example/events", "https://[invalid/events", None,
])
def test_invalid_endpoint_is_rejected_before_client_creation(endpoint, wire):
    with pytest.raises(ValueError, match="^SIEM_ENDPOINT_INVALID$"):
        http_json.PROVIDER.build({"endpoint": endpoint})
    assert wire.configurations == []


@pytest.mark.parametrize("provider", [splunk_hec.PROVIDER, logscale.PROVIDER], ids=lambda p: p.id)
def test_vendor_endpoint_path_must_be_explicit_and_exact(provider, wire):
    for endpoint in ("https://siem.example", options(provider)["endpoint"] + "/", "https://siem.example/other"):
        with pytest.raises(ValueError, match="^SIEM_ENDPOINT_INVALID$"):
            provider.build({**options(provider), "endpoint": endpoint})
    assert wire.configurations == []


@pytest.mark.parametrize("timeout", [0, -1, 30.01, True, "10", None, float("nan"), float("inf")])
def test_timeout_must_be_numeric_finite_and_bounded(timeout, wire):
    with pytest.raises(ValueError, match="^SIEM_TIMEOUT_INVALID$"):
        http_json.PROVIDER.build({**options(http_json.PROVIDER), "timeout_seconds": timeout})
    assert wire.configurations == []


@pytest.mark.parametrize("provider", HTTP_PROVIDERS, ids=lambda p: p.id)
@pytest.mark.parametrize("field", ["token", "verify", "headers", "proxy", "retries"])
def test_unknown_options_cannot_weaken_transport_contract(provider, field, wire):
    # http_json's own "headers" option takes only environment references.
    code = "SIEM_HEADERS_INVALID" if (provider.id, field) == ("http_json", "headers") else "SIEM_OPTIONS_INVALID"
    with pytest.raises(ValueError, match=f"^{code}$"):
        provider.build({**options(provider), field: "secret-value"})
    assert wire.configurations == []


def test_only_generic_http_accepts_bearer_scheme_option(wire):
    with pytest.raises(ValueError, match="^SIEM_AUTHORIZATION_SCHEME_INVALID$"):
        http_json.PROVIDER.build({**options(http_json.PROVIDER), "authorization_scheme": "Basic"})
    for provider in (splunk_hec.PROVIDER, logscale.PROVIDER):
        with pytest.raises(ValueError, match="^SIEM_OPTIONS_INVALID$"):
            provider.build({**options(provider), "authorization_scheme": "Bearer"})
    assert wire.configurations == []


@pytest.mark.parametrize("name", [None, "", "TOKEN=secret", "TOKEN\nOTHER", "1TOKEN", "A" * 129])
def test_invalid_token_environment_reference(name, wire):
    with pytest.raises(ValueError, match="^SIEM_TOKEN_ENV_INVALID$"):
        http_json.PROVIDER.build({**options(http_json.PROVIDER), "token_env": name})
    assert wire.configurations == []


@pytest.mark.parametrize("value", ["", "token\nother", "token\rother", "token with space", "tökén", "x" * 8193])
def test_empty_or_invalid_environment_token_is_rejected(value, monkeypatch, wire):
    monkeypatch.setenv(TOKEN_ENV, value)
    with pytest.raises(ValueError, match="^SIEM_TOKEN_UNAVAILABLE$"):
        http_json.PROVIDER.build(options(http_json.PROVIDER))
    assert wire.configurations == []


def test_required_or_missing_environment_token_is_rejected(monkeypatch, wire):
    for provider in (splunk_hec.PROVIDER, logscale.PROVIDER):
        with pytest.raises(ValueError, match="^SIEM_TOKEN_ENV_INVALID$"):
            provider.build({"endpoint": options(provider)["endpoint"]})
    monkeypatch.delenv(TOKEN_ENV)
    with pytest.raises(ValueError, match="^SIEM_TOKEN_UNAVAILABLE$"):
        http_json.PROVIDER.build(options(http_json.PROVIDER))
    assert wire.configurations == []


@pytest.mark.parametrize("ca_file", [None, "", "bad\npath", "missing-siem-certificate-file.pem"])
def test_invalid_custom_ca_is_not_downgraded_to_insecure(ca_file, wire):
    with pytest.raises(ValueError, match="^SIEM_CA_INVALID$"):
        http_json.PROVIDER.build({**options(http_json.PROVIDER), "ca_file": ca_file})
    assert wire.configurations == []


@pytest.mark.parametrize("provider", HTTP_PROVIDERS, ids=lambda p: p.id)
@pytest.mark.parametrize("status", [301, 307, 400, 401, 429, 503])
def test_http_failure_is_not_followed_or_retried(provider, status, wire):
    wire.response = lambda request: httpx.Response(status, headers={"location": "https://other.example/",
                                                                   "retry-after": "1"}, text="raw-error-secret")
    code = "AUTH_FAILED" if status == 401 else "HTTP_STATUS_REJECTED"
    with pytest.raises(DeliveryError, match=f"^{code}$") as caught:
        provider.build(options(provider)).send(EVENT)
    assert len(wire.requests) == 1
    assert "raw-error-secret" not in "".join(traceback.format_exception(caught.value))


@pytest.mark.parametrize("status", [201, 202, 204, 299])
def test_logscale_only_documents_200_as_accepted(status, wire):
    wire.response = lambda request: httpx.Response(status)
    with pytest.raises(DeliveryError, match="^HTTP_STATUS_REJECTED$"):
        logscale.PROVIDER.build(options(logscale.PROVIDER)).send(EVENT)


@pytest.mark.parametrize("body", [b'{}', b'{"code":1,"text":"secret"}', b'{"code":false}',
                                  b'{"code":"0"}', b'{"code":0.0}', b'[]', b'null', b'not-json', b'\xff'])
def test_hec_requires_explicit_integer_zero_acceptance(body, wire):
    wire.response = lambda request: httpx.Response(200, content=body)
    with pytest.raises(DeliveryError, match="^HEC_RESPONSE_REJECTED$"):
        splunk_hec.PROVIDER.build(options(splunk_hec.PROVIDER)).send(EVENT)


@pytest.mark.parametrize("provider", HTTP_PROVIDERS, ids=lambda p: p.id)
def test_response_limit_checks_advertised_and_streamed_size(provider, wire):
    class Chunks(httpx.SyncByteStream):
        def __iter__(self):
            yield b"x" * (64 << 10)
            yield b"x"

    for response in (lambda request: httpx.Response(200, headers={"content-length": "65537"}, content=b"{}"),
                     lambda request: httpx.Response(200, stream=Chunks())):
        wire.response = response
        with pytest.raises(DeliveryError, match="^RESPONSE_TOO_LARGE$"):
            provider.build(options(provider)).send(EVENT)
    assert len(wire.requests) == 2


@pytest.mark.parametrize("provider", HTTP_PROVIDERS, ids=lambda p: p.id)
def test_transport_exception_does_not_leak_details(provider, wire):
    def broken(request):
        raise httpx.ConnectError("https://secret-endpoint/ " + TOKEN, request=request)

    wire.response = broken
    with pytest.raises(DeliveryError, match="^HTTP_DELIVERY_FAILED$") as caught:
        provider.build(options(provider)).send(EVENT)
    rendered = "".join(traceback.format_exception(caught.value))
    assert TOKEN not in rendered
    assert "secret-endpoint" not in rendered
    assert len(wire.requests) == 1


@pytest.mark.parametrize("provider", [splunk_hec.PROVIDER, logscale.PROVIDER], ids=lambda p: p.id)
@pytest.mark.parametrize("timestamp", [None, 123, "not-a-date", "2026-09-24T00:00:00"])
def test_vendor_payload_requires_explicit_timezone(timestamp, provider, wire):
    with pytest.raises(DeliveryError, match="^INVALID_EVENT_TIME$"):
        provider.build(options(provider)).send({**EVENT, "occurred_at": timestamp})
    assert wire.requests == []


def test_hec_timestamp_converts_offset_to_unix_time(wire):
    splunk_hec.PROVIDER.build(options(splunk_hec.PROVIDER)).send(
        {**EVENT, "occurred_at": "1970-01-01T09:00:01+09:00"})
    assert json.loads(wire.requests[0].content)["time"] == 1.0


@pytest.mark.parametrize("invalid", [float("nan"), object()])
def test_non_json_payload_never_reaches_stdout_or_network(invalid, wire, capsys):
    event = {**EVENT, "invalid": invalid}
    for sink in (jsonl.PROVIDER.build({}), http_json.PROVIDER.build(options(http_json.PROVIDER))):
        with pytest.raises(DeliveryError, match="^INVALID_EVENT$"):
            sink.send(event)
    assert wire.requests == []
    assert capsys.readouterr().out == ""


def test_close_failure_is_safe(monkeypatch, wire):
    sink = http_json.PROVIDER.build(options(http_json.PROVIDER))

    def broken():
        raise OSError(TOKEN)

    with monkeypatch.context() as patch:
        patch.setattr(wire.clients[0], "close", broken)
        with pytest.raises(DeliveryError, match="^SINK_CLOSE_FAILED$") as caught:
            sink.close()
    assert TOKEN not in "".join(traceback.format_exception(caught.value))
