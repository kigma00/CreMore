"""HTTPS authentication variants and syslog over TLS against local fake receivers.

HTTP runs through httpx's MockTransport. Syslog runs a real TLS listener on
127.0.0.1 with a throwaway CA, so framing, the handshake and reconnection are
exercised on an actual socket. No external host is contacted.
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
import socket
import ssl
import threading
import time
import traceback
from types import SimpleNamespace
from urllib.parse import parse_qs

import httpx
import pytest

from cremore.siem.config import ExportConfig
from cremore.siem.contract import DeliveryError
from cremore.siem.sinks import _http, http_json, syslog_tls

EVENT = {"schema_version": 1, "event_id": "b21e4c6a-ce3f-54e7-9320-02d31ddc9568", "event_type": "finding.created",
         "occurred_at": "2026-09-24T03:00:00Z", "product": "CreMore",
         "finding": {"id": "11111111-1111-4111-8111-111111111111", "credential_id": "22222222-2222-4222-8222-222222222222",
                     "severity": "HIGH", "workflow_status": "OPEN"},
         "credential": {"provider": "github", "credential_type": "GITHUB_TOKEN", "status": "UNKNOWN"},
         "exposure": {"id": "33333333-3333-4333-8333-333333333333", "source_type": "github",
                      "source_connection_id": None, "aws_account_id": None, "line_number": 12}}
SECRET = "synthetic-client-secret-value"


@pytest.fixture
def wire(monkeypatch):
    real = httpx.Client
    state = SimpleNamespace(requests=[], clients=[], routes={})

    def handle(request):
        state.requests.append(request)
        for prefix, respond in state.routes.items():
            if str(request.url).startswith(prefix):
                return respond(request)
        return httpx.Response(204)

    def client(**kwargs):
        made = real(**kwargs, transport=httpx.MockTransport(handle))
        state.clients.append(made)
        return made

    monkeypatch.setattr(_http.httpx, "Client", client)
    monkeypatch.setattr(http_json.httpx, "Client", client)
    yield state
    for made in state.clients:
        made.close()


def test_api_key_header_and_elastic_api_key_scheme(wire, monkeypatch):
    monkeypatch.setenv("DD_KEY", "synthetic-dd-key")
    sink = http_json.PROVIDER.build({"endpoint": "https://http-intake.logs.example/api/v2/logs",
                                     "api_key_header": {"name": "DD-API-KEY", "value_env": "DD_KEY"}})
    sink.send(EVENT)
    assert wire.requests[-1].headers["dd-api-key"] == "synthetic-dd-key"
    assert "authorization" not in wire.requests[-1].headers
    monkeypatch.setenv("ES_KEY", "c3ludGhldGljOmtleQ==")
    elastic = http_json.PROVIDER.build({"endpoint": "https://es.example/cremore/_doc", "token_env": "ES_KEY",
                                        "authorization_scheme": "ApiKey"})
    elastic.send(EVENT)
    assert wire.requests[-1].headers["authorization"] == "ApiKey c3ludGhldGljOmtleQ=="
    for bad, code in [({"api_key_header": {"name": "Authorization", "value_env": "DD_KEY"}}, "SIEM_HEADERS_INVALID"),
                      ({"api_key_header": {"name": "Host", "value_env": "DD_KEY"}}, "SIEM_HEADERS_INVALID"),
                      ({"api_key_header": {"name": "DD-API-KEY"}}, "SIEM_API_KEY_HEADER_INVALID"),
                      ({"authorization_scheme": "ApiKey"}, "SIEM_AUTHORIZATION_SCHEME_INVALID"),
                      ({"token_env": "ES_KEY", "api_key_header": {"name": "X-Key", "value_env": "DD_KEY"}},
                       "SIEM_AUTHENTICATION_AMBIGUOUS")]:
        with pytest.raises(ValueError, match=f"^{code}$"):
            http_json.PROVIDER.build({"endpoint": "https://collector.example/in", **bad})


def test_custom_headers_come_from_the_environment_only(wire, monkeypatch):
    monkeypatch.setenv("TENANT_HEADER", "tenant-7")
    sink = http_json.PROVIDER.build({"endpoint": "https://gateway.example/in",
                                     "headers": {"X-Tenant": {"value_env": "TENANT_HEADER"}}})
    sink.send(EVENT)
    assert wire.requests[-1].headers["x-tenant"] == "tenant-7"
    for bad in ({"X-Tenant": "literal"}, {"X Tenant": {"value_env": "TENANT_HEADER"}},
                {"Content-Type": {"value_env": "TENANT_HEADER"}},
                {f"X-{i}": {"value_env": "TENANT_HEADER"} for i in range(9)}):
        with pytest.raises(ValueError, match="^SIEM_HEADERS_INVALID$"):
            http_json.PROVIDER.build({"endpoint": "https://gateway.example/in", "headers": bad})
    monkeypatch.delenv("TENANT_HEADER")
    with pytest.raises(ValueError, match="^SIEM_TOKEN_UNAVAILABLE$"):
        http_json.PROVIDER.build({"endpoint": "https://gateway.example/in",
                                  "headers": {"X-Tenant": {"value_env": "TENANT_HEADER"}}})


def sentinel(monkeypatch, **oauth):
    monkeypatch.setenv("SENTINEL_SECRET", SECRET)
    return {"endpoint": "https://dce.example.ingest.monitor.azure.com/dataCollectionRules/dcr-000a/streams/Custom-CreMore",
            "query": {"api-version": "2023-01-01"}, "body": "array",
            "oauth": {"token_url": "https://login.example/tenant/oauth2/v2.0/token", "client_id": "client-1",
                      "client_secret_env": "SENTINEL_SECRET", "scope": "https://monitor.azure.com//.default", **oauth}}


def token_route(wire, tokens, *, lifetime=3600, status=200):
    import itertools
    issued = itertools.chain(tokens, (f"token-extra-{n}" for n in itertools.count()))

    def respond(request):
        if status != 200:
            return httpx.Response(status, json={"error": "invalid_client", "error_description": SECRET})
        return httpx.Response(200, json={"access_token": next(issued), "token_type": "Bearer", "expires_in": lifetime})
    wire.routes["https://login.example/"] = respond


def test_sentinel_logs_ingestion_shape_with_client_credentials(wire, monkeypatch):
    token_route(wire, ["token-one"])
    sink = http_json.PROVIDER.build(sentinel(monkeypatch))
    sink.send(EVENT)
    sink.send(EVENT)
    token_calls = [r for r in wire.requests if r.url.host == "login.example"]
    posts = [r for r in wire.requests if r.url.host != "login.example"]
    assert len(token_calls) == 1  # cached until it nears expiry
    form = parse_qs(token_calls[0].content.decode())
    assert form == {"grant_type": ["client_credentials"], "client_id": ["client-1"], "client_secret": [SECRET],
                    "scope": ["https://monitor.azure.com//.default"]}
    assert posts[0].url.params["api-version"] == "2023-01-01"
    assert posts[0].headers["authorization"] == "Bearer token-one"
    assert json.loads(posts[0].content) == [EVENT]


def test_client_secret_basic_puts_the_client_in_the_authorization_header(wire, monkeypatch):
    token_route(wire, ["token-basic"])
    http_json.PROVIDER.build(sentinel(monkeypatch, auth_method="client_secret_basic")).send(EVENT)
    call = next(r for r in wire.requests if r.url.host == "login.example")
    assert call.headers["authorization"] == "Basic " + base64.b64encode(f"client-1:{SECRET}".encode()).decode()
    assert "client_secret" not in parse_qs(call.content.decode())


def test_an_expired_or_refused_token_is_fetched_again_once(wire, monkeypatch):
    clock = [0.0]
    token_route(wire, ["token-one", "token-two", "token-three"], lifetime=120)
    sink = http_json.PROVIDER.build(sentinel(monkeypatch))
    sink._oauth._clock = lambda: clock[0]
    sink.send(EVENT)
    clock[0] = 70.0  # past lifetime minus the 60 s margin
    sink.send(EVENT)
    assert [r.headers["authorization"] for r in wire.requests if r.url.host != "login.example"] == [
        "Bearer token-one", "Bearer token-two"]
    refused = iter([401, 204])
    wire.routes["https://dce.example"] = lambda request: httpx.Response(next(refused))
    sink.send(EVENT)
    assert [r.headers["authorization"] for r in wire.requests if r.url.host != "login.example"][-2:] == [
        "Bearer token-two", "Bearer token-three"]
    wire.routes["https://dce.example"] = lambda request: httpx.Response(401)
    with pytest.raises(DeliveryError, match="^AUTH_FAILED$"):
        sink.send(EVENT)


def test_token_endpoint_failures_are_a_fixed_code(wire, monkeypatch):
    token_route(wire, [], status=401)
    sink = http_json.PROVIDER.build(sentinel(monkeypatch))
    with pytest.raises(DeliveryError, match="^OAUTH_TOKEN_FAILED$") as caught:
        sink.send(EVENT)
    assert SECRET not in "".join(traceback.format_exception(caught.value))
    for bad in ({"token_url": "http://login.example/token"}, {"client_id": "bad id"},
                {"auth_method": "private_key_jwt"}, {"unknown": "x"}):
        with pytest.raises(ValueError, match="^SIEM_OAUTH_INVALID$"):
            http_json.PROVIDER.build(sentinel(monkeypatch, **bad))


def test_elasticsearch_create_by_event_id_treats_a_conflict_as_delivered(wire, monkeypatch):
    monkeypatch.setenv("ES_KEY", "c3ludGhldGljOmtleQ==")
    options = {"endpoint": "https://es.example/cremore-events/_create/{event_id}", "token_env": "ES_KEY",
               "authorization_scheme": "ApiKey", "conflict_is_duplicate": True}
    sink = http_json.PROVIDER.build(options)
    wire.routes["https://es.example/"] = lambda request: httpx.Response(409)
    sink.send(EVENT)  # the first attempt already arrived
    assert str(wire.requests[-1].url) == "https://es.example/cremore-events/_create/" + EVENT["event_id"]
    with pytest.raises(DeliveryError, match="^INVALID_EVENT$"):
        sink.send({**EVENT, "event_id": "../../_bulk"})
    for bad, code in [({"conflict_is_duplicate": True, "endpoint": "https://es.example/cremore/_doc"},
                       "SIEM_CONFLICT_OPTION_INVALID"),
                      ({"endpoint": "https://es.example/{event_id}/{event_id}"}, "SIEM_ENDPOINT_INVALID"),
                      ({"endpoint": "https://{event_id}.example/in"}, "SIEM_ENDPOINT_INVALID"),
                      ({"body": "ndjson"}, "SIEM_BODY_INVALID"),
                      ({"query": {"api-version": "2023-01-01&x=1"}}, "SIEM_QUERY_INVALID")]:
        with pytest.raises(ValueError, match=f"^{code}$"):
            http_json.PROVIDER.build({**options, "conflict_is_duplicate": False, **bad})


# --- syslog over TLS ----------------------------------------------------------

def _certificates(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = _dt.datetime.now(_dt.UTC)

    def issue(subject, issuer_name, key, signer, *, ca, san=None):
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - _dt.timedelta(minutes=1)).not_valid_after(now + _dt.timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                       key_encipherment=False, data_encipherment=False, key_agreement=False,
                       key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False), critical=True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False))
        if san:
            builder = (builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
                       .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
        return builder.sign(signer, hashes.SHA256())

    ca_key, server_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic syslog CA")])
    ca = issue(ca_name, ca_name, ca_key, ca_key, ca=True)
    server = issue(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]), ca_name, server_key, ca_key,
                   ca=False, san="localhost")
    pem = serialization.Encoding.PEM
    (tmp_path / "ca.pem").write_bytes(ca.public_bytes(pem))
    (tmp_path / "server.pem").write_bytes(server.public_bytes(pem))
    (tmp_path / "server.key").write_bytes(server_key.private_bytes(
        pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return tmp_path / "ca.pem", tmp_path / "server.pem", tmp_path / "server.key"


class Receiver:
    """A TLS syslog listener that records the bytes of each connection."""

    def __init__(self, cert, key, *, close_first_after=None):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.context, self.connections, self.close_first_after = context, [], close_first_after
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                raw, _ = self.listener.accept()
            except OSError:
                return
            received = bytearray()
            self.connections.append(received)
            try:
                with self.context.wrap_socket(raw, server_side=True) as conn:
                    while True:
                        data = conn.recv(65536)
                        if not data:
                            break
                        received.extend(data)
                        if self.close_first_after and len(self.connections) == 1 and len(received) >= self.close_first_after:
                            break
            except (OSError, ssl.SSLError):
                pass

    def wait(self, predicate, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        return False

    def close(self):
        self.listener.close()


def frames(data: bytes) -> list[bytes]:
    out = []
    while data:
        length, _, rest = data.partition(b" ")
        size = int(length)
        out.append(rest[:size])
        data = rest[size:]
    return out


@pytest.fixture
def tls(tmp_path):
    ca, cert, key = _certificates(tmp_path)
    receivers = []

    def start(**kwargs):
        receiver = Receiver(cert, key, **kwargs)
        receivers.append(receiver)
        return receiver
    yield SimpleNamespace(ca=str(ca), start=start)
    for receiver in receivers:
        receiver.close()


def syslog(tls, receiver, **options):
    return syslog_tls.PROVIDER.build({"host": "127.0.0.1", "port": receiver.port, "server_name": "localhost",
                                      "ca_file": tls.ca, "hostname": "cremore-worker-1", **options})


def test_rfc5425_octet_counted_rfc5424_json_messages(tls):
    receiver = tls.start()
    sink = syslog(tls, receiver)
    # Python 3.13+ enables this by default; exercise the same certificate checks on older runtimes.
    sink._context.verify_flags |= ssl.VERIFY_X509_STRICT
    sink.send(EVENT)
    sink.send({**EVENT, "event_id": "c21e4c6a-ce3f-54e7-9320-02d31ddc9568"})
    assert receiver.wait(lambda: len(frames(bytes(receiver.connections[0]))) == 2 if receiver.connections else False)
    sink.close()
    first = frames(bytes(receiver.connections[0]))[0].decode("ascii")
    header, body = first.split(" - ", 2)[0], first.split(" - ", 2)[-1]
    # PRI 83 = facility 10 (security/authorization) * 8 + severity 3 (error, a HIGH finding).
    assert header == "<83>1 2026-09-24T03:00:00.000000Z cremore-worker-1 cremore"
    assert first.split(" ")[5] == "finding.created"
    assert json.loads(body) == EVENT
    assert len(receiver.connections) == 1  # one connection carries every event


def test_cef_and_leef_bodies_and_newline_framing(tls):
    receiver = tls.start()
    cef = syslog(tls, receiver, message_format="cef", framing="lf", facility=13, app_name="cremore-siem")
    cef.send(EVENT)
    assert receiver.wait(lambda: receiver.connections and receiver.connections[0].endswith(b"\n"))
    line = bytes(receiver.connections[0]).decode("ascii").rstrip("\n")
    assert line.startswith("<107>1 2026-09-24T03:00:00.000000Z cremore-worker-1 cremore-siem - finding.created - CEF:0|CreMore|")
    leef = tls.start()
    leef_sink = syslog(tls, leef, message_format="leef")
    leef_sink.send(EVENT)
    assert leef.wait(lambda: leef.connections and b"LEEF:2.0|CreMore|" in leef.connections[0])
    assert b"\tcat=finding\t" in bytes(leef.connections[0])


def test_a_receiver_that_closed_the_connection_gets_a_new_one(tls):
    receiver = tls.start(close_first_after=1)
    sink = syslog(tls, receiver)
    sink.send(EVENT)
    assert receiver.wait(lambda: len(receiver.connections) == 1 and len(receiver.connections[0]) > 0)
    time.sleep(0.2)  # the receiver has closed its side
    sink.send({**EVENT, "event_id": "d21e4c6a-ce3f-54e7-9320-02d31ddc9568"})
    assert receiver.wait(lambda: len(receiver.connections) == 2 and len(receiver.connections[1]) > 0)
    assert b"d21e4c6a" in bytes(receiver.connections[1])
    sink.close()


def test_an_untrusted_or_misnamed_server_is_refused(tls, tmp_path):
    receiver = tls.start()
    untrusted = syslog_tls.PROVIDER.build({"host": "127.0.0.1", "port": receiver.port, "server_name": "localhost"})
    with pytest.raises(DeliveryError, match="^SYSLOG_TLS_FAILED$"):
        untrusted.send(EVENT)
    misnamed = syslog(tls, receiver, server_name="siem.example")
    with pytest.raises(DeliveryError, match="^SYSLOG_TLS_FAILED$"):
        misnamed.send(EVENT)
    closed = socket.create_server(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    with pytest.raises(DeliveryError, match="^SYSLOG_CONNECT_FAILED$"):
        syslog_tls.PROVIDER.build({"host": "127.0.0.1", "port": port, "ca_file": tls.ca}).send(EVENT)


def test_ocsf_through_syslog_keeps_its_own_time_and_name(tls):
    from cremore.siem.formats import to_ocsf
    receiver = tls.start()
    sink = syslog(tls, receiver)
    sink.send(to_ocsf(EVENT))
    assert receiver.wait(lambda: receiver.connections and frames(bytes(receiver.connections[0])))
    message = frames(bytes(receiver.connections[0]))[0].decode("ascii")
    assert message.startswith("<83>1 2026-09-24T03:00:00.000000Z cremore-worker-1 cremore - finding.created - {")
    assert json.loads(message.split(" - ", 2)[-1])["class_uid"] == 2004


@pytest.mark.parametrize(("options", "code"), [
    ({"host": "bad host"}, "SIEM_SYSLOG_HOST_INVALID"), ({"host": "siem.example", "port": 0}, "SIEM_SYSLOG_PORT_INVALID"),
    ({"host": "siem.example", "message_format": "xml"}, "SIEM_SYSLOG_FORMAT_INVALID"),
    ({"host": "siem.example", "framing": "udp"}, "SIEM_SYSLOG_FRAMING_INVALID"),
    ({"host": "siem.example", "facility": 24}, "SIEM_SYSLOG_FACILITY_INVALID"),
    ({"host": "siem.example", "app_name": "a b"}, "SIEM_SYSLOG_APP_NAME_INVALID"),
    ({"host": "siem.example", "cert_file": "client.pem"}, "SIEM_CLIENT_CERT_INVALID"),
    ({"host": "siem.example", "insecure": True}, "SIEM_OPTIONS_INVALID"),
    ({"host": "siem.example", "ca_file": "/missing/ca.pem"}, "SIEM_TLS_CONFIGURATION_INVALID"),
])
def test_syslog_options_are_checked_before_any_connection(options, code):
    with pytest.raises(ValueError, match=f"^{code}$"):
        syslog_tls.PROVIDER.build(options)


def test_cef_and_leef_do_not_carry_ocsf():
    base = {"destinations": [{"id": "qradar", "provider": "syslog_tls",
                              "options": {"host": "siem.example", "message_format": "leef"}, "format": "ocsf"}]}
    with pytest.raises(ValueError, match="SIEM_FORMAT_CONFLICT"):
        ExportConfig.model_validate(base)
    base["destinations"][0]["format"] = "native"
    assert ExportConfig.model_validate(base).destinations[0].format == "native"


def test_every_shipped_example_builds_its_sinks(tls, monkeypatch, tmp_path):
    from pathlib import Path

    from cremore.siem.registry import load_provider

    root = Path(__file__).resolve().parents[2] / "deploy" / "siem"
    for name in ("SIEM_HTTP_TOKEN", "SPLUNK_HEC_TOKEN", "LOGSCALE_INGEST_TOKEN", "SENTINEL_CLIENT_SECRET",
                 "ELASTIC_API_KEY", "DD_API_KEY", "OCSF_GATEWAY_TOKEN"):
        monkeypatch.setenv(name, "synthetic-value")
    built = []
    for path in sorted(root.glob("*.example.json")):
        config = ExportConfig.model_validate(json.loads(path.read_text(encoding="utf-8")))
        for destination in config.destinations:
            if destination.provider in config.allow_plugins:
                continue  # a team's own package, not shipped here
            options = dict(destination.options)
            if destination.provider == "syslog_tls":
                # Local stand-ins for the operator's certificate files.
                if "ca_file" in options:
                    options["ca_file"] = tls.ca
                if "cert_file" in options:
                    folder = tmp_path / destination.id
                    folder.mkdir()
                    _ca, cert, key = _certificates(folder)
                    options.update(cert_file=str(cert), key_file=str(key))
            sink = load_provider(destination.provider).build(options)
            built.append(destination.provider)
            sink.close()
    assert {"jsonl", "http_json", "splunk_hec", "logscale", "syslog_tls"} <= set(built)
