"""Export API, credential isolation and resumable collection with fake HTTP."""

import io
import logging
import socket
import ssl

import httpx
import pytest

from cremore_github_provider.metadata import export_http
from cremore_github_provider.metadata.endpoints import EndpointError, validate_operation
from cremore_github_provider.metadata.exports import ExportError
from cremore_github_provider.metadata.http import SourceError, Transport

from .fake import ENTERPRISE, SECRETS, FakeBroker, enterprise_spec
from .test_exports import AS_OF, data, row


def transport(handler):
    spec = enterprise_spec()
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return Transport(client, origin=spec.origin, options=spec.options,
                     enterprise=ENTERPRISE, max_requests=100, sleep=lambda _: None)


def response(request, status, **kwargs):
    return httpx.Response(status, request=request, **kwargs)


@pytest.mark.parametrize("origin,version", [("https://github.com", "2026-03-10"),
    ("https://acme.ghe.com", "2026-03-10"), ("https://ghes.acme.test", "2022-11-28")])
def test_enterprise_server_reads_use_the_version_ghes_3_20_accepts(origin, version):
    # GHES 3.20 lists only 2022-11-28 and answers 400 to an unknown version.
    seen = []
    def handler(request):
        seen.append((request.url.host, request.headers["x-github-api-version"]))
        return response(request, 200, json={})
    client = httpx.Client(transport=httpx.MockTransport(handler))
    tx = Transport(client, origin=origin, options=enterprise_spec().options, max_requests=5, sleep=lambda _: None)
    tx.request("GET", "/app", "token")
    assert seen[0][1] == version


def test_export_creation_is_the_only_new_post_and_requires_explicit_opt_in():
    path = f"/enterprises/{ENTERPRISE}/credentials/exports"
    with pytest.raises(EndpointError):
        validate_operation("POST", path, enterprise=ENTERPRISE)
    assert validate_operation("POST", path, enterprise=ENTERPRISE, allow_export_create=True) == path
    for other in (path + "/e", path + "?owner=someone", path.replace(ENTERPRISE, "another")):
        with pytest.raises(EndpointError):
            validate_operation("POST", other, enterprise=ENTERPRISE, allow_export_create=True)


def test_create_202_pending_poll_then_302_without_following_download_with_api_token():
    calls = []
    def handler(request):
        calls.append(request)
        assert request.headers["authorization"] == "Bearer API-only"
        if request.method == "POST":
            assert request.content == b"{}"
            return response(request, 202, json={"export_id": "export-1", "status": "queued", "as_of": AS_OF})
        if len(calls) == 2:
            return response(request, 200, json={"export_id": "export-1", "status": "processing", "as_of": AS_OF})
        return response(request, 302, headers={"location": "https://download.example/export?signature=transient"})
    tx = transport(handler)
    state = export_http.create(tx, "API-only")
    assert export_http.poll(tx, "API-only", state) is None
    assert export_http.poll(tx, "API-only", state).startswith("https://download.example/")
    assert len(calls) == 3
    assert "signature" not in str(state)


@pytest.mark.parametrize("change,code", [({"export_id": "other"}, "identity_changed"),
    ({"as_of": "2026-10-04T00:00:00Z"}, "snapshot_changed"), ({"status": "expired"}, "expired"),
    ({"status": "failed"}, "failed")])
def test_poll_refuses_changed_or_failed_exports(change, code):
    tx = transport(lambda request: response(request, 200, json={"export_id": "e", "status": "queued", "as_of": AS_OF, **change}))
    with pytest.raises(ExportError, match=code):
        export_http.poll(tx, "API-only", {"export_id": "e", "as_of": export_http.timestamp(AS_OF)})


def test_post_is_never_retried_by_the_http_client():
    calls = []
    def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout("request may have reached GitHub; sensitive response suppressed", request=request)
    with pytest.raises(SourceError, match="^github_unavailable$"):
        export_http.create(transport(handler), "API-only")
    assert len(calls) == 1


def factory(handler):
    class Connection:
        def __init__(self, address, hostname, *, timeout):
            self.address, self.hostname = address, hostname

        def request(self, method, path, headers):
            request = httpx.Request(method, "https://" + self.address + path, headers=headers,
                                    extensions={"sni_hostname": self.hostname})
            self.response = handler(request)

        def getresponse(self):
            response = io.BytesIO(self.response.content if self.response.is_stream_consumed
                                 else b"".join(self.response.iter_raw()))
            response.status = self.response.status_code
            response.getheader = self.response.headers.get
            return response

        def close(self):
            pass

    return Connection


def test_download_pins_the_verified_ip_and_tls_name_and_removes_ambient_credentials():
    calls, resolutions = [], []
    body = data(row())
    def handler(request):
        calls.append(request)
        assert request.url.host == "8.8.8.8"
        assert request.headers["host"] == "download.example"
        assert request.extensions["sni_hostname"] == "download.example"
        assert not {"authorization", "cookie", "proxy-authorization"} & set(request.headers)
        return response(request, 200, content=body)
    def resolve(host, timeout):
        resolutions.append(host)
        return {"8.8.8.8"}
    tx = transport(lambda _: pytest.fail("The API client must never download the CSV"))
    result = b"".join(export_http.download(tx, "https://download.example/result?signature=temporary",
                         resolve=resolve, connection_factory=factory(handler)))
    assert result == body
    assert len(calls) == 1 and resolutions == ["download.example"] and tx.requests == 1


@pytest.mark.parametrize("url", ["http://download.example/file", "https://user:password@download.example/file",
    "https://download.example:444/file", "https://download.example/file#fragment", "//download.example/file",
    "https://download.example./file", "https://download.example/\\@localhost", "https://download.example/\nfile"])
def test_download_rejects_unsafe_urls_before_io(url):
    tx = transport(lambda _: pytest.fail("no API call"))
    with pytest.raises(ExportError, match="url_refused"):
        list(export_http.download(tx, url, resolve=lambda *_: pytest.fail("no DNS"),
                                 connection_factory=lambda _: pytest.fail("no connection")))


@pytest.mark.parametrize("addresses", [{"127.0.0.1"}, {"169.254.169.254"}, {"168.63.129.16"},
    {"10.0.0.1", "8.8.8.8"}, {"::1"}, {"64:ff9b::a9fe:a9fe"}, {"ff02::1"}])
def test_every_dns_answer_must_be_public_for_a_cross_origin_download(addresses):
    tx = transport(lambda _: pytest.fail("no API call"))
    with pytest.raises(ExportError, match="address_refused"):
        list(export_http.download(tx, "https://download.example/file", resolve=lambda *_: addresses,
                                 connection_factory=lambda _: pytest.fail("no connection")))


def test_each_redirect_gets_its_own_dns_check_and_cannot_move_to_metadata_service():
    calls = []
    def handler(request):
        calls.append(request)
        return response(request, 302, headers={"location": "https://169.254.169.254/metadata"})
    with pytest.raises(ExportError, match="address_refused"):
        list(export_http.download(transport(lambda _: None), "https://download.example/file",
            resolve=lambda host, _: {"8.8.8.8" if host == "download.example" else host}, connection_factory=factory(handler)))
    assert len(calls) == 1


@pytest.mark.parametrize("headers,body,code", [({"content-encoding": "gzip"}, b"tiny", "encoding_refused"),
    ({"content-length": str(export_http.MAX_EXPORT_BYTES + 1)}, b"", "size_limit"),
    ({"content-length": "1000"}, b"short", "incomplete_download")])
def test_download_rejects_compression_and_size_or_truncation_before_success(headers, body, code):
    with pytest.raises(ExportError, match=code):
        list(export_http.download(transport(lambda _: None), "https://download.example/file", resolve=lambda *_: {"8.8.8.8"},
             connection_factory=factory(lambda r: response(r, 200, headers=headers, stream=httpx.ByteStream(body)))))


def test_expired_download_can_be_repolled_without_creating_another_export():
    with pytest.raises(SourceError, match="^github_export_download_expired$"):
        list(export_http.download(transport(lambda _: None), "https://download.example/file", resolve=lambda *_: {"8.8.8.8"},
             connection_factory=factory(lambda r: response(r, 403))))


def test_download_errors_never_reflect_the_signed_url():
    def handler(request):
        raise OSError(str(request.url))
    with pytest.raises(SourceError, match="^github_unavailable$"):
        list(export_http.download(transport(lambda _: None), "https://download.example/file?signature=never-report",
             resolve=lambda *_: {"8.8.8.8"}, connection_factory=factory(handler)))


def test_default_download_transport_never_logs_signed_urls_even_with_debug_enabled(monkeypatch, caplog, capsys):
    requests, connections, names, closed = [], [], [], []
    class Socket:
        def setsockopt(self, *args):
            pass

        def sendall(self, content):
            requests.append(content)

        def makefile(self, *args):
            return io.BytesIO(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nX-Private: response-marker\r\n\r\ncsv")

        def close(self):
            closed.append(True)

    def connect(address, timeout, source_address=None):
        connections.append(address)
        return Socket()

    def wrap(context, sock, *, server_hostname):
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        names.append(server_hostname)
        return sock

    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
    monkeypatch.setattr(export_http.http.client.HTTPConnection, "debuglevel", 1)
    caplog.set_level(logging.DEBUG)
    for name in ("httpx", "httpcore"):  # quieted at import by cremore.alerts.delivery when that ran first
        caplog.set_level(logging.DEBUG, logger=name)
    logging.getLogger("httpx").debug("capture-control")
    chunks = export_http.download(transport(lambda _: pytest.fail("no API request")),
        "https://download.example/result?signature=signed-marker", resolve=lambda *_: {"8.8.8.8"})
    assert b"".join(chunks) == b"csv"
    assert connections == [("8.8.8.8", 443)] and names == ["download.example"] and closed
    wire = b"".join(requests)
    assert b"signed-marker" in wire and b"Host: download.example" in wire
    assert b"Authorization:" not in wire and b"Cookie:" not in wire
    assert "capture-control" in caplog.text
    captured = capsys.readouterr()
    for marker in ("signed-marker", "response-marker"):
        assert marker not in caplog.text + captured.out + captured.err


def attempt(spec, tx, *, checkpoint=None, committed=(), stop_after=None):
    from cremore_github_provider.metadata.adapter import collect_pages
    saved = list(committed)
    stream = collect_pages(spec, secrets=SECRETS, checkpoint=checkpoint or {}, check=lambda: None,
        transport=tx, broker=FakeBroker(), read_records=lambda: iter(saved))
    pages = []
    for page in stream:
        pages.append(page)
        saved.extend(item.model_dump() for item in page.records)
        if stop_after and len(pages) >= stop_after:
            stream.close()
            break
    return pages, saved


def export_api(calls):
    def handler(request):
        calls.append((request.method, request.url.path))
        if request.method == "POST":
            return response(request, 202, json={"export_id": "export-1", "status": "queued", "as_of": AS_OF})
        return response(request, 302, headers={"location": "https://download.example/result?signature=temporary"})
    return handler


def test_adapter_collects_new_export_without_calling_the_retired_endpoint(monkeypatch):
    from .test_exports import chunks
    calls = []
    spec = enterprise_spec(capabilities=["inventory", "relations"], options={"enterprise_only": True})
    tx = transport(export_api(calls))
    first, committed = attempt(spec, tx)
    assert first[-1].status == "WAITING" and first[-1].reasons == ["GITHUB_EXPORT_QUEUED"]
    assert "signature" not in str(first[-1].checkpoint)
    body = data(row(organization_id="10", organization="one"), row(organization_id="20", organization="two"))
    monkeypatch.setattr(export_http, "download", lambda *a, **kw: chunks(body))
    second, saved = attempt(spec, transport(export_api(calls)), checkpoint=first[-1].checkpoint, committed=committed)
    assert second[-1].status == "COMPLETE"
    inventory = [r for r in saved if r.get("identity", {}).get("object_id", "").startswith("inventory:")]
    assert len(inventory) == 1
    assert len([r for r in saved if r["record_type"] == "relation"]) == 2
    assert calls == [("POST", f"/enterprises/{ENTERPRISE}/credentials/exports"),
                     ("GET", f"/enterprises/{ENTERPRISE}/credentials/exports/export-1")]


def test_documented_started_status_and_null_as_of_keep_the_export_queued(monkeypatch):
    # docs.github.com token-inventory: status pending|queued|started|success|error; as_of string or null.
    from .test_exports import chunks
    calls = []
    def handler(request):
        calls.append(request.method)
        if request.method == "POST":
            return response(request, 202, json={"export_id": "export-1", "status": "started", "as_of": None})
        if len(calls) == 2:
            return response(request, 200, json={"export_id": "export-1", "status": "started", "as_of": None})
        if len(calls) == 3:
            return response(request, 200, json={"export_id": "export-1", "status": "started", "as_of": AS_OF})
        return response(request, 302, headers={"location": "https://download.example/result?signature=temporary"})
    spec = enterprise_spec(capabilities=["inventory", "relations"], options={"enterprise_only": True})
    pages, committed = attempt(spec, transport(handler))
    for _ in range(2):
        assert pages[-1].status == "WAITING" and pages[-1].reasons == ["GITHUB_EXPORT_QUEUED"]
        pages, committed = attempt(spec, transport(handler), checkpoint=pages[-1].checkpoint, committed=committed)
    monkeypatch.setattr(export_http, "download", lambda *a, **kw: chunks(data(row())))
    pages, saved = attempt(spec, transport(handler), checkpoint=pages[-1].checkpoint, committed=committed)
    assert pages[-1].status == "COMPLETE" and calls == ["POST", "GET", "GET", "GET"]
    inventory = [r for r in saved if r.get("identity", {}).get("object_id", "").startswith("inventory:")]
    assert inventory[0]["provenance"]["provider_generated_at"] == export_http.timestamp(AS_OF)


def test_rate_limited_export_poll_waits_for_the_provider_retry_after():
    calls = []
    def handler(request):
        calls.append(request.method)
        if request.method == "POST":
            return response(request, 202, json={"export_id": "export-1", "status": "queued", "as_of": AS_OF})
        return response(request, 429, headers={"retry-after": "900"})
    spec = enterprise_spec(options={"enterprise_only": True})
    first, committed = attempt(spec, transport(handler))
    limited, _ = attempt(spec, transport(handler), checkpoint=first[-1].checkpoint, committed=committed)
    assert limited[-1].status == "WAITING" and limited[-1].reasons == ["GITHUB_RATE_LIMITED"]
    assert limited[-1].retry_after_seconds == 900


def test_submission_intent_is_committed_before_post_and_restart_never_reposts():
    calls = []
    spec = enterprise_spec(options={"enterprise_only": True})
    first, committed = attempt(spec, transport(export_api(calls)), stop_after=2)
    assert calls == []
    state = first[-1].checkpoint
    current = next(task for task in state["tasks"].values() if task["kind"] == "inventory")
    assert current["export"]["stage"] == "submitting"
    resumed, _ = attempt(spec, transport(export_api(calls)), checkpoint=state, committed=committed)
    assert resumed[-1].status == "PARTIAL"
    assert "GITHUB_EXPORT_SUBMISSION_UNKNOWN" in resumed[-1].reasons
    assert calls == []


def test_post_timeout_is_recorded_as_uncertain_and_never_automatically_resubmitted():
    calls = []
    def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout("opaque", request=request)
    spec = enterprise_spec(options={"enterprise_only": True})
    first, committed = attempt(spec, transport(handler))
    assert first[-1].status == "PARTIAL"
    assert "GITHUB_EXPORT_SUBMISSION_UNKNOWN" in first[-1].reasons
    resumed, _ = attempt(spec, transport(handler), checkpoint=first[-1].checkpoint, committed=committed)
    assert resumed[-1].status == "PARTIAL" and len(calls) == 1


def test_resume_replays_same_export_skips_committed_rows_and_preserves_all_grants(monkeypatch):
    from .test_exports import chunks
    calls = []
    spec = enterprise_spec(capabilities=["inventory", "relations"], options={"enterprise_only": True, "page_size": 2})
    first, committed = attempt(spec, transport(export_api(calls)))
    body = data(row(organization_id="10", organization="one"), row(credential_id="18"),
                row(organization_id="20", organization="two"))
    monkeypatch.setattr(export_http, "download", lambda *a, **kw: chunks(body))
    partial, committed = attempt(spec, transport(export_api(calls)), checkpoint=first[-1].checkpoint,
                                 committed=committed, stop_after=1)
    current = next(t for t in partial[-1].checkpoint["tasks"].values() if t["kind"] == "inventory")
    assert current["export"]["rows"] == 2
    last, saved = attempt(spec, transport(export_api(calls)), checkpoint=partial[-1].checkpoint, committed=committed)
    assert last[-1].status == "COMPLETE"
    assert len([r for r in saved if r.get("identity", {}).get("object_id", "").startswith("inventory:")]) == 2
    assert len([r for r in saved if r["record_type"] == "relation"]) == 2
    assert sum(method == "POST" for method, path in calls) == 1


def test_resume_detects_changed_export_content_before_accepting_any_new_rows(monkeypatch):
    from .test_exports import chunks
    calls = []
    spec = enterprise_spec(options={"enterprise_only": True, "page_size": 1})
    first, committed = attempt(spec, transport(export_api(calls)))
    monkeypatch.setattr(export_http, "download", lambda *a, **kw: chunks(data(row(), row(credential_id="18"))))
    partial, committed = attempt(spec, transport(export_api(calls)), checkpoint=first[-1].checkpoint,
                                 committed=committed, stop_after=1)
    monkeypatch.setattr(export_http, "download", lambda *a, **kw: chunks(data(row(credential_id="19"), row(credential_id="18"))))
    last, saved = attempt(spec, transport(export_api(calls)), checkpoint=partial[-1].checkpoint, committed=committed)
    assert last[-1].status == "PARTIAL" and "GITHUB_EXPORT_CONTENT_CHANGED" in last[-1].reasons
    assert len([r for r in saved if r.get("identity", {}).get("object_id", "").startswith("inventory:")]) == 1
