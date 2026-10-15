"""The web exposure scan's fetcher: only covered hosts, allowed addresses, pinned connections, bounded reads (N4b).
Synthetic sites and a synthetic resolver; the deadline test talks to a server on this machine's loopback only."""

from __future__ import annotations

import gzip
import socket
import threading
import time
import tracemalloc

import httpx
import pytest

from cremore_website_provider import fetch
from cremore_website_provider.addresses import INTERNAL, PUBLIC
from cremore_website_provider.fetch import Fetcher, FetchRefused

VERIFIED = {"acme.test": False, "intranet.acme.test": True}  # name -> allow_internal
ADDRESSES = {"acme.test": {"8.8.8.10"}, "www.acme.test": {"8.8.8.11"}, "intranet.acme.test": {"10.0.0.8"},
             "split.acme.test": {"8.8.8.12", "10.0.0.9"}, "meta.acme.test": {"169.254.169.254"},
             "dual.acme.test": {"2606:4700::1111", "8.8.8.13"}, "evil.test": {"8.8.8.66"}}


def cover(host):
    host = host.lower()
    for name, internal in sorted(VERIFIED.items(), key=lambda item: -len(item[0])):
        if host == name or host.endswith("." + name):
            return {"name": name, "host": host, "allow_internal": internal}
    return None


def answer(status, headers=None, body=b""):
    # A stream not yet read, as a real transport hands it over (content= would read and decode it at once).
    return httpx.Response(status, headers=headers or {}, stream=httpx.ByteStream(body))


class Site:
    """Answers by the pinned address and the Host header, as a real server behind that address would."""

    def __init__(self, pages):
        self.pages, self.seen, self.headers = pages, [], []

    def __call__(self, proxy):
        def handler(request):
            self.seen.append((proxy, str(request.url), request.headers.get("host"),
                              request.extensions.get("sni_hostname")))
            self.headers.append(request.headers)
            page = self.pages.get((request.headers.get("host"), request.url.path))
            return answer(*page) if page is not None else answer(404)
        return httpx.Client(transport=httpx.MockTransport(handler))


def fetcher(site, **extra):
    return Fetcher(cover, resolve=lambda host, port: ADDRESSES.get(host) or (_ for _ in ()).throw(OSError()),
                   client_factory=site, proxies={}, **extra)


def refused(call, *args):
    with pytest.raises(FetchRefused) as raised:
        call(*args)
    return raised.value.code


def test_a_covered_host_is_fetched_over_the_checked_address_named_by_its_host():
    site = Site({("acme.test", "/"): (200, {"content-type": "text/html; charset=utf-8"}, b"<html>ok</html>")})
    page = fetcher(site).get("https://ACME.test/")
    assert (page.status, page.content_type, page.body, page.reach) == (200, "text/html", b"<html>ok</html>", PUBLIC)
    assert site.seen == [(None, "https://8.8.8.10/", "acme.test", "acme.test")]  # httpx drops the default port
    # A new connection per request, never reused for another name; raw bytes asked for.
    assert (site.headers[0]["connection"], site.headers[0]["accept-encoding"]) == ("close", "identity")
    # Of a name's checked addresses, IPv4 first.
    dual = Site({("dual.acme.test", "/"): (200, {}, b"ok")})
    fetcher(dual).get("https://dual.acme.test/")
    assert dual.seen[0][1] == "https://8.8.8.13/"


def test_names_are_resolved_as_absolute_names(monkeypatch):
    asked = []
    monkeypatch.setattr(fetch.socket, "getaddrinfo",
                        lambda host, port, **kwargs: asked.append(host) or [(2, 1, 6, "", ("8.8.8.10", port))])
    assert fetch._resolve("acme.test", 443) == {"8.8.8.10"} and asked == ["acme.test."]


def test_redirects_are_followed_only_inside_covered_hosts_allowed_addresses_and_the_scope():
    site = Site({("acme.test", "/"): (301, {"location": "https://www.acme.test/home"}, b""),
                 ("www.acme.test", "/home"): (302, {"location": "https://evil.test/steal"}, b"")})
    assert refused(fetcher(site).get, "https://acme.test/") == "HOST_NOT_VERIFIED"
    assert [host for _p, _u, host, _s in site.seen] == ["acme.test", "www.acme.test"]  # evil.test never asked
    loop = Site({("acme.test", "/"): (302, {"location": "/"}, b"")})
    assert refused(fetcher(loop).get, "https://acme.test/") == "TOO_MANY_REDIRECTS" and len(loop.seen) == 6
    # A hop the approved scope leaves out is never asked for.
    admin = Site({("acme.test", "/"): (302, {"location": "/admin/secret"}, b""), ("acme.test", "/admin/secret"): (200, {}, b"x")})
    assert refused(fetcher(admin).get, "https://acme.test/", lambda url: "/admin/" not in url) == "PATH_NOT_ALLOWED"
    assert [url for _p, url, _h, _s in admin.seen] == ["https://8.8.8.10/"]
    # Never from https down to plain http, and a Location that is not a URL is a code, not an error (httpx reads
    # the Location itself and calls such a site broken).
    down = Site({("acme.test", "/"): (302, {"location": "http://acme.test/plain"}, b"")})
    assert refused(fetcher(down).get, "https://acme.test/") == "REDIRECT_DOWNGRADE"
    broken = Site({("acme.test", "/"): (302, {"location": "http://[::1/x"}, b"")})
    assert refused(fetcher(broken).get, "https://acme.test/") == "SITE_UNAVAILABLE"


@pytest.mark.parametrize(("url", "code"), [
    ("https://intranet.acme.test.evil.test/", "HOST_NOT_VERIFIED"), ("https://10.0.0.8/", "HOST_NOT_VERIFIED"),
    ("https://127.0x1/", "HOST_NOT_VERIFIED"), ("ftp://acme.test/", "URL_NOT_ALLOWED"),
    ("https://user:" + "pass@acme.test/", "URL_NOT_ALLOWED"), ("https://acme.test:8443/", "PORT_NOT_ALLOWED"),
    ("https://split.acme.test/", "ADDRESS_NOT_ALLOWED"), ("https://meta.acme.test/", "ADDRESS_NOT_ALLOWED"),
    ("https://missing.acme.test/", "HOST_NOT_RESOLVED"), ("https://acme.test:99999/", "URL_NOT_ALLOWED"),
    ("http://[::1/x.js", "URL_NOT_ALLOWED")])
def test_what_is_never_reached(url, code):
    site = Site({})
    assert refused(fetcher(site).get, url) == code and site.seen == []


def test_a_url_httpx_cannot_send_is_a_code():
    assert refused(fetcher(Site({})).get, "https://acme.test/a\x01b") == "URL_NOT_ALLOWED"
    assert refused(fetcher(Site({})).get, "https://acme.test/" + "a" * 70_000) == "URL_NOT_ALLOWED"


def test_internal_sites_and_ports_only_where_allowed():
    site = Site({("intranet.acme.test:8080", "/app"): (200, {"content-type": "application/javascript"}, b"x")})
    page = fetcher(site, ports={"intranet.acme.test": {8080}}).get("http://intranet.acme.test:8080/app")
    assert page.reach == INTERNAL and site.seen == [(None, "http://10.0.0.8:8080/app", "intranet.acme.test:8080", None)]


def test_the_fetcher_alone_decides_a_proxy_and_its_clients_never_read_the_environment():
    site = Site({("acme.test", "/"): (200, {}, b"via proxy")})
    proxied = Fetcher(cover, resolve=lambda host, port: ADDRESSES[host], client_factory=site,
                      proxies={"https": "http://proxy.corp:3128"}, bypass=lambda host: False)
    assert proxied.get("https://acme.test/").body == b"via proxy"
    assert site.seen == [("http://proxy.corp:3128", "https://acme.test/", "acme.test", None)]
    # The address rule still holds before anything is sent.
    assert refused(proxied.get, "https://meta.acme.test/") == "ADDRESS_NOT_ALLOWED"
    # A host NO_PROXY leaves out (NO_PROXY=* included) goes direct, pinned, never by the name.
    direct = Site({("acme.test", "/"): (200, {}, b"direct")})
    Fetcher(cover, resolve=lambda host, port: ADDRESSES[host], client_factory=direct,
            proxies={"https": "http://proxy.corp:3128"}, bypass=lambda host: True).get("https://acme.test/")
    assert direct.seen == [(None, "https://8.8.8.10/", "acme.test", "acme.test")]
    with fetch._client(None) as pinned, fetch._client("http://proxy.corp:3128") as through:
        assert (pinned.trust_env, through.trust_env, len(pinned._mounts), len(through._mounts)) == (False, False, 0, 1)
    # A proxy named without a scheme, as curl takes it, is an http proxy; one httpx cannot use is a code.
    bare = Site({("acme.test", "/"): (200, {}, b"ok")})
    Fetcher(cover, resolve=lambda host, port: ADDRESSES[host], client_factory=bare, proxies={"https": "proxy.corp:3128"},
            bypass=lambda host: False).get("https://acme.test/")
    assert bare.seen[0][0] == "http://proxy.corp:3128"

    def unusable(proxy):
        raise ValueError("Unknown scheme for proxy URL")

    assert refused(Fetcher(cover, resolve=lambda host, port: ADDRESSES[host], client_factory=unusable,
                           proxies={"https": "socks9://proxy.corp:1"}, bypass=lambda host: False).get, "https://acme.test/") == "PROXY_INVALID"
    assert refused(Fetcher(cover, resolve=lambda host, port: ADDRESSES[host], proxies={"https": "http://[::1"},
                           bypass=lambda host: False).get, "https://acme.test/") == "PROXY_INVALID"  # httpx's own InvalidURL


def test_bodies_are_read_raw_within_the_bound():
    assert refused(fetcher(Site({("acme.test", "/"): (200, {}, b"x" * 2048)}), max_bytes=1024).get,
                   "https://acme.test/") == "TOO_LARGE"
    page = gzip.compress(b"<script src=/app.js></script>")
    zipped = Site({("acme.test", "/"): (200, {"content-encoding": "gzip"}, page)})
    assert fetcher(zipped).get("https://acme.test/").body == b"<script src=/app.js></script>"
    # A gzip bomb inflates only as far as the bound; stacked or other encodings are refused unread.
    bomb = gzip.compress(bytes(16 << 20))
    tracemalloc.start()
    try:
        code = refused(fetcher(Site({("acme.test", "/"): (200, {"content-encoding": "gzip"}, bomb)}), max_bytes=1 << 20).get,
                       "https://acme.test/")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert code == "TOO_LARGE" and peak < 6 << 20
    for encoding in ("gzip, gzip", "br", "zstd"):
        assert refused(fetcher(Site({("acme.test", "/"): (200, {"content-encoding": encoding}, bomb)})).get,
                       "https://acme.test/") == "ENCODING_NOT_ALLOWED"
    # A whole gzip member is the page, and reading stops there, whatever keeps streaming after it.
    class Member(httpx.SyncByteStream):
        read = 0

        def __iter__(self):
            yield gzip.compress(b"page")
            for _ in range(500):
                Member.read += 1
                yield bytes(64 << 10)

    def streaming(proxy):
        return httpx.Client(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, headers={"content-encoding": "gzip"}, stream=Member())))

    assert fetcher(streaming, max_bytes=1024).get("https://acme.test/").body == b"page" and Member.read == 0
    # A member cut short is not a page.
    cut = Site({("acme.test", "/"): (200, {"content-encoding": "gzip"}, gzip.compress(b"page" * 100)[:-12])})
    assert refused(fetcher(cut).get, "https://acme.test/") == "SITE_UNAVAILABLE"


def test_a_trickling_body_and_a_site_that_fails_are_codes():
    class Trickle(httpx.SyncByteStream):
        def __iter__(self):
            for _ in range(200):
                time.sleep(0.02)
                yield b"x"

    def slow(proxy):
        return httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=Trickle())))

    started = time.monotonic()
    assert refused(fetcher(slow, deadline=0.2).get, "https://acme.test/") == "SITE_TOO_SLOW"
    assert time.monotonic() - started < 2

    def down(proxy):
        return httpx.Client(transport=httpx.MockTransport(lambda request: (_ for _ in ()).throw(httpx.ConnectError("x"))))

    assert refused(fetcher(down).get, "https://acme.test/") == "SITE_UNAVAILABLE"


def test_a_response_past_its_deadline_is_hung_up_even_while_its_headers_trickle():
    # A server on this machine's loopback that never finishes its headers: only closing the connection ends the read.
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve():
        conn, _ = server.accept()
        with conn:
            conn.sendall(b"HTTP/1.1 200 OK\r\n")
            until = time.monotonic() + 10
            while time.monotonic() < until:
                try:
                    conn.sendall(b"X")
                except OSError:
                    return
                time.sleep(0.05)

    threading.Thread(target=serve, daemon=True).start()
    started = time.monotonic()
    try:
        # Past the address rule on purpose: this test is about the deadline alone.
        code = refused(Fetcher(cover, proxies={}, deadline=0.5)._send,
                       fetch._Target("http", "acme.test", port, "/", "127.0.0.1", PUBLIC))
    finally:
        server.close()
    assert code == "SITE_TOO_SLOW" and time.monotonic() - started < 5


def test_a_body_the_deadline_ended_is_never_taken_as_whole():
    # No length and not chunked: the body runs until the connection closes. The server sends part and goes silent.
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve():
        conn, _ = server.accept()
        with conn:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>partial")
            time.sleep(5)

    threading.Thread(target=serve, daemon=True).start()
    try:
        # A short read timeout keeps the test quick where a shutdown does not wake a waiting read (Windows).
        quick = Fetcher(cover, proxies={}, deadline=0.5, client_factory=lambda proxy: httpx.Client(timeout=1.0, trust_env=False))
        code = refused(quick._send, fetch._Target("http", "acme.test", port, "/", "127.0.0.1", PUBLIC))
    finally:
        server.close()
    assert code == "SITE_TOO_SLOW"


def test_every_request_is_counted_before_it_goes():
    site = Site({("acme.test", "/"): (301, {"location": "/a"}, b""), ("acme.test", "/a"): (200, {}, b"ok")})
    counted = []
    fetcher(site, before_request=lambda: counted.append(1)).get("https://acme.test/")
    assert len(counted) == 2


def test_the_scans_own_client_keeps_no_cookie_a_site_sets():
    with fetch._client(None) as client:
        client.cookies.extract_cookies(httpx.Response(200, headers={"set-cookie": "session=abc; Path=/"},
                                                      request=httpx.Request("GET", "https://8.8.8.9/")))
        assert len(client.cookies) == 0 and client.follow_redirects is False and client.trust_env is False
