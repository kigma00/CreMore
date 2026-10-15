"""A company's own web page or asset, fetched only as its verified domains allow (N4b).

Every request, each redirect's included, goes to a host a verified domain covers (``cover``: cremore.domains.covering
bound to the repository and the time), on the scheme's default port or a port the scan's own start URLs name for that
host, and only after every address the name resolves to passes the domain's address rule
(cremore_website_provider.addresses). Without a proxy the connection is pinned to the checked address: the URL names
the address, the Host header and the TLS server name name the host, so a second DNS answer cannot move it. With a
proxy the environment names (HTTPS_PROXY / HTTP_PROXY, not bypassed by NO_PROXY), the proxy resolves the name itself:
the check is still made, but only the proxy's own rules bind what it reaches (docs/DOMAIN_VERIFICATION.md). That
decision is this module's alone: no client reads the environment.

GET only, no cookies, no credentials, a new connection per request, at most five redirects, never from https down to
http. A body is read raw, as sent: identity or one whole gzip member (inflated within the size bound), anything else
refused; the server's charset is never applied. One response has a deadline from its request to its last byte,
enforced by shutting its connection down (on Windows a read already waiting may take its 20-second read timeout to
end). Failures are stable codes, never the site's answer.
"""

from __future__ import annotations

import dataclasses
import functools
import http.cookiejar
import socket
import threading
import time
import urllib.parse
import urllib.request
import zlib

import httpx

from cremore_website_provider.addresses import allowed

MAX_REDIRECTS = 5
DEADLINE = 60.0  # seconds, one response from its request to its last byte
DEFAULT_PORTS = {"https": 443, "http": 80}
HEADERS = {"User-Agent": "CreMore-exposure-scan/1", "Accept": "*/*", "Accept-Encoding": "identity",
           "Connection": "close"}
_REDIRECTS = (301, 302, 303, 307, 308)
_GZIP = ("gzip", "x-gzip")


class FetchRefused(Exception):
    """A URL the scan does not reach, or could not read: a stable code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclasses.dataclass(frozen=True)
class Page:
    url: str  # where the content came from, after redirects
    status: int
    content_type: str
    body: bytes
    reach: str  # addresses.PUBLIC or addresses.INTERNAL
    headers: dict


@dataclasses.dataclass(frozen=True)
class _Target:
    scheme: str
    host: str
    port: int
    path: str
    address: str
    reach: str


def _resolve(host: str, port: int) -> set[str]:
    # The absolute name: a resolver's search list never answers for another one.
    return {info[4][0] for info in socket.getaddrinfo(host + ".", port, type=socket.SOCK_STREAM)}


@functools.cache
def _context():
    # The platform's own TLS trust (certifi, or SSL_CERT_FILE / SSL_CERT_DIR in its place), made once.
    return httpx.create_ssl_context(trust_env=True)


def _client(proxy: str | None) -> httpx.Client:
    # No environment: whether a proxy is used, and which, is the fetcher's decision. A pinned connection never goes
    # through a proxy, since a proxy tunnel would verify the certificate against the address. A cookie a site sets is
    # never kept, so every request is the same anonymous one.
    return httpx.Client(timeout=20.0, follow_redirects=False, trust_env=False, proxy=proxy, verify=_context(),
                        cookies=http.cookiejar.CookieJar(http.cookiejar.DefaultCookiePolicy(allowed_domains=[])))


def _hang_up(opened: dict) -> None:
    """Ends a response past its deadline: shutting its socket down wakes a read blocked on it."""
    stream = opened.get("stream")
    sock = stream.get_extra_info("socket") if stream is not None else None
    if sock is not None:
        try:
            # The plain socket's own shutdown: a TLS socket's would drop its TLS object under the reading thread.
            socket.socket.shutdown(sock, socket.SHUT_RDWR)
        except OSError:
            pass  # already closed: the read is over anyway


class Fetcher:
    def __init__(self, cover, *, ports=None, resolve=None, client_factory=None, proxies=None, bypass=None,
                 max_bytes: int = 5 << 20, before_request=None, deadline: float = DEADLINE) -> None:
        self.cover = cover
        self.ports = {host: set(extra) for host, extra in (ports or {}).items()}
        self.resolve = resolve or _resolve
        self.client_factory = client_factory or _client
        self.proxies = urllib.request.getproxies_environment() if proxies is None else proxies
        self.bypass = bypass or urllib.request.proxy_bypass_environment
        self.max_bytes = max_bytes
        self.before_request = before_request
        self.deadline = deadline
        self._clients: dict = {}

    def get(self, url: str, allowed_url=None) -> Page:
        """The page at ``url``; ``allowed_url(url)`` bounds every hop by the approved scope (``PATH_NOT_ALLOWED``)."""
        for _hop in range(MAX_REDIRECTS + 1):
            if allowed_url is not None and not allowed_url(url):
                raise FetchRefused("PATH_NOT_ALLOWED")
            target = self._target(url)
            status, headers, body = self._send(target)
            location = headers.get("location")
            if status in _REDIRECTS and location:
                try:
                    following = urllib.parse.urljoin(url, location)
                except ValueError:
                    raise FetchRefused("URL_NOT_ALLOWED") from None
                if target.scheme == "https" and urllib.parse.urlsplit(following).scheme.lower() == "http":
                    raise FetchRefused("REDIRECT_DOWNGRADE")  # asked for over TLS, never read in plaintext
                url = following
                continue
            return Page(url=url, status=status,
                        content_type=str(headers.get("content-type") or "").split(";")[0].strip().lower(),
                        body=body, reach=target.reach, headers=dict(headers))
        raise FetchRefused("TOO_MANY_REDIRECTS")

    def _target(self, url: str) -> _Target:
        try:
            parts = urllib.parse.urlsplit(url)
            port = parts.port
        except ValueError:
            raise FetchRefused("URL_NOT_ALLOWED") from None
        scheme = parts.scheme.lower()
        if scheme not in DEFAULT_PORTS or parts.username is not None or parts.password is not None or not parts.hostname:
            raise FetchRefused("URL_NOT_ALLOWED")
        covered = self.cover(parts.hostname)
        if covered is None:
            raise FetchRefused("HOST_NOT_VERIFIED")
        host = covered["host"]
        port = port or DEFAULT_PORTS[scheme]
        if port != DEFAULT_PORTS[scheme] and port not in self.ports.get(host, ()):
            raise FetchRefused("PORT_NOT_ALLOWED")
        try:
            addresses = self.resolve(host, port)
        except OSError:
            raise FetchRefused("HOST_NOT_RESOLVED") from None
        reach = allowed(addresses, allow_internal=bool(covered["allow_internal"]))
        if reach is None:
            raise FetchRefused("ADDRESS_NOT_ALLOWED")
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")  # as the URL gives it
        # Every address passed; IPv4 first, since many hosts cannot reach IPv6.
        address = min(addresses, key=lambda item: (":" in item, item))
        return _Target(scheme, host, port, path, address, reach)

    def _proxy(self, target: _Target) -> str | None:
        proxy = self.proxies.get(target.scheme)
        if not proxy or self.bypass(target.host):
            return None
        return proxy if "://" in proxy else f"http://{proxy}"  # "proxy.corp:3128", as curl reads it

    def _send(self, target: _Target):
        """``(status, headers, body)`` of one request, read within the size bound and the deadline."""
        default = target.port == DEFAULT_PORTS[target.scheme]
        authority = target.host if default else f"{target.host}:{target.port}"
        proxy = self._proxy(target)
        if proxy:
            url, headers, extensions = f"{target.scheme}://{authority}{target.path}", HEADERS, {}
        else:
            address = f"[{target.address}]" if ":" in target.address else target.address
            url = f"{target.scheme}://{address}:{target.port}{target.path}"
            headers = {**HEADERS, "Host": authority}
            extensions = {"sni_hostname": target.host} if target.scheme == "https" else {}
        client = self._clients.get(proxy)
        if client is None:
            try:
                client = self._clients[proxy] = self.client_factory(proxy)
            except (ValueError, ImportError, httpx.InvalidURL):
                raise FetchRefused("PROXY_INVALID") from None  # a proxy the environment names that httpx cannot use
        if self.before_request is not None:
            self.before_request()
        opened: dict = {}  # the request's own connection (a new one each time: Connection: close)

        def trace(event, info):
            if event.endswith(("connect_tcp.complete", "start_tls.complete")) and info.get("return_value") is not None:
                opened["stream"] = info["return_value"]

        timer = threading.Timer(self.deadline, _hang_up, (opened,))
        timer.daemon = True
        started = time.monotonic()
        timer.start()
        try:
            with client.stream("GET", url, headers=headers, extensions={**extensions, "trace": trace}) as response:
                return response.status_code, response.headers, self._body(response, started)
        except httpx.InvalidURL:
            raise FetchRefused("URL_NOT_ALLOWED") from None
        except (httpx.HTTPError, httpx.StreamError):
            late = time.monotonic() - started >= self.deadline
            raise FetchRefused("SITE_TOO_SLOW" if late else "SITE_UNAVAILABLE") from None
        except (OSError, ValueError, AttributeError):
            if time.monotonic() - started >= self.deadline:
                raise FetchRefused("SITE_TOO_SLOW") from None  # whatever the hang-up left the reading thread with
            raise
        finally:
            timer.cancel()

    def _body(self, response, started: float) -> bytes:
        encoding = response.headers.get("content-encoding", "").strip().lower()
        if encoding in ("", "identity"):
            inflate = None
            try:
                if int(response.headers.get("content-length") or 0) > self.max_bytes:
                    raise FetchRefused("TOO_LARGE")
            except ValueError:
                pass  # a malformed length: the read below still stops at the bound
        elif encoding in _GZIP:
            inflate = zlib.decompressobj(16 + zlib.MAX_WBITS)  # one gzip layer, inflated only as far as the bound
        else:
            raise FetchRefused("ENCODING_NOT_ALLOWED")  # br, zstd, stacked layers: identity was asked for
        body = bytearray()
        for chunk in response.iter_raw():
            if inflate is not None:
                try:
                    chunk = inflate.decompress(chunk, self.max_bytes + 1 - len(body))
                except zlib.error:
                    raise FetchRefused("SITE_UNAVAILABLE") from None
                if inflate.unconsumed_tail:
                    raise FetchRefused("TOO_LARGE")
            body += chunk
            if len(body) > self.max_bytes:
                raise FetchRefused("TOO_LARGE")
            if time.monotonic() - started >= self.deadline:
                raise FetchRefused("SITE_TOO_SLOW")
            if inflate is not None and inflate.eof:
                break  # the gzip member is whole: what follows it is not the page
        if time.monotonic() - started >= self.deadline:
            raise FetchRefused("SITE_TOO_SLOW")  # a body the hang-up ended is not a whole one
        if inflate is not None and not inflate.eof:
            raise FetchRefused("SITE_UNAVAILABLE")  # a gzip body cut short
        return bytes(body)

    def close(self) -> None:
        for client in self._clients.values():
            client.close()
        self._clients.clear()
