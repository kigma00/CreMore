"""Asynchronous export API and credential-free, address-pinned CSV download."""

from __future__ import annotations

import http.client
import ipaddress
import ssl
import time
from contextlib import contextmanager
from urllib.parse import urljoin, urlsplit

import httpx

from cremore.network_addresses import PUBLIC, allowed

from .endpoints import inventory_flags
from .exports import MAX_EXPORT_BYTES, ExportError, export_id, timestamp
from .http import SourceError

MAX_DOWNLOAD_SECONDS = 300
# Documented: pending, queued, started (then 302 when ready, or error).
_PENDING = {"queued", "pending", "started", "processing", "in_progress", "generating"}


def _payload(response):
    try:
        data = response.json()
    except ValueError:
        raise ExportError("github_export_invalid_response") from None
    if not isinstance(data, dict):
        raise ExportError("github_export_invalid_response")
    return data


def create(transport, bearer):
    """Exactly one submission. The caller must durably reserve it before calling."""
    response, headers = transport.response("POST",
        f"/enterprises/{transport.enterprise}/credentials/exports", bearer, json={}, export=True)
    if response.status_code != 202:
        raise ExportError("github_export_creation_unconfirmed")
    data = _payload(response)
    if data.get("status") not in _PENDING:
        raise ExportError("github_export_creation_unconfirmed")
    warnings, _generated = inventory_flags(headers)
    return {"export_id": export_id(data.get("export_id")), "stage": "queued",
            "as_of": _as_of(data.get("as_of")), "warnings": warnings}


def _as_of(value):
    # Documented as "string or null"; a later poll may report it.
    return None if value is None else timestamp(value)


def poll(transport, bearer, state):
    response, headers = transport.response("GET",
        f"/enterprises/{transport.enterprise}/credentials/exports/{export_id(state['export_id'])}", bearer, export=True)
    if response.status_code == 302:
        location = headers.get("location")
        if not isinstance(location, str) or not location:
            raise ExportError("github_export_missing_download")
        # This transient location is only passed to download(), never into a
        # checkpoint, record, job result, diagnostic or public response.
        return location
    if response.status_code != 200:
        raise ExportError("github_export_invalid_response")
    data = _payload(response)
    if export_id(data.get("export_id")) != state["export_id"]:
        raise ExportError("github_export_identity_changed")
    if data.get("as_of") is not None:
        as_of = timestamp(data["as_of"])
        if state.get("as_of") is None:
            state["as_of"] = as_of
        elif as_of != state["as_of"]:
            raise ExportError("github_export_snapshot_changed")
    if data.get("status") not in _PENDING:
        raise ExportError("github_export_expired" if data.get("status") == "expired" else "github_export_failed")
    return None


def _resolve(host, timeout):
    """Explicit lifetime, absolute DNS names, and both address families."""
    import dns.exception
    import dns.resolver

    try:
        return {str(ipaddress.ip_address(host))}
    except ValueError:
        pass
    addresses = set()
    resolver = dns.resolver.Resolver()
    for family in ("A", "AAAA"):
        try:
            addresses.update(str(record) for record in resolver.resolve(host + ".", family, lifetime=timeout / 2))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except dns.exception.DNSException:
            raise ExportError("github_export_dns_unavailable") from None
    return addresses


def _target(url, api, resolve, timeout):
    try:
        if (not isinstance(url, str) or len(url) > 16384 or "\\" in url
                or any(ord(char) < 33 or ord(char) == 127 for char in url)):
            raise ValueError
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.port not in (None, 443) or parsed.fragment):
            raise ValueError
        hostname = parsed.hostname.encode("idna").decode("ascii").lower()
        if hostname.endswith("."):
            raise ValueError
        validated = httpx.URL(url)
    except (ValueError, UnicodeError, httpx.InvalidURL):
        raise ExportError("github_export_download_url_refused") from None
    addresses = resolve(hostname, timeout)
    # An explicitly configured GHES origin may be on a private network. A
    # redirect to any other host must resolve exclusively to public addresses.
    same_origin = hostname == urlsplit(api).hostname
    internal = same_origin and hostname != "api.github.com" and not hostname.endswith(".ghe.com")
    if not addresses or (allowed(addresses, allow_internal=internal) != PUBLIC and not (
            internal and allowed(addresses, allow_internal=True) is not None)):
        raise ExportError("github_export_download_address_refused")
    address = min(addresses, key=lambda item: (":" in item, item))
    url = validated.copy_with(host=address)
    return url, hostname


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Standard-library TLS without HTTPX/httpcore request logging.

    Only the already checked IP is dialled; the certificate and SNI use the
    original hostname. No proxy, cookie jar or ambient authorization is used.
    """

    def __init__(self, address, hostname, *, timeout):
        super().__init__(address, timeout=timeout, context=ssl.create_default_context())
        self.set_debuglevel(0)
        self.hostname = hostname

    def connect(self):
        http.client.HTTPConnection.connect(self)
        try:
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self.hostname)
        except BaseException:
            self.close()
            raise


@contextmanager
def _response(pinned, host, timeout, connection_factory):
    connection = connection_factory(pinned.host, host, timeout=timeout)
    try:
        connection.request("GET", pinned.raw_path.decode("ascii"), headers={"Host": host,
            "Accept": "text/csv, application/octet-stream", "Accept-Encoding": "identity",
            "User-Agent": "CreMore-Coverage/1.0"})
        with connection.getresponse() as response:
            yield response
    finally:
        connection.close()


def download(transport, location, *, resolve=None, connection_factory=None, clock=time.monotonic):
    """Bounded chunks with pinned DNS, verified TLS and no forwarded credentials."""
    resolve = resolve or _resolve
    connection_factory = connection_factory or _PinnedHTTPSConnection
    deadline = clock() + MAX_DOWNLOAD_SECONDS
    current, total = location, 0
    timeout = transport.options.timeout_seconds
    for _ in range(4):
        transport.check()
        if clock() >= deadline:
            raise ExportError("github_export_download_time_limit")
        pinned, host = _target(current, transport.api, resolve, min(timeout, max(.1, deadline - clock())))
        transport._charge()
        transport._pace()
        # One connection per redirect; signed URLs never enter a logging HTTP client.
        try:
            with _response(pinned, host, min(timeout, max(.1, deadline - clock())), connection_factory) as response:
                if response.status in (301, 302, 303, 307, 308):
                    following = response.getheader("location")
                    if not following:
                        raise ExportError("github_export_missing_download")
                    current = urljoin(current, following)
                    continue
                if response.status in (401, 403, 404):
                    # Re-poll the same export to obtain a fresh signed URL.
                    raise SourceError("github_export_download_expired", retry_after=30)
                if response.status != 200:
                    raise SourceError("github_unavailable" if response.status >= 500
                                      else "github_export_download_failed")
                if response.getheader("content-encoding", "identity").lower() != "identity":
                    raise ExportError("github_export_download_encoding_refused")
                length = response.getheader("content-length")
                try:
                    if length is not None and (int(length) < 0 or int(length) > MAX_EXPORT_BYTES):
                        raise ExportError("github_export_size_limit")
                except ValueError:
                    raise ExportError("github_export_invalid_content_length") from None
                while True:
                    transport.check()
                    if clock() >= deadline:
                        raise ExportError("github_export_download_time_limit")
                    chunk = response.read(64 << 10)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_EXPORT_BYTES:
                        raise ExportError("github_export_size_limit")
                    yield chunk
                if length is not None and total != int(length):
                    raise ExportError("github_export_incomplete_download")
                return
        except (OSError, http.client.HTTPException):
            raise SourceError("github_unavailable") from None
    raise ExportError("github_export_redirect_limit")
