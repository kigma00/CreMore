"""confluence content API operations; shared lifecycle stays in the platform."""
from __future__ import annotations

import copy
import socket
from urllib.parse import parse_qs, quote, urljoin, urlsplit, urlunsplit

from cremore.collectors.base import CollectorError
from cremore.collectors.content import ContentCollector, ContentHTTP, build_roots
from cremore.http_client import HTTPResponseTooLarge, bounded_request
from cremore.network_addresses import PUBLIC, allowed

# Cloud's REST attachment download answers with a redirect to where the bytes are served.
_REDIRECTS = (301, 302, 303, 307, 308)
MAX_DOWNLOAD_HOPS = 2


def _origin(url):
    parts = urlsplit(url)
    return parts.scheme, (parts.hostname or "").lower(), parts.port or 443


def _resolve(host, port):
    # The absolute name: a resolver's search list never answers for another one.
    return {info[4][0] for info in socket.getaddrinfo(host + ".", port, type=socket.SOCK_STREAM)}


def _pinned(url):
    """``(url, headers, extensions)`` for a hop off the site: only to a name every address of which is public, and
    dialled at the checked address (the Host header and TLS server name keep the name), so a second DNS answer
    cannot move it to a loopback, metadata or intranet address."""
    parts = urlsplit(url)
    try:
        if parts.port not in (None, 443):
            raise ValueError
        host = parts.hostname.encode("idna").decode("ascii")
        addresses = _resolve(host, 443)
    except (OSError, UnicodeError, ValueError):
        raise CollectorError("CONFLUENCE_DOWNLOAD_ADDRESS_REFUSED") from None
    if allowed(addresses, allow_internal=False) != PUBLIC:
        raise CollectorError("CONFLUENCE_DOWNLOAD_ADDRESS_REFUSED")
    address = min(addresses, key=lambda item: (":" in item, item))  # IPv4 first, as many hosts cannot reach IPv6
    netloc = f"[{address}]" if ":" in address else address
    return (urlunsplit(("https", netloc, parts.path or "/", parts.query, "")), {"Host": host},
            {"sni_hostname": host})


class SourceHTTP(ContentHTTP):
    def __init__(self, payload, client, **kwargs):
        super().__init__(payload, client, **kwargs)
        self.api = "/api/v2" if payload["edition"] == "cloud" else "/rest/api"
        # The API address every page and listing request uses; downloads name the site (get(site=True)).
        self.base, self._site = None, None

    def site(self):
        """The site's API address: the site itself, or the Atlassian API gateway for a service account's token."""
        if self._site is None:
            self._site = self.payload["base_url"]
            if getattr(self.token, "gateway", False):
                from cremore_atlassian_provider.cloud_api import CloudError, api_site

                try:
                    self._site = api_site(self._site, self.client, self.budget)
                except CloudError as exc:
                    raise CollectorError(exc.code) from None
        return self._site

    def get(self, route, *, site=False, **kwargs):
        if self.base is None:
            self.base = self.site() + self.api
        if getattr(self.token, "gateway", False) and self.token.stale():
            self.budget.consume()  # the service account's token grant is one of this scan's requests too
        if not site:
            return super().get(route, **kwargs)
        # A download from the site itself, sent through a copy that carries the site's address: reads
        # running at the same time never see a changed base, and the API requests keep theirs.
        http = copy.copy(self)
        http.base = self.site()
        return ContentHTTP.get(http, route, **kwargs)

    def download(self, route, params=None):
        """Cloud attachment bytes through the documented REST download (a 302 to where they are served).

        At most MAX_DOWNLOAD_HOPS redirects, https only. The token goes only to the site's (or the
        gateway's) origin; once the chain leaves it, no later request carries it, and a hop off the site
        goes only to a public address, pinned (_pinned).
        [Download attachment](https://developer.atlassian.com/cloud/confluence/rest/v1/api-group-content---attachments/)
        """
        if getattr(self.token, "gateway", False) and self.token.stale():
            self.budget.consume()  # the service account's token grant is one of this scan's requests too
        token = self.token() if callable(self.token) else self.token
        if not token:
            raise CollectorError("NO_CREDENTIAL")
        url = self.site() + route
        origin, on_site = _origin(url), True
        for hop in range(MAX_DOWNLOAD_HOPS + 1):
            on_site = on_site and _origin(url) == origin
            sent, headers, extensions = url, {"Authorization": self.authorization(token)} if on_site else {}, {}
            if _origin(url) != origin:
                sent, headers, extensions = _pinned(url)
            try:
                response = bounded_request(
                    self.client, "GET", sent, params=params if hop == 0 else None, headers=headers,
                    extensions=extensions, follow_redirects=False, retry_429=True, before_attempt=self.budget.consume,
                    max_response_bytes=self.max_bytes, pacer=self.pacer)
            except CollectorError:
                raise
            except HTTPResponseTooLarge:
                raise CollectorError("SOURCE_RESPONSE_TOO_LARGE") from None
            except Exception:  # noqa: BLE001 -- Untrusted provider failures must become bounded safe collection failures.
                raise CollectorError("SOURCE_REQUEST_FAILED") from None
            if response.status_code == 200:
                return response.content
            if response.status_code not in _REDIRECTS:
                raise CollectorError("SOURCE_HTTP_FAILED", str(response.status_code))
            location = (response.headers or {}).get("location")
            try:
                target = urlsplit(urljoin(url, location)) if isinstance(location, str) and location else None
                # urljoin reads "https:///path" as a path on the current host; an absolute Location names its own.
                own = urlsplit(location) if target is not None else None
                valid = (target is not None and target.scheme == "https" and bool(target.hostname)
                         and not (own.scheme and not own.hostname)
                         and not target.username and not target.password and target.port != 0
                         and not any(ord(c) < 33 for c in location))
            except ValueError:  # a port that is not a number
                valid = False
            if not valid:
                raise CollectorError("CONFLUENCE_DOWNLOAD_REDIRECT_INVALID")
            url = target.geturl()
        raise CollectorError("CONFLUENCE_DOWNLOAD_REDIRECT_LIMIT")

    def confluence_pages(self, route, params=None):
        cursor, start, seen = "", 0, set()
        cloud = self.payload["edition"] == "cloud"
        while True:
            # Cloud rejects an empty cursor; omit it until a next-page link supplies one.
            paging = {"limit": 100} if cloud else {"start": start, "limit": 100}
            if cloud and cursor:
                paging["cursor"] = cursor
            body, _ = self.get(route, params={**(params or {}), **paging})
            if not isinstance(body, dict) or not isinstance(body.get("results"), list):
                raise CollectorError("SOURCE_LIST_MALFORMED")
            rows = body["results"]
            yield from rows
            link = (body.get("_links") or {}).get("next")
            if not link:
                return
            if not rows or link in seen:
                raise CollectorError("SOURCE_PAGINATION_LOOP")
            seen.add(link)
            # Consume only the cursor. Never follow provider-supplied URLs with credentials.
            if cloud:
                cursor = (parse_qs(urlsplit(link).query).get("cursor") or [""])[0]
                if not cursor:
                    raise CollectorError("SOURCE_PAGINATION_INCOMPLETE")
            else:
                start += len(rows)


def roots(payload, client, budget=None):
    """Discovery does not approve content reads."""
    http = SourceHTTP(payload, client, budget=budget)
    cloud = payload["edition"] == "cloud"
    route = "/spaces/" + quote(payload["space"], safe="") + "/pages" if cloud else "/content"
    params = {"status": "current"} if cloud else {"spaceKey": payload["space"], "type": "page", "status": "current"}
    for row in http.confluence_pages(route, params):
        yield "CONFLUENCE_PAGE", str(row["id"]), str(row["id"])


class Collector(ContentCollector):
    PROVIDER = "confluence"
    ROOT_FIELD = "page_id"
    HTTP = SourceHTTP
    # Attachment downloads overlap on the scan's read-ahead threads (ContentCollector's eight):
    # each names its own site address and shares no state with the listing or another read.

    def resource_metadata(self):
        return {"source_instance": self.p["base_url"], "source_site": self.p.get("site_url", self.p["base_url"])}

    def objects(self):
        page = self.p["page_id"]
        cloud = self.p["edition"] == "cloud"
        route = "/pages/" + quote(page, safe="") if cloud else "/content/" + quote(page, safe="")
        read_body = self.selected("body")
        params = ({"body-format": "storage"} if read_body else {}) if cloud else {"expand": "body.storage,version,space" if read_body else "version,space"}
        response, _ = self.http.get(route, params=params)
        space = str(response.get("spaceId", "")) if cloud else (response.get("space") or {}).get("key", "")
        if str(response.get("id")) != page or space != self.p["space"]:
            raise CollectorError("CONFLUENCE_PAGE_OUTSIDE_SCOPE")
        current = response["version"]["number"]
        version = str(current)
        if read_body:
            body = response["body"]["storage"]["value"].encode("utf-8")
            # A page version names its body: an unchanged page is answered by the detection cache. A Cloud live
            # doc changes its body without a new version, so it is scanned every time (its body is here anyway).
            named = type(current) is int and current > 0 and response.get("subtype") != "live"
            yield self.object(page, "body", version, lambda: body, revision=f"{page}:{current}" if named else None)
        attachment_route = route + "/attachments" if cloud else route + "/child/attachment"
        context_path = urlsplit(self.p["base_url"]).path
        # Data Center lists attachments without their version unless asked (an empty expand by default).
        for attachment in self.http.confluence_pages(attachment_route, None if cloud else {"expand": "version"}):
            ident = str(attachment["id"])
            key = "attachments/" + ident
            if not self.selected(key):
                continue
            self.listed(key)
            own = (attachment.get("version") or {}).get("number")
            number = str(own if own is not None else version)
            if cloud:
                # The documented REST download. downloadLink (/download/attachments/...) no longer answers a token
                # (CHANGE-2735). The version asked for is the one the revision names.
                rest = f"/rest/api/content/{quote(page, safe='')}/child/attachment/{quote(ident, safe='')}/download"
                pinned = {"version": own} if type(own) is int and own > 0 else None

                def load(rest=rest, pinned=pinned):
                    return self.http.download(rest, pinned)
            else:
                # Downloads are relative to the declared site. Reject external
                # storage/CDN redirects instead of forwarding a PAT.
                download = (attachment.get("_links") or {}).get("download")
                if not isinstance(download, str) or not download.startswith("/") or download.startswith("//"):
                    self.failed_objects += 1
                    continue
                parsed = urlsplit(download)
                if parsed.scheme or parsed.netloc or any(part in (".", "..") for part in parsed.path.split("/")):
                    self.failed_objects += 1
                    continue
                # The same origin and deployment context, never the links.base response field.
                site_route = (download[len(context_path):] if context_path and download.startswith(context_path + "/")
                              else download)

                def load(site_route=site_route):
                    return self.http.get(site_route, raw=True, site=True)
            # The attachment's own version: an unchanged attachment is not downloaded again. Without one the
            # page's version would not move when a new file version is uploaded, so nothing is cached.
            yield self.object(page, key, number, load, revision=ident + ":" + number if own is not None else None)

    confluence = objects


def build(payload, client, **kwargs):
    return build_roots(Collector, roots, payload, client, **kwargs)
