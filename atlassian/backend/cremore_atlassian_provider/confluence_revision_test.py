"""A Confluence page body is named by its version, so the detection cache answers for an unchanged page."""

import ipaddress
import json
import uuid

import httpx
import pytest

from cremore.collectors.base import CollectorError
from cremore.db.repository import InMemoryRepository
from cremore.scanning import service as service_module
from cremore.scanning.orchestrator import Orchestrator
from cremore.scanning.service import ScanService
from cremore_atlassian_provider import confluence_content
from cremore_atlassian_provider.confluence_content import Collector, SourceHTTP

SITE = "https://example.atlassian.net/wiki"
DC = "https://confluence.example.test/confluence"
MEDIA_ADDRESS = "93.184.216.34"  # a public address the fake media host resolves to; nothing is dialled
NAMES = {"media.example.test": {MEDIA_ADDRESS}}


def fake_resolve(host, _port):
    try:
        return {str(ipaddress.ip_address(host))}  # an address literal is itself, as getaddrinfo answers it
    except ValueError:
        pass
    if NAMES.get(host):
        return NAMES[host]
    raise OSError("not found")


@pytest.fixture(autouse=True)
def resolver(monkeypatch):
    monkeypatch.setattr(confluence_content, "_resolve", fake_resolve)


def logical(url, headers):
    """The URL a request names: a pinned hop dials the address and keeps the name in its Host header."""
    host = (headers or {}).get("Host")
    return url if not host else str(httpx.URL(url).copy_with(host=host))


class Reply:
    def __init__(self, status=200, body=b"", headers=None):
        self.status_code, self.content, self.headers = status, body, headers or {}

    def json(self):
        return json.loads(self.content)


class Space:
    """One page with two attachments; a test edits the page (a new version) or an attachment."""

    def __init__(self, *, cloud=True, version=3, body="page text", subtype=None):
        self.cloud, self.version, self.body, self.subtype = cloud, version, body, subtype
        self.attachments = {"att1": 1, "att2": 4}
        self.downloads = []

    def get(self, url, params=None, headers=None, **_kwargs):
        url = logical(url, headers)
        if self.cloud and url == SITE + "/api/v2/pages/1" or not self.cloud and url == DC + "/rest/api/content/1":
            page = {"id": "1", "version": {"number": self.version}, "body": {"storage": {"value": self.body}}}
            page.update({"spaceId": "77"} if self.cloud else {"space": {"key": "ENG"}})
            if self.subtype:
                page["subtype"] = self.subtype
            return Reply(200, json.dumps(page).encode())
        if url in (SITE + "/api/v2/pages/1/attachments", DC + "/rest/api/content/1/child/attachment"):
            link = "/download/attachments/1/{}.txt"
            # Data Center's attachment listing has an empty expand default: no version unless asked.
            versioned = self.cloud or "version" in str((params or {}).get("expand", "")).split(",")
            rows = [{"id": ident, **({"version": {"number": number}} if versioned else {}),
                     **({"downloadLink": link.format(ident)} if self.cloud
                        else {"_links": {"download": "/confluence" + link.format(ident)}})}
                    for ident, number in self.attachments.items()]
            return Reply(200, json.dumps({"results": rows, "_links": {}, "size": len(rows)}).encode())
        for ident in self.attachments:
            if self.cloud and url == SITE + f"/rest/api/content/1/child/attachment/{ident}/download":
                assert (params or {}).get("version") == self.attachments[ident]  # the version the revision names
                return Reply(302, headers={"location": f"https://media.example.test/file/{ident}?token=signed"})
            if (url == f"https://media.example.test/file/{ident}?token=signed" if self.cloud
                    else url == DC + f"/download/attachments/1/{ident}.txt"):
                self.downloads.append(ident)
                return Reply(200, f"attachment {ident} v{self.attachments[ident]}".encode())
        return Reply(404)

    def collector(self):
        payload = ({"edition": "cloud", "base_url": SITE, "space": "77"} if self.cloud
                   else {"edition": "data_center", "base_url": DC, "space": "ENG"})
        return Collector({**payload, "page_id": "1", "token": "t", "_lazy": True}, self)


@pytest.mark.parametrize("cloud", [True, False])
def test_the_body_is_named_by_page_and_version_and_attachments_by_their_own_version(cloud):
    space = Space(cloud=cloud)
    objects = {obj.resource.location: obj for obj in space.collector().collect()}
    assert {key: obj.resource.revision for key, obj in objects.items()} == {
        "body": "1:3", "attachments/att1": "att1:1", "attachments/att2": "att2:4"}
    # Lazy: nothing is read before the scan asks, and the body costs no further request.
    assert all(obj.data is None for obj in objects.values()) and space.downloads == []
    assert objects["body"].read() == b"page text" and space.downloads == []


@pytest.mark.parametrize("version", [None, "3", 0, -1, True])
def test_a_version_that_is_not_a_page_number_names_nothing(version):
    space = Space(version=version)
    body = next(obj for obj in space.collector().collect() if obj.resource.location == "body")
    assert body.resource.revision == "" and body.data == b"page text"  # read at once, never cached


def test_an_unchanged_page_is_answered_by_the_cache_and_a_new_version_is_scanned(monkeypatch):
    repo, connection = InMemoryRepository(), uuid.uuid4()
    scanned = []
    real = service_module.extract

    def extract(data, *, filename="", **kwargs):
        scanned.append(filename)
        return real(data, filename=filename, **kwargs)

    monkeypatch.setattr(service_module, "extract", extract)
    space = Space()

    def run():
        scanned.clear()
        space.downloads.clear()
        return ScanService(Orchestrator(repo)).run(space.collector(), source_connection_id=connection)

    first = run()
    assert first.objects == 3 and sorted(scanned) == ["attachments/att1", "attachments/att2", "body"]
    again = run()
    assert again.objects == 3 and again.reused == 3 and scanned == [] and space.downloads == []
    space.version, space.body = 4, "page text, edited"
    edited = run()
    assert scanned == ["body"] and edited.reused == 2 and space.downloads == []
    space.attachments["att2"] = 5
    run()
    assert scanned == ["attachments/att2"] and space.downloads == ["att2"]

def test_a_live_doc_is_scanned_every_time_because_its_version_does_not_name_its_body(monkeypatch):
    # A Confluence Cloud live doc saves edits to its body without a new version number.
    space = Space(subtype="live")
    body = next(obj for obj in space.collector().collect() if obj.resource.location == "body")
    assert body.resource.revision == "" and body.data == b"page text"
    repo, connection = InMemoryRepository(), uuid.uuid4()
    scanned = []
    real = service_module.extract

    def extract(data, *, filename="", **kwargs):
        scanned.append(filename)
        return real(data, filename=filename, **kwargs)

    monkeypatch.setattr(service_module, "extract", extract)
    for _ in range(2):
        ScanService(Orchestrator(repo)).run(space.collector(), source_connection_id=connection)
        space.body = "page text, edited in place"
    # The attachments keep their versions and are answered by the cache; the body is read both times.
    assert scanned == ["body", "attachments/att1", "attachments/att2", "body"]


ROUTE = "/rest/api/content/1/child/attachment/att1/download"


def redirects(*hops, final=200):
    """A Cloud site whose REST download redirects through ``hops`` (absolute or relative Locations)."""
    seen = []

    def handler(request):
        name = request.headers["host"]
        seen.append((str(request.url.copy_with(host=name)), request.headers.get("authorization")))
        handler.dialled.append((request.url.host, request.extensions.get("sni_hostname")))
        step = len(seen) - 1
        if step < len(hops):
            return httpx.Response(302, headers={"location": hops[step]})
        return httpx.Response(final, content=b"attachment bytes")

    handler.dialled = []
    http = SourceHTTP({"edition": "cloud", "base_url": SITE, "token": "t"}, httpx.Client(transport=httpx.MockTransport(handler)))
    http.dialled = handler.dialled
    return http, seen


def test_the_token_never_leaves_the_sites_origin_on_a_download_redirect():
    http, seen = redirects("https://media.example.test/file/1?token=signed")
    assert http.download(ROUTE, {"version": 2}) == b"attachment bytes"
    assert seen == [(SITE + ROUTE + "?version=2", "Bearer t"), ("https://media.example.test/file/1?token=signed", None)]
    # The hop off the site dials the address that was checked; the certificate is checked for the name.
    assert http.dialled == [("example.atlassian.net", None), (MEDIA_ADDRESS, "media.example.test")]
    # Once the chain has left the site, coming back to it does not bring the token back.
    http, seen = redirects("https://media.example.test/a", SITE + "/again")
    assert http.download(ROUTE) == b"attachment bytes"
    assert [auth for _url, auth in seen] == ["Bearer t", None, None]
    # A redirect within the site (a relative Location) keeps it.
    http, seen = redirects("/wiki/files/1")
    assert http.download(ROUTE) == b"attachment bytes"
    assert seen[1] == ("https://example.atlassian.net/wiki/files/1", "Bearer t")


@pytest.mark.parametrize(("location", "addresses"), [
    ("https://media.example.test/f", {"127.0.0.1"}),                      # loopback
    ("https://media.example.test/f", {"169.254.169.254"}),                # cloud instance metadata
    ("https://media.example.test/f", {"10.0.0.5"}),                       # an intranet (private DNS)
    ("https://media.example.test/f", {MEDIA_ADDRESS, "10.0.0.5"}),        # one private answer refuses the name
    ("https://media.example.test/f", {"::1"}),
    ("https://media.example.test/f", {"fd00:ec2::254"}),                  # AWS metadata over IPv6
    ("https://media.example.test/f", set()),                              # the name does not resolve
    ("https://127.0.0.1/f", None), ("https://[::1]/f", None), ("https://169.254.169.254/latest/meta-data", None),
    ("https://media.example.test:8443/f", {MEDIA_ADDRESS}),               # only the https default port
])
def test_a_download_redirect_off_the_site_reaches_only_public_addresses(monkeypatch, location, addresses):
    if addresses is not None:
        monkeypatch.setitem(NAMES, "media.example.test", addresses)
    http, seen = redirects(location)
    with pytest.raises(CollectorError, match="CONFLUENCE_DOWNLOAD_ADDRESS_REFUSED"):
        http.download(ROUTE)
    assert len(seen) == 1  # nothing is sent to the refused address


@pytest.mark.parametrize("location", ["http://media.example.test/file", "https://user:pw@media.example.test/f",
                                      "ftp://media.example.test/f", "https:///nohost", "https://media.example.test/a b"])
def test_a_download_redirect_that_is_not_plain_https_is_refused(location):
    http, seen = redirects(location)
    with pytest.raises(CollectorError, match="CONFLUENCE_DOWNLOAD_REDIRECT_INVALID"):
        http.download(ROUTE)
    assert len(seen) == 1


def test_a_location_httpx_cannot_parse_sends_nothing_more():
    # httpx itself refuses a Location whose port is not a number before the answer reaches the reader.
    http, seen = redirects("https://media.example.test:bad/f")
    with pytest.raises(CollectorError):
        http.download(ROUTE)
    assert len(seen) == 1


def test_a_download_stops_after_two_redirects_and_a_refusal_is_its_status():
    http, seen = redirects("https://media.example.test/1", "https://media.example.test/2", "https://media.example.test/3")
    with pytest.raises(CollectorError, match="CONFLUENCE_DOWNLOAD_REDIRECT_LIMIT"):
        http.download(ROUTE)
    assert len(seen) == 3  # the download and two redirects; the third Location is never requested
    http, _seen = redirects(final=401)
    with pytest.raises(CollectorError, match="SOURCE_HTTP_FAILED"):
        http.download(ROUTE)
