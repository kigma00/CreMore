"""The web exposure scan of one verified domain (N4b): its start pages, the scripts they load and the original
sources those scripts' maps carry, each scanned as its own object.

Only what the fetcher reaches is read (cremore_website_provider.fetch): a script on a host no verified domain covers
(a public CDN) is not the company's and is left alone, not counted as a failure. A page or asset of the company's that
could not be read is counted in ``failed_objects`` so the run is partial; no start URL read at all fails the run.
A start URL may be a page, a script or a source map (an exact rescan names the location a finding was in). An approved
scope's ``paths`` and ``excluded_paths`` are URL paths (``/admin/``) and bound every URL, each redirect's included, as
slash-delimited prefixes of the path a server resolves, entries read the same way (crawl.url_path; exclusions as the
most lenient server reads them); an entry that is not a URL path stops the scan's plan (source.scope_problem) and
fails a run that still gets one, rather than match nothing. Budgets: assets, bytes per object (the fetcher's) and bytes in all,
the run's own time (``max_seconds``) and its request budget (``request_budget``, which a scoped run replaces with its
durable one).

A location is kept without its query or fragment: a link's query can carry a token, and a location reaches the
finding, the API and the SIEM.
"""

from __future__ import annotations

import re
import time
import urllib.parse
from collections.abc import Iterator

from cremore.collectors.base import CollectedObject, CollectorError, path_under
from cremore.detection import ResourceRef
from cremore_website_provider import crawl
from cremore_website_provider.fetch import FetchRefused

SOURCE_TYPE = "website"
_HTML = ("text/html", "application/xhtml+xml")
_SCRIPT = ("application/javascript", "application/x-javascript", "application/ecmascript", "text/javascript",
           "text/ecmascript")
# Someone else's host, a port nobody named, or a path the approved scope leaves out: not a failure.
_NOT_OURS = ("HOST_NOT_VERIFIED", "PORT_NOT_ALLOWED")
_MEDIA_TYPE = re.compile(r"[a-z0-9.+-]{1,60}/[a-z0-9.+-]{1,60}")


def _path(url: str) -> str:
    try:
        return urllib.parse.urlsplit(url).path or "/"
    except ValueError:
        return "/"


def _kept(url: str) -> str:
    """The location a finding keeps: the URL without its query or fragment."""
    try:
        return urllib.parse.urlunsplit(urllib.parse.urlsplit(url)._replace(query="", fragment=""))
    except ValueError:
        return url.split("?", 1)[0].split("#", 1)[0]


def _url_paths(paths, *, loose: bool = False) -> list[str]:
    """Scope entries read as the URLs they are compared with (crawl.url_path): ``/%EA%B4%80%EB%A6%AC%EC%9E%90/`` and
    ``/관리자/`` are one entry. An entry that is not a URL path is refused, never guessed at: ``admin/`` would exclude
    nothing."""
    if any(not isinstance(path, str) or (path and not path.startswith("/")) or "?" in path or "#" in path
           for path in paths):  # "" is the whole site; a query or fragment is no part of a path
        raise CollectorError("WEBSITE_SCOPE_PATH_INVALID", "a website scope path is a URL path starting with /")
    return [crawl.url_path("http://x" + path, loose=loose) for path in paths if path or not loose]


def scope(paths=(), excluded_paths=()):
    """An approved scope's test for a URL, the one the run and the platform's rescan check share
    (source.scope_allows). An entry that is not a URL path raises ``WEBSITE_SCOPE_PATH_INVALID``."""
    included, excluded = _url_paths(paths), _url_paths(excluded_paths, loose=True)
    included_loose = [crawl.url_path("http://x" + path, loose=True) for path in paths]  # "" is still the site

    def allows(url: str) -> bool:
        # The path as a server resolves it (/x/../admin, //admin and /%61dmin are all /admin); an exclusion holds
        # as the most lenient server reads it (/ADMIN, /admin;x=1, /admin., /%2561dmin).
        loose = crawl.url_path(url, loose=True)
        if path_under(loose, excluded):
            return False
        # Included only when the strict and the lenient reading both put it under an approved path.
        return not included or (path_under(crawl.url_path(url), included) and path_under(loose, included_loose))

    return allows


class WebsiteCollector:
    authoritative_listing = False  # a site read from its pages never proves a file is gone

    def __init__(self, fetcher, *, domain: str, start_urls: list[str], max_assets: int = 200,
                 max_total_bytes: int = 50 << 20, max_seconds: float = 1800, paths=(), excluded_paths=()) -> None:
        self.fetcher, self.domain, self.start_urls = fetcher, domain, list(dict.fromkeys(start_urls))
        self.max_assets, self.max_total_bytes = max_assets, max_total_bytes
        self.max_seconds = max_seconds  # the whole run: a slow site never holds the installation's scan slot for long
        self._started = time.monotonic()
        self._in_scope = scope(paths, excluded_paths)
        self.request_budget = None  # the run's; asked before every request (source.py binds it to the fetcher)
        self.failed_objects = 0
        self.skipped = 0  # someone else's scripts, and URLs the approved scope leaves out
        self._bytes = 0

    def _object(self, location: str, body: bytes, reach: str, **metadata) -> CollectedObject:
        self._bytes += len(body)
        kind = metadata.pop("content_type", "")
        kept = {key: value for key, value in (("content_type", kind if _MEDIA_TYPE.fullmatch(kind or "") else ""),
                                               *metadata.items()) if value}
        return CollectedObject(resource=ResourceRef(source_type=SOURCE_TYPE, resource=self.domain, location=location,
                                                    size=len(body), metadata={"exposure": reach, **kept}),
                               data=body)

    def _get(self, url: str, *, start: bool = False):
        """The page, or None: out of the approved scope or someone else's script (``skipped``), or unreadable
        (``failed_objects``). A start URL is the company's own by its configuration: a refusal there (a domain no
        longer verified) fails it, unless the approved scope leaves it out."""
        if not self._in_scope(url):
            self.skipped += 1
            return None
        if self._bytes >= self.max_total_bytes or time.monotonic() - self._started >= self.max_seconds:
            self.failed_objects += 1  # left unread by a budget: the run is partial
            return None
        try:
            page = self.fetcher.get(url, self._in_scope)
        except FetchRefused as refused:
            if refused.code == "PATH_NOT_ALLOWED" or (refused.code in _NOT_OURS and not start):
                self.skipped += 1
            else:
                self.failed_objects += 1
            return None
        if page.status != 200:
            self.failed_objects += 1
            return None
        return page

    def collect(self) -> Iterator[CollectedObject]:
        read, tried, assets = 0, 0, {}
        self._started = time.monotonic()
        try:
            for url in self.start_urls:
                skipped = self.skipped
                page = self._get(url, start=True)
                tried += self.skipped == skipped  # a start URL the scope leaves out was never the run's to read
                if page is None:
                    continue
                read += 1
                path = _path(page.url)
                if page.content_type in _HTML or (not page.content_type and not path.endswith((".js", ".mjs", ".map"))):
                    yield self._object(_kept(page.url), page.body, page.reach, content_type=page.content_type)
                    for link in crawl.scripts(page.body.decode("utf-8", "replace"), page.url):
                        assets.setdefault(link, None)
                elif page.content_type in _SCRIPT or path.endswith((".js", ".mjs")):
                    yield from self._script(page)
                elif path.endswith(".map"):
                    yield from self._sources(page.body, page.reach, _kept(page.url))
                else:
                    # Every explicitly approved start URL reaches the common
                    # bounded extractor, including PDF/Office/HWP and unknown
                    # binary types. An unsupported document stays partial.
                    yield self._object(_kept(page.url), page.body, page.reach, content_type=page.content_type)
            if tried and not read:
                raise CollectorError("WEBSITE_UNREACHABLE", "no start URL could be read")
            links = list(assets)
            for url in links[:self.max_assets]:
                script = self._get(url)
                if script is not None:
                    yield from self._script(script)
            self.failed_objects += max(0, len(links) - self.max_assets)
        finally:
            close = getattr(self.fetcher, "close", None)
            if callable(close):
                close()

    def _script(self, script) -> Iterator[CollectedObject]:
        yield self._object(_kept(script.url), script.body, script.reach, content_type=script.content_type)
        where = crawl.source_map(script.body, script.headers, script.url)
        if where is None:
            return
        if where.startswith("data:"):
            body = crawl.inline_map(where, self.fetcher.max_bytes)
            if body is None:
                self.failed_objects += 1
                return
            yield from self._sources(body, script.reach, _kept(script.url) + "#map")
            return
        found = self._get(where)
        if found is not None:
            yield from self._sources(found.body, found.reach, _kept(found.url))

    def _sources(self, body: bytes, reach: str, location: str) -> Iterator[CollectedObject]:
        for name, text in crawl.sources(body):
            yield self._object(f"{location}!/{name}", text.encode("utf-8"), reach, content_type="text/plain",
                               source_map=location)
