"""The web exposure scan of one domain: start pages, their scripts, the sources their maps carry (N4b). A synthetic
fetcher only."""

from __future__ import annotations

import json

import httpx
import pytest

from cremore.collectors.base import CollectorError
from cremore_website_provider.addresses import INTERNAL, PUBLIC
from cremore_website_provider.collector import WebsiteCollector
from cremore_website_provider.fetch import FetchRefused, Page

MAP = json.dumps({"version": 3, "sources": ["webpack://app/src/config.ts"],
                  "sourcesContent": ["export const token = 'synthetic-value';\n"]}).encode()


class Fetcher:
    max_bytes = 1 << 20

    def __init__(self, pages):
        self.pages, self.asked, self.closed = pages, [], False

    def get(self, url, allowed_url=None):
        if allowed_url is not None and not allowed_url(url):
            raise FetchRefused("PATH_NOT_ALLOWED")
        self.asked.append(url)
        found = self.pages.get(url)
        if isinstance(found, tuple) and found[0] == "redirect":  # ("redirect", target): the next hop, bounded too
            return self.get(found[1], allowed_url)
        if isinstance(found, str):
            raise FetchRefused(found)
        if found is None:
            return Page(url=url, status=404, content_type="text/html", body=b"", reach=PUBLIC, headers={})
        content_type, body, headers = found
        return Page(url=url, status=200, content_type=content_type, body=body, reach=PUBLIC, headers=headers)

    def close(self):
        self.closed = True


@pytest.mark.parametrize("mime,body", [
    ("application/pdf", b"%PDF-1.7 synthetic"),
    ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", b"PK\x03\x04synthetic"),
    ("application/x-hwp", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1synthetic"),
    ("application/octet-stream", b"\x00\x01unknown"),
])
def test_approved_binary_url_reaches_common_extractor(mime, body):
    url = "https://acme.test/approved/document"
    fetcher = Fetcher({url: (mime, body, {})})
    collector = WebsiteCollector(fetcher, domain="acme.test", start_urls=[url], paths=["/approved"])
    objects = list(collector.collect())
    assert len(objects) == 1 and objects[0].read() == body
    assert objects[0].resource.metadata["content_type"] == mime
    assert fetcher.asked == [url] and fetcher.closed
    assert collector.authoritative_listing is False


def test_pages_scripts_and_map_sources_are_scanned_and_someone_elses_is_left_alone():
    fetcher = Fetcher({
        "https://acme.test/": ("text/html", (b'<script src="/app.js"></script><script src="https://cdn.example/x.js">'
                                             b'</script><script src="/gone.js"></script><img src="/logo.png">'), {}),
        "https://acme.test/app.js": ("application/javascript", b"run();\n//# sourceMappingURL=app.js.map\n", {}),
        "https://acme.test/app.js.map": ("application/json", MAP, {}),
        "https://cdn.example/x.js": "HOST_NOT_VERIFIED",
    })
    collector = WebsiteCollector(fetcher, domain="acme.test", start_urls=["https://acme.test/"])
    objects = list(collector.collect())
    assert [item.resource.location for item in objects] == [
        "https://acme.test/", "https://acme.test/app.js",
        "https://acme.test/app.js.map!/webpack://app/src/config.ts"]
    source = objects[-1]
    assert source.read() == b"export const token = 'synthetic-value';\n"
    assert (source.resource.source_type, source.resource.resource, source.resource.metadata["exposure"]) == (
        "website", "acme.test", PUBLIC)
    # The CDN's script is not the company's; the missing script of the company's makes the run partial.
    assert (collector.skipped, collector.failed_objects) == (1, 1) and collector.authoritative_listing is False
    assert fetcher.closed


def test_a_start_url_may_be_a_script_or_a_map_and_the_scope_bounds_every_url():
    fetcher = Fetcher({
        "https://acme.test/app.js": ("application/javascript", b"x();\n//# sourceMappingURL=app.js.map", {}),
        "https://acme.test/app.js.map": ("application/json", MAP, {}),
        "https://acme.test/other.js.map": ("application/octet-stream", MAP, {}),
        "https://acme.test/admin/": ("text/html", b'<script src="/admin/a.js"></script>', {}),
    })
    # An exact rescan names a script and a map it once read; each is read as what it is.
    objects = list(WebsiteCollector(fetcher, domain="acme.test",
                                    start_urls=["https://acme.test/app.js", "https://acme.test/other.js.map"]).collect())
    assert [item.resource.location for item in objects] == [
        "https://acme.test/app.js", "https://acme.test/app.js.map!/webpack://app/src/config.ts",
        "https://acme.test/other.js.map!/webpack://app/src/config.ts"]
    # Paths the approved scope excludes are never asked for, and a start page left out does not fail the run.
    narrowed = Fetcher(fetcher.pages)
    collector = WebsiteCollector(narrowed, domain="acme.test", start_urls=["https://acme.test/admin/"],
                                 excluded_paths=["/admin/"])
    assert list(collector.collect()) == [] and narrowed.asked == [] and collector.skipped == 1


def test_a_start_url_refused_counts_as_a_failure_even_on_its_own_domain():
    # A start URL is the company's by its configuration: a domain no longer verified fails it, never skips it.
    collector = WebsiteCollector(Fetcher({"https://acme.test/": "HOST_NOT_VERIFIED"}), domain="acme.test",
                                 start_urls=["https://acme.test/"])
    with pytest.raises(CollectorError):
        list(collector.collect())
    assert collector.failed_objects == 1


def test_no_start_page_read_fails_the_run_and_internal_reach_is_kept():
    unreachable = WebsiteCollector(Fetcher({"https://acme.test/": "ADDRESS_NOT_ALLOWED"}), domain="acme.test",
                                   start_urls=["https://acme.test/"])
    with pytest.raises(CollectorError) as failed:
        list(unreachable.collect())
    assert failed.value.code == "WEBSITE_UNREACHABLE"

    class Inside(Fetcher):
        def get(self, url, allowed_url=None):
            page = super().get(url, allowed_url)
            return Page(url=page.url, status=page.status, content_type=page.content_type, body=page.body,
                        reach=INTERNAL, headers=page.headers)

    objects = list(WebsiteCollector(Inside({"http://intranet.acme.test/": ("text/html", b"<p>hi</p>", {})}),
                                    domain="acme.test", start_urls=["http://intranet.acme.test/"]).collect())
    assert objects[0].resource.metadata["exposure"] == INTERNAL


def test_scope_paths_are_slash_delimited_url_paths_bounding_every_hop():
    fetcher = Fetcher({
        "https://acme.test/": ("text/html", b'<script src="/docs-private/a.js"></script><script src="/docs/b.js"></script>', {}),
        "https://acme.test/docs/b.js": ("text/javascript", b"b()", {}),
        "https://acme.test/docs-private/a.js": ("text/javascript", b"a()", {}),
        "https://acme.test/old": ("redirect", "https://acme.test/admin/secret"),
        "https://acme.test/admin/secret": ("text/html", b"secret", {}),
    })
    # /docs covers /docs/b.js, not /docs-private/a.js; a start page that redirects into an excluded path is left out
    # without failing the run.
    collector = WebsiteCollector(fetcher, domain="acme.test", start_urls=["https://acme.test/", "https://acme.test/old"],
                                 paths=["/", "/docs"], excluded_paths=["/docs-private", "/admin"])
    objects = list(collector.collect())
    assert [item.resource.location for item in objects] == ["https://acme.test/", "https://acme.test/docs/b.js"]
    assert "https://acme.test/admin/secret" not in fetcher.asked and collector.failed_objects == 0
    # The path a server resolves is what the scope sees: dot segments, repeated slashes, escapes and case.
    tricky = Fetcher({"https://acme.test/": ("text/html", b"".join(
        f'<script src="{src}"></script>'.encode() for src in (
            "https://acme.test/x/../admin/a.js", "//acme.test//admin/b.js", "/%61dmin/c.js", "/ADMIN/d.js")), {})})
    left = WebsiteCollector(tricky, domain="acme.test", start_urls=["https://acme.test/"], excluded_paths=["/admin/"])
    assert [item.resource.location for item in left.collect()] == ["https://acme.test/"]
    assert tricky.asked == ["https://acme.test/"] and left.skipped == 4
    # Entries are read like the URLs: an encoded Hangul path, path parameters, trailing dots and double encoding.
    lenient = Fetcher({"https://acme.test/": ("text/html", b"".join(
        f'<script src="{src}"></script>'.encode() for src in (
            "/%EA%B4%80%EB%A6%AC%EC%9E%90/app.js", "/admin;jsessionid=1/a.js", "/x/..;/admin/b.js", "/admin./c.js",
            "/%2561dmin/d.js", "/public/e.js")), {}), "https://acme.test/public/e.js": ("text/javascript", b"e()", {})})
    kept = WebsiteCollector(lenient, domain="acme.test", start_urls=["https://acme.test/"],
                            excluded_paths=["/%EA%B4%80%EB%A6%AC%EC%9E%90/", "/admin/"])
    assert [item.resource.location for item in kept.collect()] == ["https://acme.test/", "https://acme.test/public/e.js"]
    assert kept.skipped == 5
    # An approved path includes a URL only when the lenient reading agrees too (Tomcat reads /docs/..;/admin as /admin).
    docs = Fetcher({"https://acme.test/docs/": ("text/html", b"".join(f'<script src="{src}"></script>'.encode() for src in (
        "/docs/..;/admin/a.js", "/docs/%252e%252e/admin/b.js", "/docs/c.js")), {}), "https://acme.test/docs/c.js": ("text/javascript", b"c()", {})})
    narrow = WebsiteCollector(docs, domain="acme.test", start_urls=["https://acme.test/docs/"], paths=["/docs/"])
    assert [item.resource.location for item in narrow.collect()] == ["https://acme.test/docs/", "https://acme.test/docs/c.js"]
    # An exclusion also holds for compatibility characters (fullwidth ａ).
    assert not WebsiteCollector(docs, domain="acme.test", start_urls=[], excluded_paths=["/admin/"])._in_scope(
        "https://acme.test/%EF%BD%81dmin/x.js")
    # An entry that is not a URL path would exclude nothing: the run refuses it.
    for entries in (["admin/"], ["/docs?x=1"], ["/docs#top"]):
        with pytest.raises(CollectorError) as invalid:
            WebsiteCollector(fetcher, domain="acme.test", start_urls=["https://acme.test/"], excluded_paths=entries)
        assert invalid.value.code == "WEBSITE_SCOPE_PATH_INVALID"


def test_a_location_keeps_no_query_and_a_sites_content_type_is_kept_only_when_plain():
    fetcher = Fetcher({
        "https://acme.test/?session=abc": ("text/html", b'<script src="/cfg.js?token=synthetic#x"></script>', {}),
        "https://acme.test/cfg.js?token=synthetic": ("text/javascript;" + "x" * 300, b"cfg()", {}),
    })
    objects = list(WebsiteCollector(fetcher, domain="acme.test", start_urls=["https://acme.test/?session=abc"]).collect())
    assert [item.resource.location for item in objects] == ["https://acme.test/", "https://acme.test/cfg.js"]
    assert "content_type" not in objects[1].resource.metadata  # a site-chosen value that is not a media type


def test_every_request_asks_the_budget_the_run_holds_now():
    from cremore_website_provider import source

    asked = []

    class Budget:
        def __init__(self, name):
            self.name = name

        def consume(self):
            asked.append(self.name)

    payload = {"domain": "acme.test", "start_urls": ["https://acme.test/"], "max_assets": 5,
               "domain_cover": lambda host: {"name": "acme.test", "host": host, "allow_internal": False}}
    collector = source._collector(payload, ["https://acme.test/"], request_budget=Budget("plain"))
    collector.request_budget = Budget("durable")  # what a scoped run does (cremore/worker/runtime.py)
    collector.fetcher.resolve = lambda host, port: {"8.8.8.10"}
    collector.fetcher.client_factory = lambda proxy: httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(404)))
    with pytest.raises(CollectorError):
        list(collector.collect())  # the only start page answers 404
    assert asked == ["durable"]


def test_a_run_past_its_own_time_reads_nothing_more_and_is_partial():
    slow = WebsiteCollector(Fetcher({"https://acme.test/": ("text/html", b"<p>x</p>", {})}), domain="acme.test",
                            start_urls=["https://acme.test/"], max_seconds=0)
    with pytest.raises(CollectorError):
        list(slow.collect())
    assert slow.failed_objects == 1


def test_budgets_bound_what_is_read():
    page = ("text/html", "".join(f'<script src="/s{n}.js"></script>' for n in range(5)).encode(), {})
    fetcher = Fetcher({"https://acme.test/": page, **{f"https://acme.test/s{n}.js": ("text/javascript", b"x", {})
                                                     for n in range(5)}})
    collector = WebsiteCollector(fetcher, domain="acme.test", start_urls=["https://acme.test/"], max_assets=2)
    assert len(list(collector.collect())) == 3 and collector.failed_objects == 3  # the scripts left unread count
