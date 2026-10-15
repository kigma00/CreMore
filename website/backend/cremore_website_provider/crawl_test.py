"""What a page and its scripts point to (N4b). Synthetic pages only."""

from __future__ import annotations

import base64
import json

from cremore_website_provider.crawl import inline_map, scripts, source_map, sources

PAGE = """<!doctype html><html><head>
<base href="/app/">
<script src="main.js"></script><script src="https://cdn.example/lib.js" async></script>
<link rel="modulepreload" href="/chunks/a.js"><link rel="preload" as="script" href="b.js">
<link rel="stylesheet" href="site.css"><script>var inline = 1;</script>
<script src="main.js#again"></script><script src="javascript:alert(1)"></script>
</head><body><a href="/other">x</a></body></html>"""


def test_a_page_names_its_scripts_and_preloads_in_order():
    assert scripts(PAGE, "https://acme.test/index.html") == [
        "https://acme.test/app/main.js", "https://cdn.example/lib.js", "https://acme.test/chunks/a.js",
        "https://acme.test/app/b.js"]  # no stylesheet, no link, no javascript: URL, no repeat
    assert scripts("<script src=", "https://acme.test/") == []  # an unfinished page names what it read


def test_a_script_names_its_map_by_header_or_trailing_comment():
    body = b"console.log(1);\n//# sourceMappingURL=main.js.map\n"
    assert source_map(body, {}, "https://acme.test/app/main.js") == "https://acme.test/app/main.js.map"
    assert source_map(b"x", {"SourceMap": "/maps/x.map"}, "https://acme.test/a.js") == "https://acme.test/maps/x.map"
    assert source_map(b"a();\n/*# sourceMappingURL=a.css.map */", {}, "https://acme.test/a.js") == "https://acme.test/a.css.map"
    assert source_map(b"var s = '//# sourceMappingURL=not-last';\nrun();", {}, "https://acme.test/a.js") is None
    assert source_map(b"x\n//# sourceMappingURL=javascript:alert(1)", {}, "https://acme.test/a.js") is None


def test_an_inline_map_and_the_sources_it_carries():
    document = {"version": 3, "sources": ["src/config.ts", "src/empty.ts", "src/app.ts"],
                "sourcesContent": ["export const KEY = 'value';\n", None, "run();\n"]}
    encoded = base64.b64encode(json.dumps(document).encode()).decode()
    url = source_map(f"x\n//# sourceMappingURL=data:application/json;charset=utf-8;base64,{encoded}".encode(), {},
                     "https://acme.test/a.js")
    body = inline_map(url, 1 << 20)
    assert sources(body) == [("src/config.ts", "export const KEY = 'value';\n"), ("src/app.ts", "run();\n")]
    assert inline_map(url, 10) is None and inline_map("data:text/html,<b>", 1024) is None
    assert sources(b"not json") == [] and sources(b"[]") == [] and sources(b'{"sources": 1}') == []
    # A real inline map fills a last line far longer than any fixed tail.
    big = base64.b64encode(json.dumps({**document, "mappings": "A" * 200_000}).encode()).decode()
    long_line = f"x\n//# sourceMappingURL=data:application/json;base64,{big}".encode()
    assert sources(inline_map(source_map(long_line, {}, "https://acme.test/a.js"), 1 << 20))[0][0] == "src/config.ts"


def test_a_url_path_is_read_as_a_server_resolves_it():
    from cremore_website_provider.crawl import url_path

    for url, path in (("https://acme.test/x/../admin/secret.js", "/admin/secret.js"), ("https://acme.test//admin/b.js", "/admin/b.js"),
                      ("https://acme.test/%61dmin/c.js", "/admin/c.js"), ("https://acme.test/a\\..\\admin\\d.js", "/admin/d.js"),
                      ("https://acme.test/docs%2F..%2Fadmin/e", "/admin/e"), ("https://acme.test/admin/", "/admin/"),
                      ("https://acme.test", "/"), ("https://acme.test/../..", "/"), ("http://[::1/x", "/")):
        assert url_path(url) == path, url
    # Exclusions read as the most lenient server does.
    for url, path in (("https://acme.test/ADMIN;x=1/./a..", "/admin/a"), ("https://acme.test/x/..;/admin/b", "/admin/b"),
                      ("https://acme.test/%2561dmin%20/c", "/admin/c"), ("https://acme.test/admin/", "/admin/")):
        assert url_path(url, loose=True) == path, url


def test_links_that_are_not_urls_are_skipped_and_pages_are_read_in_linear_time():
    import time

    broken = ('<base href="http://[x"><script src="http://[::1/x.js"></script><script src="/a\x01.js"></script>'
              '<script src="/ok.js"></script>')
    assert scripts(broken, "https://acme.test/") == ["https://acme.test/a\x01.js", "https://acme.test/ok.js"]
    assert source_map(b"x\n//# sourceMappingURL=http://[::1/m.map", {}, "https://acme.test/a.js") is None
    started = time.monotonic()
    many = "".join(f"<script src=/s{n}></script>" for n in range(100_000))
    assert len(scripts(many, "https://acme.test/")) == 200 and time.monotonic() - started < 5
    started = time.monotonic()
    assert scripts("<script src=/a></script>" * 100_000, "https://acme.test/") == ["https://acme.test/a"]
    assert time.monotonic() - started < 5
