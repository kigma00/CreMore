"""What a page and its scripts point to (N4b): script sources and module preloads in HTML, a script's source map
(the ``SourceMap`` header or a trailing ``sourceMappingURL`` comment, an inline ``data:`` map included), and the
original sources a map carries in ``sourcesContent``. Pure functions; the collector fetches.

Every step is linear in the page: a link that cannot be read as a URL is skipped, never an error for the page.
"""

from __future__ import annotations

import base64
import binascii
import json
import posixpath
import re
import unicodedata
import urllib.parse
from html.parser import HTMLParser

MAX_SCRIPTS = 200
MAX_SOURCES = 2000
_MARK = b"sourceMappingURL="


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base: str | None = None
        self.found: list[str] = []

    def handle_starttag(self, tag, attrs):
        values = {name: value or "" for name, value in attrs}
        if tag == "base" and self.base is None and values.get("href"):
            self.base = values["href"]
        elif tag == "script" and values.get("src"):
            self.found.append(values["src"])
        elif tag == "link" and values.get("href"):
            rel = values.get("rel", "").lower().split()
            if "modulepreload" in rel or ("preload" in rel and values.get("as", "").lower() == "script"):
                self.found.append(values["href"])


def url_path(url: str, *, loose: bool = False) -> str:
    """A URL's path as a server resolves it, for comparing it with a scope: percent-decoded, backslashes and repeated
    slashes as one slash, dot segments removed (a trailing slash kept). ``/x/../admin//a%2ejs`` is ``/admin/a.js``.

    ``loose`` reads it as the most lenient servers do: decoded twice (``%2561``), compatibility characters folded
    (fullwidth letters), each segment without its ``;`` parameters (Tomcat, Jetty) or trailing dots and spaces (IIS),
    in lower case. A scope excludes by this reading and includes only what both readings include."""
    try:
        path = urllib.parse.unquote(urllib.parse.urlsplit(url).path) or "/"
    except ValueError:
        return "/"
    if loose:
        path = unicodedata.normalize("NFKC", urllib.parse.unquote(path))  # fullwidth ａ is a
    merged = re.sub(r"/{2,}", "/", path.replace("\\", "/"))
    if loose:
        segments = [segment.split(";", 1)[0] for segment in merged.split("/")]
        merged = "/".join(segment if segment in (".", "..") else segment.rstrip(". ") for segment in segments)
        merged = re.sub(r"/{2,}", "/", merged)
    normal = posixpath.normpath(merged if merged.startswith("/") else "/" + merged)
    normal = normal + "/" if merged.endswith("/") and normal != "/" else normal
    return normal.lower() if loose else normal


def _absolute(base: str, link: str) -> str | None:
    """``link`` against ``base`` as an http(s) URL without its fragment, or None."""
    try:
        absolute = urllib.parse.urldefrag(urllib.parse.urljoin(base, link.strip())).url
        return absolute if urllib.parse.urlsplit(absolute).scheme in ("http", "https") else None
    except ValueError:
        return None


def scripts(html: str, url: str) -> list[str]:
    """The scripts a page loads, as absolute URLs in page order (``<base href>`` respected), at most 200."""
    parser = _Links()
    try:
        parser.feed(html)  # no close(): an unfinished tail names no script, and close() is the slow path
    except Exception:  # noqa: BLE001, S110 -- a page the parser cannot finish still names what it read so far
        pass
    base = (_absolute(url, parser.base) or url) if parser.base else url
    out: dict[str, None] = {}
    for link in parser.found:
        absolute = _absolute(base, link)
        if absolute is not None:
            out[absolute] = None
            if len(out) == MAX_SCRIPTS:
                break
    return list(out)


def _trailing_comment(script: bytes) -> str | None:
    """The URL of a ``//# sourceMappingURL=`` (or ``/*# … */``, or the older ``@``) comment on the script's last
    line, however long that line is (an inline map fills it)."""
    text = script.rstrip()
    line = text[text.rfind(b"\n") + 1:]
    at = line.rfind(_MARK)
    if at < 0:
        return None
    lead = line[:at].rstrip(b" \t")
    if not lead.endswith((b"#", b"@")) or not lead[:-1].rstrip(b" \t").endswith((b"//", b"/*")):
        return None
    value = line[at + len(_MARK):].strip()
    if value.endswith(b"*/"):
        value = value[:-2].rstrip()
    if not value or any(ch in value for ch in b" \t'\""):
        return None
    return value.decode("utf-8", "replace")


def source_map(script: bytes, headers: dict, url: str) -> str | None:
    """Where a script's source map is: the header first, else its trailing comment; absolute, or a ``data:`` URL."""
    lowered = {str(name).lower(): value for name, value in (headers or {}).items()}
    named = lowered.get("sourcemap") or lowered.get("x-sourcemap") or _trailing_comment(script)
    if not named:
        return None
    if named.startswith("data:"):
        return named
    return _absolute(url, named)


def inline_map(data_url: str, limit: int) -> bytes | None:
    """The map a ``data:application/json[;charset=…];base64,…`` URL carries, when it fits ``limit`` bytes."""
    head, _, payload = data_url.partition(",")
    if not head.startswith("data:application/json") or len(payload) > limit * 4 // 3 + 4:
        return None
    try:
        body = base64.b64decode(payload, validate=True) if head.endswith(";base64") else urllib.parse.unquote_to_bytes(payload)
    except (binascii.Error, ValueError):
        return None
    return body if len(body) <= limit else None


def sources(map_body: bytes) -> list[tuple[str, str]]:
    """``(source name, original text)`` for every source the map carries the content of, at most 2000."""
    try:
        document = json.loads(map_body)
    except (ValueError, RecursionError):
        return []
    if not isinstance(document, dict):
        return []
    names, texts = document.get("sources"), document.get("sourcesContent")
    if not isinstance(names, list) or not isinstance(texts, list):
        return []
    out = []
    for index, text in enumerate(texts[:MAX_SOURCES]):
        if isinstance(text, str) and text:
            name = names[index] if index < len(names) and isinstance(names[index], str) else f"source-{index}"
            out.append((name[:500], text))
    return out
