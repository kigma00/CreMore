"""Content decoders (from public encoding specifications).

A credential is often committed inside an encoded envelope — a base64 blob, a
UTF-16 file, a JSON ``\\uXXXX`` string, or HTML-entity-escaped text. Each decoder
produces zero or more *decoded views* of the input; the engine scans the
original bytes and every decoded view, tagging any finding with the decoder that
revealed it.

Every implementation here is written from the encoding's public specification
(RFC 4648 base64, the Unicode UTF-16 encoding form, JSON string escapes, the
HTML5 named/numeric character references) using the Python standard library.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
from dataclasses import dataclass

# Minimum length of a base64 run worth decoding. Short runs are almost always
# ordinary words and decoding them wastes work and invites false positives.
_MIN_B64_RUN = 24
_MAX_B64_RUN = 8192

# Standard and URL-safe base64 alphabets (RFC 4648 §4 and §5).
_B64_RUN = re.compile(rb"[A-Za-z0-9+/]{%d,%d}={0,2}" % (_MIN_B64_RUN, _MAX_B64_RUN))
_B64URL_RUN = re.compile(rb"[A-Za-z0-9_-]{%d,%d}={0,2}" % (_MIN_B64_RUN, _MAX_B64_RUN))

# A JSON/Java/Python style ``\uXXXX`` (and ``\xXX``) escape.
_UNICODE_ESCAPE = re.compile(rb"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}")

# HTML numeric or named character reference.
_HTML_ENTITY = re.compile(rb"&(#\d+|#[xX][0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]+);")


@dataclass(frozen=True)
class DecodedView:
    """A decoded transformation of the input and the decoder that produced it."""

    data: bytes
    decoder: str


def _mostly_text(data: bytes) -> bool:
    """True when the bytes look like a credential-bearing text payload.

    A decode that yields mostly control bytes is almost always a false base64
    run (ordinary prose happens to be in the alphabet), so it is discarded.
    """

    if not data:
        return False
    printable = sum(1 for b in data if b == 9 or b == 10 or b == 13 or 32 <= b <= 126)
    return printable / len(data) >= 0.85


def decode_base64(data: bytes) -> list[DecodedView]:
    """Decode embedded standard and URL-safe base64 runs.

    Each sufficiently long base64 run is decoded independently; the decoded
    bytes are concatenated (newline-separated) into a single view so a
    credential split by the encoder is still found in one pass.
    """

    views: list[DecodedView] = []
    for alphabet, run, urlsafe in (
        ("std", _B64_RUN, False),
        ("url", _B64URL_RUN, True),
    ):
        pieces: list[bytes] = []
        for m in run.finditer(data):
            chunk = m.group(0)
            # A run whose length is not a multiple of 4 (ignoring padding) is
            # not valid base64; pad it so the decoder accepts the leading bytes.
            body = chunk.rstrip(b"=")
            pad = (-len(body)) % 4
            candidate = body + (b"=" * pad)
            try:
                if urlsafe:
                    decoded = base64.urlsafe_b64decode(candidate)
                else:
                    decoded = base64.b64decode(candidate, validate=True)
            except (binascii.Error, ValueError):
                continue
            if _mostly_text(decoded):
                pieces.append(decoded)
        if pieces:
            views.append(DecodedView(b"\n".join(pieces), f"base64:{alphabet}"))
    return views


def decode_utf16(data: bytes) -> list[DecodedView]:
    """Decode UTF-16 content to UTF-8 so ASCII credentials become findable.

    Only content that actually looks like UTF-16 is decoded: a byte-order mark,
    or a high density of interleaved NUL bytes characteristic of ASCII text in
    UTF-16.
    """

    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        try:
            return [DecodedView(data.decode("utf-16").encode("utf-8"), "utf16")]
        except UnicodeError:
            return []
    # No BOM: detect the interleaved-NUL signature of ASCII text stored UTF-16.
    sample = data[:2048]
    if len(sample) < 8:
        return []
    nul = sample.count(0)
    if nul / len(sample) < 0.30:
        return []
    for enc in ("utf-16-le", "utf-16-be"):
        try:
            decoded = data.decode(enc)
        except UnicodeError:
            continue
        encoded = decoded.encode("utf-8", "ignore")
        if _mostly_text(encoded):
            return [DecodedView(encoded, "utf16")]
    return []


def decode_unicode_escape(data: bytes) -> list[DecodedView]:
    """Resolve ``\\uXXXX`` / ``\\xXX`` escapes (JSON, Java, Python string form)."""

    if not _UNICODE_ESCAPE.search(data):
        return []

    def repl(m: re.Match[bytes]) -> bytes:
        token = m.group(0)
        try:
            code = int(token[2:], 16)  # noqa: FURB166 -- Strip the literal \u/\x escape marker; this is not a numeric 0x prefix.
            return chr(code).encode("utf-8", "ignore")
        except ValueError:
            return token

    decoded = _UNICODE_ESCAPE.sub(repl, data)
    if decoded == data:
        return []
    return [DecodedView(decoded, "unicode-escape")]


def decode_html_entities(data: bytes) -> list[DecodedView]:
    """Resolve HTML numeric and named character references (HTML5 spec)."""

    if not _HTML_ENTITY.search(data):
        return []
    try:
        decoded = html.unescape(data.decode("utf-8", "ignore")).encode("utf-8", "ignore")
    except UnicodeError:
        return []
    if decoded == data:
        return []
    return [DecodedView(decoded, "html-entity")]


#: Decoders applied to every scanned chunk, in order.
DECODERS = (
    decode_base64,
    decode_utf16,
    decode_unicode_escape,
    decode_html_entities,
)


def decoded_views(data: bytes, max_depth: int = 2) -> list[DecodedView]:
    """Produce all decoded views of ``data`` up to ``max_depth`` nestings.

    Bounded depth stops a crafted input (base64 of base64 of …) from causing
    unbounded work while still catching the common single and double wrap.
    """

    views: list[DecodedView] = []
    seen: set[bytes] = {data}
    frontier: list[tuple[bytes, int]] = [(data, 0)]
    while frontier:
        current, depth = frontier.pop()
        if depth >= max_depth:
            continue
        for decoder in DECODERS:
            for view in decoder(current):
                if not view.data or view.data in seen:
                    continue
                seen.add(view.data)
                views.append(view)
                frontier.append((view.data, depth + 1))
    return views
