"""Credential fingerprinting and masking.

A finding must be de-duplicable and referenceable without storing the secret.
The fingerprint is a one-way SHA-256 over the credential material (optionally
keyed for per-tenant isolation), and the hint is a masked form that keeps only
enough of the value for a human to recognise it.
"""

from __future__ import annotations

import hashlib
import hmac

_FINGERPRINT_DOMAIN = b"cremore-credential-fingerprint-v1\x00"


def fingerprint(material: bytes, *, key: bytes | None = None) -> str:
    """Return a stable, non-reversible fingerprint of credential ``material``.

    When ``key`` is given the fingerprint is an HMAC, which keeps identical
    secrets from correlating across tenants that use different keys.
    """

    if key:
        return hmac.new(key, _FINGERPRINT_DOMAIN + material, hashlib.sha256).hexdigest()
    digest = hashlib.sha256()
    digest.update(_FINGERPRINT_DOMAIN)
    digest.update(material)
    return digest.hexdigest()


MASK_WIDTH = 4


def mask_hint(value: str, *, prefix: int = 4, suffix: int = 4, dot: str = "•") -> str:
    """Mask the middle of a credential, keeping a short prefix and suffix.

    The mask is always :data:`MASK_WIDTH` characters wide, so every hint reads
    alike and the stored hint never discloses the secret's real length (a
    variable-width mask leaks it). ``AKIAIOSFODNN7EXAMPLE`` becomes
    ``AKIA••••MPLE``.

    How much is revealed scales with the value, because a fixed 4+4 would expose
    most of a short secret: under 12 characters (passwords, PINs, short tokens)
    nothing is revealed, and under 20 only two characters each side.
    """

    mask = dot * MASK_WIDTH
    length = len(value)
    if length < 12:
        return mask
    head, tail = (2, 2) if length < 20 else (max(0, min(prefix, 4)), max(0, min(suffix, 4)))
    return value[:head] + mask + (value[length - tail:] if tail else "")


def redact_line(line: bytes, spans: list[tuple[int, int]], dot: str = "•") -> str:
    """Return ``line`` decoded to text with each secret span replaced by dots.

    Offsets are byte offsets into ``line``; overlapping or out-of-range spans are
    clamped so a bad offset can never leak surrounding bytes.
    """

    if not spans:
        return line.decode("utf-8", "replace")
    ordered = sorted((max(0, s), min(len(line), e)) for s, e in spans if e > s)
    out = bytearray()
    cursor = 0
    for start, end in ordered:
        start = max(start, cursor)
        if start >= end:
            continue
        out += line[cursor:start]
        out += (dot * (end - start)).encode("utf-8")
        cursor = end
    out += line[cursor:]
    return out.decode("utf-8", "replace")
