"""Structural validators for detector matches (false-positive reduction).

A detector may attach a ``validate`` predicate that the engine runs on the raw
matched secret bytes before a candidate is accepted. These catch values that fit
a regex but cannot be the real credential — a 40-char base64 run that is actually
low-entropy filler, a card number that fails the Luhn checksum — so a match has
to be structurally plausible, not merely the right length.

All validators are pure (authored from the public definition of
the check, e.g. Shannon entropy, the Luhn algorithm, the base32 alphabet).
"""

from __future__ import annotations

import math
from collections.abc import Callable

Validator = Callable[[bytes], bool]


def shannon_entropy(data: str | bytes) -> float:
    """Shannon entropy in bits per character or byte, without transcoding."""
    if not data:
        return 0.0
    counts: dict[str | int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def min_entropy(threshold: float) -> Validator:
    """Require the matched bytes to carry at least ``threshold`` bits/symbol.

    Filler like ``AAAA...`` or ``0000...`` has near-zero entropy and is rejected,
    while a real random secret comfortably clears a modest threshold.
    """

    def _check(data: bytes) -> bool:
        return shannon_entropy(data) >= threshold

    return _check


def luhn_valid(data: bytes) -> bool:
    """The Luhn checksum used by payment card numbers (and some account ids)."""

    digits = [c - 48 for c in data if 48 <= c <= 57]
    if len(digits) < 12:
        return False
    total = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def basic_auth_b64(data: bytes) -> bool:
    """A base64 blob is an HTTP Basic credential only if it decodes to ``user:pass``."""

    import base64
    import binascii

    try:
        decoded = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        return False
    return b":" in decoded[:-1] and len(decoded) >= 3


def all_of(*validators: Validator) -> Validator:
    def _check(data: bytes) -> bool:
        return all(v(data) for v in validators)

    return _check
