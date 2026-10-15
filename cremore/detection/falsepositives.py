"""False-positive suppression.

This module combines algorithmic checks (Shannon entropy, repeated
and sequential runs, dictionary shape) with a small, deliberately-authored list
of placeholder and example values that appear in documentation and test
fixtures. The list is ours to grow; it starts from the obvious offenders rather
than a copied corpus.
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass

from cremore.detection.validators import shannon_entropy

# Signals returned to the engine. A signal never silently drops a finding by
# itself; the policy decides whether to suppress or merely annotate it.
SIGNAL_LOW_ENTROPY = "low_entropy"
SIGNAL_WORDLIST = "wordlist"
SIGNAL_UNIFORM = "uniform"
SIGNAL_SEQUENTIAL = "sequential"

# Placeholder / example tokens we have seen in provider docs, READMEs and test
# fixtures. Lowercased, compared case-insensitively. Authored here, not copied.
# Part of the engine's detection_digest, so editing it re-sweeps scanned roots.
PLACEHOLDER_SUBSTRINGS = (
    "example",
    "placeholder",
    "changeme",
    "replace-with",
    "replace-me",
    "your-",
    "yourkey",
    "yoursecret",
    "dummy",
    "sample",
    "test-key",
    "testkey",
    "notreal",
    "fake",
    "redacted",
    "xxxxxxxx",
    "000000000000",
    "111111111111",
    "aaaaaaaaaaaa",
    "abcdefghijkl",
    "deadbeef",
    "1234567890",
    "lorem",
    "ipsum",
)

# A canonical UUID; common as an id but rarely a real secret on its own.
_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _is_uniform(value: str) -> bool:
    """True when the value is one repeated character or a tiny alphabet."""

    return len(set(value)) <= max(1, len(value) // 12)


def _is_sequential(value: str) -> bool:
    """True when a long stretch is strictly ascending/descending by code point."""

    if len(value) < 8:
        return False
    runs = 1
    best = 1
    step = 0
    for a, b in itertools.pairwise(value):
        delta = ord(b) - ord(a)
        if delta in (1, -1) and (step == 0 or delta == step):
            runs += 1
            step = delta
            best = max(best, runs)
        else:
            runs = 1
            step = 0
    return best >= 8


@dataclass(frozen=True)
class FPPolicy:
    """Configures false-positive handling.

    ``entropy`` is the minimum bits/char a secret must carry. ``retain`` keeps a
    flagged finding (annotated with its signal) rather than dropping it, so an
    analyst can review borderline matches instead of silently losing them.
    """

    entropy: float = 3.0
    retain: bool = True

    def signal(self, value: str) -> str:
        """Return the strongest false-positive signal for ``value``, or ""."""

        lowered = value.lower()
        for needle in PLACEHOLDER_SUBSTRINGS:
            if needle in lowered:
                return SIGNAL_WORDLIST
        if _UUID.match(value):
            return SIGNAL_WORDLIST
        if _is_uniform(value):
            return SIGNAL_UNIFORM
        if _is_sequential(value):
            return SIGNAL_SEQUENTIAL
        if self.entropy > 0 and shannon_entropy(value) < self.entropy:
            return SIGNAL_LOW_ENTROPY
        return ""

    def policy_tag(self) -> str:
        """Short identity of this policy for the engine version string."""

        return f"fp={'retain' if self.retain else 'drop'}:entropy={self.entropy:g}"
