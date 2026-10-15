"""Plain text that goes into records people read later: nothing that hides, breaks or reorders it."""

from __future__ import annotations

import unicodedata

_UNSAFE_CATEGORIES = ("Cc", "Cf", "Zl", "Zp", "Cs")
# Letters that draw nothing (the Hangul fillers, the blank Braille pattern): a name of them reads as empty.
_BLANK_LETTERS = frozenset(map(chr, (0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800)))


def unsafe_text(value: str, *, newlines: bool = False) -> bool:
    """Characters no stored label or note takes: controls (C0 and C1), format and bidi characters, line and
    paragraph separators, lone surrogates, letters that draw nothing. ``newlines`` lets plain line feeds through
    for multi-line notes."""
    return any((unicodedata.category(char) in _UNSAFE_CATEGORIES and not (newlines and char == "\n"))
               or char in _BLANK_LETTERS for char in value)
