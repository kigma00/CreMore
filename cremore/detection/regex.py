"""Regex backend.

The engine runs untrusted content through many expressions, so it prefers RE2
(``google-re2``) for its linear-time guarantee against pathological input.
When RE2 is not installed it falls back to the standard library
``re`` module; the built-in catalog deliberately uses only expressions both
engines accept (no backreferences or lookaround), so behaviour matches.
"""

from __future__ import annotations

import re as _stdlib_re
from typing import Any, Protocol

try:  # pragma: no cover - import guard
    import re2 as _backend  # type: ignore

    USING_RE2 = True
except Exception:  # pragma: no cover  # noqa: BLE001 -- Native extension initialization can fail beyond ImportError.
    _backend = _stdlib_re  # type: ignore
    USING_RE2 = False


class Match(Protocol):
    def group(self, g: int | str = 0, /) -> str | None: ...
    def start(self, g: int | str = 0, /) -> int: ...
    def end(self, g: int | str = 0, /) -> int: ...


class Pattern:
    """Thin wrapper exposing exactly what the engine needs from a compiled regex."""

    __slots__ = ("_group_index", "_re")

    def __init__(self, compiled: Any) -> None:
        self._re = compiled
        self._group_index: dict[str, int] = {}
        groupindex = getattr(compiled, "groupindex", {}) or {}
        for name, index in dict(groupindex).items():
            # A bytes pattern makes google-re2 report bytes group names, while
            # the stdlib reports str; normalise so both backends resolve
            # ``group_index("secret")`` identically.
            key = name.decode("utf-8") if isinstance(name, (bytes, bytearray)) else str(name)
            self._group_index[key] = int(index)

    def finditer(self, data: bytes, *, resume_group: int | None = None) -> Any:
        if resume_group is None:
            yield from self._re.finditer(data)
            return
        # A detector may consume a trailing delimiter. Resume at the secret's
        # end so that the next candidate can reuse that delimiter as its start.
        position = 0
        while position <= len(data):
            match = self._re.search(data, position)
            if match is None:
                return
            yield match
            position = max(position + 1, match.start() + 1, match.end(resume_group))

    def search(self, data: bytes) -> Any:
        return self._re.search(data)

    def num_groups(self) -> int:
        # re2 and re both expose the subgroup count via ``groups``.
        return int(getattr(self._re, "groups", 0))

    def group_index(self, name: str) -> int:
        """Return the 1-based index of a named group, or -1 when absent."""
        return self._group_index.get(name, -1)


def compile_bytes(expr: str) -> Pattern:
    """Compile a pattern for matching against ``bytes`` input.

    Both backends operate on bytes when given a bytes pattern, which keeps the
    engine byte-accurate for line and span offsets.
    """

    return Pattern(_backend.compile(expr.encode("utf-8")))
