"""Bounded provider facts, screened without verification or engine recursion."""

from __future__ import annotations

import re
from functools import lru_cache
from urllib.parse import unquote

from cremore.detection.catalog import builtin_definitions
from cremore.detection.decoders import decoded_views
from cremore.detection.models import PatternRole
from cremore.detection.regex import compile_bytes

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# These credential families are no longer issued as standalone findings, but
# must still never appear in evidence beside a supported detector's match.
_RETIRED_SLACK = re.compile(rb"(?:xoxe[-.]|xwfp-|xox[cd]-)[A-Za-z0-9-]{10,}")
MAX_FACT_LENGTH = 2048
_MAX_VIEWS = 16
_MAX_DEPTH = 3


@lru_cache(maxsize=1)
def _fact_patterns():
    return tuple((tuple(k.lower().encode() for k in definition.catalog.keywords),
                  tuple(compile_bytes(_fact_expression(p.expr)) for p in definition.patterns if p.role == PatternRole.SECRET),
                  tuple(compile_bytes(p.expr) for p in definition.patterns
                        if p.role in (PatternRole.IDENTIFIER, PatternRole.REQUIRED)))
                 for definition in builtin_definitions())


def _fact_expression(expr):
    # Content boundaries avoid false positives in source code. A metadata field
    # is not allowed to retain a token merely because a label touches its edge.
    for boundary in ("[^A-Za-z0-9_-]", "[^A-Za-z0-9_~.-]"):
        expr = expr.removeprefix("(?:^|" + boundary + ")").removesuffix("(?:$|" + boundary + ")")
    return expr


def safe_fact_text(value: object, *, secrets: tuple[str, ...] = ()) -> str | None:
    """Keep an entire short fact or omit it; never truncate a credential.

    Provider responses are untrusted even when their field names are allowed.
    Screen known authentication material and catalog shapes in the original and
    bounded decoded forms. No verification, persistence or raw-content logging.
    """
    return _safe_text(value, secrets, _fact_patterns())


def safe_evidence_text(value: str) -> str | None:
    """Screen retired families after the engine's contextual detector masking.

    Active catalog matches have already been masked using their code-context
    rules. Reapplying metadata-only patterns would hide legitimate source code.
    """
    return _safe_text(value, (), ())


def _safe_text(value, secrets, patterns):
    if not isinstance(value, str) or len(value) > MAX_FACT_LENGTH or _CONTROL.search(value):
        return None
    try:
        pending = [(value.encode("utf-8"), 0)]
        known = tuple(s.encode("utf-8") for s in secrets if s)
    except UnicodeError:
        return None
    seen = set()
    while pending:
        view, depth = pending.pop()
        if view in seen:
            continue
        if len(seen) >= _MAX_VIEWS or len(view) > MAX_FACT_LENGTH * 4:
            return None
        seen.add(view)
        if any(secret in view for secret in known):
            return None
        if _RETIRED_SLACK.search(view):
            return None
        lowered = view.lower()
        for keywords, candidates, required in patterns:
            if keywords and not any(k in lowered for k in keywords):
                continue
            if any(pattern.search(view) for pattern in candidates) and all(p.search(view) for p in required):
                return None
        decoded = [item.data for item in decoded_views(view)]
        decoded.append(unquote(view.decode("utf-8", "replace")).encode("utf-8"))
        for child in decoded:
            if child not in seen:
                if depth >= _MAX_DEPTH:
                    return None
                pending.append((child, depth + 1))
    return value
