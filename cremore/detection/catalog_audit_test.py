"""Catalog-wide audit: a mechanical quality gate over every detector.

Rather than trusting each hand-authored detector individually, these checks run
against the whole catalog so a malformed, unroutable, over-broad, or
RE2-unsafe detector fails CI. This is the "verify thoroughly" backstop for the
breadth work: it keeps false positives (over-broad/unanchored patterns) and
false negatives (broken patterns, missing keywords) from slipping in.
"""

from __future__ import annotations

import re

import pytest

from cremore.detection.catalog import builtin_definitions
from cremore.detection.engine import Engine
from cremore.detection.models import PatternRole
from cremore.detection.regex import compile_bytes

DEFS = builtin_definitions()
_VALID_CONFIDENCE = {"high", "medium", "low"}
# Constructs RE2 does not support; their presence means the pattern is not
# portable/linear-time and must be rewritten.
_RE2_UNSAFE = [
    (r"(?<=", "lookbehind"),
    (r"(?<!", "negative lookbehind"),
    (r"(?=", "lookahead"),
    (r"(?!", "negative lookahead"),
]
_BACKREF = re.compile(r"\\[1-9]")
# RE2 rejects counted repetition above 1000 ({n,m} with m > 1000). The stdlib
# accepts it silently, so check explicitly rather than relying on the backend
# that happens to be installed.
_COUNTED_REP = re.compile(r"\{(\d+)?,(\d+)\}")
_RE2_MAX_REPEAT = 1000


def test_catalog_builds():
    # The engine compiles every pattern; this also proves RE2/stdlib acceptance.
    assert len(Engine().catalog()) == len(DEFS)


@pytest.mark.parametrize("d", DEFS, ids=[d.catalog.id for d in DEFS])
def test_each_detector_is_well_formed(d):
    c = d.catalog
    assert c.id and c.provider and c.credential_type, c.id
    assert c.source_url.startswith("http"), f"{c.id} lacks a source_url"
    assert c.provenance == "provider-documentation"
    assert c.confidence in _VALID_CONFIDENCE, f"{c.id} bad confidence {c.confidence!r}"
    # Every detector must be routable: at least one non-empty keyword.
    assert c.keywords and all(k for k in c.keywords), f"{c.id} has no routable keyword"
    # Exactly the expected pattern roles, and at least one SECRET expression.
    assert any(p.role == PatternRole.SECRET for p in d.patterns), f"{c.id} has no SECRET pattern"


@pytest.mark.parametrize("d", DEFS, ids=[d.catalog.id for d in DEFS])
def test_patterns_are_re2_safe_and_compile(d):
    for p in d.patterns:
        for token, label in _RE2_UNSAFE:
            assert token not in p.expr, f"{d.catalog.id}: {label} is not RE2-safe"
        assert not _BACKREF.search(p.expr), f"{d.catalog.id}: backreference is not RE2-safe"
        for m in _COUNTED_REP.finditer(p.expr):
            assert int(m.group(2)) <= _RE2_MAX_REPEAT, (
                f"{d.catalog.id}: repetition {m.group(0)} exceeds RE2's limit of {_RE2_MAX_REPEAT}")
        compile_bytes(p.expr)  # raises if the backend rejects it


def test_no_duplicate_ids_or_detector_names():
    ids = [d.catalog.id for d in DEFS]
    assert len(ids) == len(set(ids)), "duplicate detector id"
    names = [d.detector_name for d in DEFS]
    assert len(names) == len(set(names)), "duplicate detector_name"


@pytest.mark.parametrize("d", DEFS, ids=[d.catalog.id for d in DEFS])
def test_secret_pattern_rejects_trivial_input(d):
    # A SECRET expression must not match a single space or empty-ish noise: that
    # would be a catastrophically over-broad (false-positive) detector.
    engine = Engine(definitions=[d])
    for noise in (b" ", b"\n", b"x", b"=", b"://"):
        assert engine.scan(_inp(noise)) == [], f"{d.catalog.id} matched trivial {noise!r}"


def _inp(data: bytes):
    from cremore.detection.models import DetectorInput, ResourceRef

    return DetectorInput(data=data, resource=ResourceRef())
