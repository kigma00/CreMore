"""The keyword router chooses exactly the detectors the per-keyword ``in`` test chose."""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from cremore.detection.engine import Engine, _KeywordRouter

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def engine():
    return Engine()


def _expected(engine, lowered):
    return [spec.catalog.id for spec in engine._specs
            if not spec.keywords or any(k in lowered for k in spec.keywords)]


def _routed(engine, lowered):
    present = engine._router.present(lowered)
    return [spec.catalog.id for spec in engine._specs
            if not spec.keywords or any(k in present for k in spec.keywords)]


def _keywords(engine):
    return sorted({k for spec in engine._specs for k in spec.keywords})


def test_repository_files_route_identically(engine):
    files = [path for pattern in ("cremore/**/*.py", "docs/*.md", "web/console/**/*.ts", "deploy/**/*.yaml")
             for path in sorted(ROOT.glob(pattern))][:400]
    assert len(files) > 100
    for path in files:
        lowered = path.read_bytes().lower()
        assert _routed(engine, lowered) == _expected(engine, lowered), path


def test_fragment_soup_routes_identically(engine):
    """Overlapping keyword prefixes and suffixes are where a non-overlapping scan could miss one."""
    keywords = _keywords(engine)
    rng = random.Random(20261009)
    for _ in range(400):
        parts = []
        for _ in range(rng.randrange(1, 60)):
            keyword = rng.choice(keywords)
            cut = rng.randrange(len(keyword) + 1)
            parts.append(rng.choice((keyword, keyword[:cut], keyword[cut:], bytes([rng.randrange(256)]))))
        lowered = b"".join(parts).lower()
        assert _routed(engine, lowered) == _expected(engine, lowered)


def test_random_bytes_route_identically(engine):
    rng = random.Random(7)
    for _ in range(200):
        lowered = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 3000))).lower()
        assert _routed(engine, lowered) == _expected(engine, lowered)


KEYWORDS = [b"abcd", b"cdef", b"bc", b"abcdefg", b"d", b"\xc3\xa9t\xff", b"fab",
            b"a.b", b"(|", b"\\", b"\x00x", b"\n="]


@pytest.mark.parametrize("text", [
    b"abcdef", b"xabcdefgx", b"cdefabcd", b"bcd", b"abcabcdcdef", b"", b"\xc3\xa9t\xffabc",
    b"a.b(|\\", b"axb", b"\x00x\n=", b"a.b\x00", b"(|abcd\\",
])
def test_overlapping_contained_and_special_byte_keywords(text):
    router = _KeywordRouter(KEYWORDS)
    assert router.present(text) == {k for k in KEYWORDS if k in text}


def test_plain_test_without_re2_gives_the_same_answer(monkeypatch):
    from cremore.detection import engine as engine_module

    monkeypatch.setattr(engine_module, "USING_RE2", False)
    router = _KeywordRouter(KEYWORDS)
    assert router._pattern is None
    for text in (b"abcdefg", b"a.b(|", b"zzz", b"\x00x"):
        assert router.present(text) == {k for k in KEYWORDS if k in text}


def test_keyword_overlapping_only_at_the_end_of_a_long_run_is_found():
    keywords = [b"token", b"enable", b"ken_x"]
    router = _KeywordRouter(keywords)
    text = b"token " * 10_000 + b"tokenable"
    assert router.present(text) == {b"token", b"enable"}
    text = b"token " * 10_000 + b"token_x"
    assert router.present(text) == {b"token", b"ken_x"}


def test_keyword_dense_view_switches_to_the_plain_test_exactly():
    """Denser than one match per DENSE_BYTES: the plain test finishes the job with the same answer."""
    keywords = [b"ab", b"bab", b"zz", b"never"]
    router = _KeywordRouter(keywords)
    text = b"ab" * (router.DENSE_MATCHES * 2) + b"zz"
    assert router.present(text) == {b"ab", b"bab", b"zz"}
    # A sparse start does not hide a dense tail.
    text = b"x" * 200_000 + b"ab" * (router.DENSE_MATCHES * 3) + b"zz"
    assert router.present(text) == {b"ab", b"bab", b"zz"}


def test_empty_keyword_is_always_present():
    router = _KeywordRouter([b"", b"abc"])
    assert router.present(b"zzz") == {b""}
    assert router.present(b"zabcz") == {b"", b"abc"}


def test_detection_results_unchanged_on_secret_bearing_content(engine):
    from cremore.detection.models import DetectorInput, ResourceRef

    # Synthetic key shapes, built at run time so the file holds no credential-shaped literal.
    content = (b"aws_access_key_id = AKIA" + b"IOSFODNN7EXAMPLQ\n"
               b"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEZ\n"
               b"github: ghp_" + b"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" + b"\n")
    ref = ResourceRef(source_type="inline", location="config.env")
    routed = engine.scan(DetectorInput(content, ref))
    original = engine._router
    try:
        class _Plain:
            always = frozenset()

            @staticmethod
            def present(lowered):
                return {k for spec in engine._specs for k in spec.keywords if k in lowered}

        engine._router = _Plain()
        plain = engine.scan(DetectorInput(content, ref))
    finally:
        engine._router = original
    assert sorted((d.detector_name, d.fingerprint) for d in routed) == sorted((d.detector_name, d.fingerprint) for d in plain)
