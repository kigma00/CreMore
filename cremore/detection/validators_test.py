"""Validator tests (false-positive reduction primitives)."""

from __future__ import annotations

import pytest

from cremore.detection.falsepositives import shannon_entropy as text_entropy
from cremore.detection.validators import all_of, luhn_valid, min_entropy, shannon_entropy


def test_shannon_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"aaaaaaaa") == 0.0
    assert shannon_entropy(b"abcdefgh") > 2.9  # 8 distinct symbols -> 3 bits


@pytest.mark.parametrize("value,expected", [
    ("", 0.0), (b"", 0.0), ("aaaa", 0.0),
    ("\u00e9\u00e9", 0.0), (b"\xc3\xa9\xc3\xa9", 1.0), ("abcd", 2.0),
])
def test_entropy_preserves_unicode_symbols_and_raw_bytes(value, expected):
    assert text_entropy(value) == shannon_entropy(value) == expected


def test_min_entropy_gate():
    gate = min_entropy(3.0)
    assert gate(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") is False
    assert gate(b"aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4dE6f") is True


def test_luhn():
    assert luhn_valid(b"4242424242424242") is True   # a Luhn-valid test PAN
    assert luhn_valid(b"4242424242424241") is False
    assert luhn_valid(b"1234") is False               # too short


def test_all_of():
    v = all_of(min_entropy(2.0), lambda b: len(b) >= 8)
    assert v(b"abcdefgh") is True
    assert v(b"abc") is False  # too short
