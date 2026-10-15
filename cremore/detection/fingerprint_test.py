from cremore.detection.fingerprint import MASK_WIDTH, fingerprint, mask_hint


def _mask_run(hint: str) -> int:
    return sum(1 for ch in hint if ch == "•")


def test_every_hint_uses_the_same_mask_width_so_length_is_not_disclosed():
    # Two secrets of very different lengths must produce the same mask run, so a
    # reader (or an attacker reading stored hints) cannot infer the real length.
    short_token = "ghp_" + "a" * 32 + "aaaa"       # 40
    long_token = "ghp_" + "a" * 90 + "zzzz"        # 98
    assert _mask_run(mask_hint(short_token)) == _mask_run(mask_hint(long_token)) == MASK_WIDTH
    assert mask_hint(short_token) == "ghp_••••aaaa"


def test_a_long_credential_keeps_four_characters_each_side():
    assert mask_hint("AKIAIOSFODNN7EXAMPLE") == "AKIA••••MPLE"


def test_mid_length_values_reveal_less_than_a_long_one():
    hint = mask_hint("abcdefghijklmnop")  # 16
    assert hint == "ab••••op"
    assert _mask_run(hint) == MASK_WIDTH


def test_short_values_reveal_nothing_because_any_character_is_a_large_fraction():
    for value in ("hunter2!", "p@ss", "1234", "s3cret"):
        assert mask_hint(value) == "•" * MASK_WIDTH


def test_masking_never_returns_the_secret_and_fingerprint_stays_one_way():
    secret = "AKIAIOSFODNN7EXAMPLE"
    assert secret not in mask_hint(secret)
    keyed = fingerprint(secret.encode(), key=b"tenant-key")
    assert keyed != fingerprint(secret.encode())
    assert secret not in keyed and len(keyed) == 64
