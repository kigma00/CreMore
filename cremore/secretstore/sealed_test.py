"""Sealed connection credentials: what one key used to prevent, and what two allow.

The v1 format recorded nothing about which key sealed it, so an installation
could not hold two keys at once and changing the key made every stored
credential unreadable with no way to tell which key was missing. These tests pin
the v1 format so it keeps opening, and pin what v2's key id makes possible:
rotation, and a master that lives somewhere other than this disk.
"""

from __future__ import annotations

import base64
import json
import os

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cremore.secretstore.resolver import SecretRefError, SecretResolver, inject_secret
from cremore.secretstore.sealed import (
    SealedSecretError,
    SealingKeys,
    is_sealed,
    key_id,
    public_ref,
    seal_token,
    unseal,
)

KEY = bytes.fromhex("ab" * 32)
NEW_KEY = bytes.fromhex("cd" * 32)
OTHER = bytes.fromhex("ef" * 32)
TOKEN = "synthetic-connection-token-" + "x" * 16


def legacy_seal(master: bytes, token: str) -> str:
    """A v1 credential, built the way the original code built one.

    Written out here rather than called, so the format an existing installation
    already has on disk is pinned independently of the implementation.
    """
    cipher = AESGCM(HKDF(hashes.SHA256(), 32, salt=None,
                         info=b"cremore/connection-secret/v1").derive(master))
    nonce = os.urandom(12)
    body = cipher.encrypt(nonce, json.dumps({"token": token}).encode(),
                          b"cremore/connection-secret/v1")
    return "sealed:v1:" + base64.urlsafe_b64encode(nonce + body).decode()


# -- what is written now -------------------------------------------------------


def test_a_new_credential_records_the_key_that_sealed_it():
    ref = seal_token(KEY, TOKEN)
    assert ref.startswith("sealed:v2:" + key_id(KEY) + ":")
    assert TOKEN not in ref
    assert seal_token(KEY, TOKEN) != ref, "a fresh nonce each time"
    assert unseal(KEY, ref) == {"token": TOKEN}


def test_a_key_id_names_a_key_without_revealing_it():
    identifier = key_id(KEY)
    assert len(identifier) == 16 and int(identifier, 16) >= 0
    assert identifier != key_id(NEW_KEY)
    # An HKDF output, not the key and not a hash of it.
    assert KEY.hex()[:16] != identifier
    assert key_id(KEY) == identifier, "stable across calls"


def test_the_key_id_cannot_be_edited_to_point_at_another_held_key():
    keys = SealingKeys(KEY, KEY, previous=(NEW_KEY,))
    ref = seal_token(keys, TOKEN)
    moved = ref.replace(key_id(KEY), key_id(NEW_KEY))
    # The id is authenticated with the ciphertext, so swapping it fails to open
    # rather than silently selecting a different key.
    with pytest.raises(SealedSecretError, match="could not be decrypted"):
        unseal(keys, moved)


# -- what an installation already has ------------------------------------------


def test_a_credential_sealed_before_this_change_still_opens():
    old = legacy_seal(KEY, TOKEN)
    assert is_sealed(old)
    assert unseal(KEY, old) == {"token": TOKEN}
    # And through a keyring whose current key is a different one entirely.
    assert unseal(SealingKeys(NEW_KEY, legacy=KEY), old) == {"token": TOKEN}


def test_the_version_travels_so_a_reader_is_not_told_v1_about_a_v2_credential():
    assert public_ref(legacy_seal(KEY, TOKEN)) == "sealed:v1"
    assert public_ref(seal_token(KEY, TOKEN)) == "sealed:v2"
    assert public_ref("vault://gh/x") == "configured"
    assert public_ref("vault://gh/x", include_reference=True) == "vault://gh/x"
    assert public_ref(None) is None


@pytest.mark.parametrize("value", [TOKEN, "https://credentials.test/value", "vault://../invalid", ""])
def test_legacy_unrecognized_references_are_not_public(value):
    assert public_ref(value) == "configured"
    assert public_ref(value, include_reference=True) == "configured"


def test_an_unset_sealing_key_keeps_the_installation_on_its_existing_master():
    from cremore.config import Settings

    keys = Settings(FINGERPRINT_KEY=KEY.hex()).sealing_keys
    # Nothing to migrate: the same master seals and opens, as it always did.
    assert keys.current == KEY and keys.legacy == KEY
    assert unseal(keys, legacy_seal(KEY, TOKEN)) == {"token": TOKEN}
    assert unseal(keys, seal_token(keys, TOKEN)) == {"token": TOKEN}


# -- what two keys make possible -----------------------------------------------


def test_rotation_keeps_stored_credentials_readable_while_new_ones_use_the_new_key():
    from cremore.config import Settings

    before = seal_token(KEY, TOKEN)
    rotated = Settings(FINGERPRINT_KEY=OTHER.hex(), SEALING_KEY=NEW_KEY.hex(),
                       SEALING_KEY_PREVIOUS=KEY.hex()).sealing_keys
    # The credential sealed under the old key still opens...
    assert unseal(rotated, before) == {"token": TOKEN}
    # ...and anything sealed from now on names the new one.
    after = seal_token(rotated, TOKEN)
    assert after.startswith("sealed:v2:" + key_id(NEW_KEY) + ":")
    assert unseal(rotated, after) == {"token": TOKEN}
    # The old key opens, it does not seal.
    assert rotated.current_id == key_id(NEW_KEY)


def test_a_fingerprint_key_that_no_longer_seals_still_opens_what_it_sealed():
    from cremore.config import Settings

    old = legacy_seal(KEY, TOKEN)
    separated = Settings(FINGERPRINT_KEY=KEY.hex(), SEALING_KEY=NEW_KEY.hex()).sealing_keys
    # This is the separation: FINGERPRINT_KEY keys fingerprints, which must never
    # rotate, and it is no longer the master for new credentials.
    assert separated.current == NEW_KEY
    assert unseal(separated, old) == {"token": TOKEN}
    assert seal_token(separated, TOKEN).startswith("sealed:v2:" + key_id(NEW_KEY))


def test_a_missing_key_is_named_so_an_operator_knows_which_one_to_restore():
    ref = seal_token(OTHER, TOKEN)
    with pytest.raises(SealedSecretError, match=f"SEALING_KEY_NOT_AVAILABLE: {key_id(OTHER)}"):
        unseal(SealingKeys(KEY, KEY), ref)


# -- failing closed ------------------------------------------------------------


def test_wrong_key_tampering_and_missing_key_fail_closed():
    ref = seal_token(KEY, TOKEN)
    with pytest.raises(SealedSecretError):
        unseal(SealingKeys(NEW_KEY, NEW_KEY), ref)
    flipped = ref[:-2] + ("A" if ref[-2] != "A" else "B") + ref[-1]
    with pytest.raises(SealedSecretError):
        unseal(KEY, flipped)
    with pytest.raises(SealedSecretError, match="SEALING_KEY_REQUIRED"):
        seal_token(None, TOKEN)
    with pytest.raises(SealedSecretError, match="SEALING_KEY_REQUIRED"):
        key_id(b"")


@pytest.mark.parametrize("bad", ["", "   ", "a\nb", "x" * 8193])
def test_seal_rejects_empty_control_or_oversized_tokens(bad):
    with pytest.raises(SealedSecretError):
        seal_token(KEY, bad)


@pytest.mark.parametrize("bad", [
    "sealed:v2:" + "a" * 15 + ":Zm9v", "sealed:v2::Zm9v", "sealed:v2:" + key_id(KEY),
    "sealed:v2:" + key_id(KEY) + ":not base64!",
])
def test_a_malformed_reference_is_refused_rather_than_guessed_at(bad):
    with pytest.raises(SealedSecretError):
        unseal(KEY, bad)


def test_only_supported_versions_and_strict_envelopes_are_opened():
    legacy = legacy_seal(KEY, TOKEN)
    current = seal_token(KEY, TOKEN)
    for invalid in (legacy.replace("sealed:v1:", "sealed:v9:"), current + "\n", None, 42):
        with pytest.raises(SealedSecretError):
            unseal(KEY, invalid)
    assert unseal(KEY, legacy) == unseal(KEY, current) == {"token": TOKEN}


@pytest.mark.parametrize("value,sealed", [
    ("sealed:v1:abc", True), ("sealed:v2:abc", True), ("sealed:v3:abc", False),
    ("vault://a/b", False), ("sealed", False), ("", False), (None, False),
])
def test_only_a_known_sealed_format_is_treated_as_stored_ciphertext(value, sealed):
    assert is_sealed(value) is sealed


# -- the path a scan actually takes --------------------------------------------


def test_resolver_injects_sealed_tokens_without_a_secret_store():
    resolver = SecretResolver(sealing_key=KEY)
    payload = {"owner": "o", "repo": "r", "secret_ref": seal_token(KEY, TOKEN)}
    assert inject_secret("github", payload, resolver)["token"] == TOKEN
    # A v1 credential reaches the worker the same way.
    assert inject_secret("github", {**payload, "secret_ref": legacy_seal(KEY, TOKEN)},
                         resolver)["token"] == TOKEN
    with pytest.raises(SecretRefError, match="SECRET_STORE_URL"):
        inject_secret("github", {"secret_ref": "vault://gh/o"}, resolver)
    with pytest.raises(SecretRefError, match="could not resolve"):
        inject_secret("notion", {"secret_ref": seal_token(KEY, TOKEN)},
                      SecretResolver(sealing_key=bytes(32)))


def test_the_worker_resolves_through_the_installations_whole_keyring():
    from cremore.config import Settings

    rotated = Settings(FINGERPRINT_KEY=KEY.hex(), SEALING_KEY=NEW_KEY.hex(),
                       SEALING_KEY_PREVIOUS=OTHER.hex()).sealing_keys
    resolver = SecretResolver(sealing_key=rotated)
    for ref in (legacy_seal(KEY, TOKEN), seal_token(OTHER, TOKEN), seal_token(NEW_KEY, TOKEN)):
        assert inject_secret("notion", {"secret_ref": ref}, resolver)["token"] == TOKEN
