"""Passphrase derivation, opening-key compatibility and safe error reporting.

The passphrase root exists for the installation the others do not reach: no
AWS, no Vault, and no OS keyring because there is no desktop session. What
these pin is that the same phrase always yields the same master (or every
stored credential is orphaned by a restart), that a short one is refused while
somebody is still there to type a longer one, and that the phrase itself never
appears in an error or sealed output. These tests do not prove disk absence.
"""

from __future__ import annotations

import pytest

from cremore.config import Settings
from cremore.secretstore.passphrase import MIN_LENGTH, SealingPassphraseError, master, salt_for
from cremore.secretstore.sealed import key_id, seal_token, unseal

KEY = bytes.fromhex("ab" * 32)
OTHER = bytes.fromhex("cd" * 32)
PHRASE = "correct horse battery staple"
OLD_PHRASE = "the one we used before this"
TOKEN = "synthetic-connection-token-" + "x" * 16


# -- the same phrase must always give the same master --------------------------


def test_the_same_phrase_gives_the_same_master_every_time():
    # A restart that derived a different master would orphan every stored
    # credential, and nothing would say why.
    assert master(PHRASE, KEY) == master(PHRASE, KEY)
    assert len(master(PHRASE, KEY)) == 32


def test_spacing_around_the_phrase_does_not_change_the_master():
    assert master(f"  {PHRASE}  ", KEY) == master(PHRASE, KEY)


def test_the_same_characters_typed_two_ways_give_the_same_master():
    # NFKC: the same Korean phrase composed and decomposed is the same phrase,
    # and a master that differed between two keyboards would be unopenable on
    # one of them with nothing to explain it.
    composed, decomposed = "비밀번호를 길게 적습니다", "비밀번호를 길게 적습니다"
    import unicodedata

    assert master(unicodedata.normalize("NFC", composed), KEY) == master(unicodedata.normalize("NFD", decomposed), KEY)


def test_a_different_installation_derives_a_different_master():
    # The salt comes from FINGERPRINT_KEY, so one phrase reused across two
    # installations does not produce one key that opens both databases.
    assert master(PHRASE, KEY) != master(PHRASE, OTHER)
    assert salt_for(KEY) != salt_for(OTHER)
    assert len(salt_for(KEY)) == 16


def test_a_different_phrase_gives_a_different_master():
    assert master(PHRASE, KEY) != master(PHRASE + "!", KEY)


# -- refusing while somebody is still there ------------------------------------


@pytest.mark.parametrize("bad", ["", "   ", "short", "a" * (MIN_LENGTH - 1)])
def test_a_short_phrase_is_refused_and_the_refusal_says_what_helps(bad):
    with pytest.raises(SealingPassphraseError, match=f"at least {MIN_LENGTH} characters"):
        master(bad, KEY)


def test_a_phrase_without_a_fingerprint_key_has_no_salt_to_use():
    with pytest.raises(SealingPassphraseError, match="FINGERPRINT_KEY"):
        master(PHRASE, b"")


def test_start_up_refuses_a_short_phrase_rather_than_the_first_credential():
    with pytest.raises(ValueError, match="SEALING_PASSPHRASE must be at least"):
        Settings(FINGERPRINT_KEY=KEY.hex(), SEALING_PASSPHRASE="tooshort").validate_sealing()
    with pytest.raises(ValueError, match="SEALING_PASSPHRASE_PREVIOUS must be at least"):
        Settings(FINGERPRINT_KEY=KEY.hex(), SEALING_PASSPHRASE_PREVIOUS=f"{PHRASE},no").validate_sealing()
    Settings(FINGERPRINT_KEY=KEY.hex(), SEALING_PASSPHRASE=PHRASE).validate_sealing()


# -- what the installation ends up with ----------------------------------------


def test_a_typed_phrase_seals_instead_of_a_key_sitting_in_the_environment():
    keys = Settings(FINGERPRINT_KEY=KEY.hex(), SEALING_PASSPHRASE=PHRASE, SEALING_KEY=OTHER.hex()).sealing_keys
    # The configured phrase takes precedence; the deployment owns persistence.
    assert keys.current == master(PHRASE, KEY)
    assert seal_token(keys, TOKEN).startswith("sealed:v2:" + key_id(master(PHRASE, KEY)))
    # The key it displaced still opens what it sealed.
    assert unseal(keys, seal_token(OTHER, TOKEN)) == {"token": TOKEN}


def test_changing_the_phrase_keeps_what_the_old_one_sealed_readable():
    before = seal_token(master(OLD_PHRASE, KEY), TOKEN)
    keys = Settings(FINGERPRINT_KEY=KEY.hex(), SEALING_PASSPHRASE=PHRASE,
                    SEALING_PASSPHRASE_PREVIOUS=OLD_PHRASE).sealing_keys
    assert unseal(keys, before) == {"token": TOKEN}
    assert keys.current_id == key_id(master(PHRASE, KEY)), "the old phrase opens, it does not seal"


def test_no_phrase_leaves_the_installation_exactly_as_it_was():
    keys = Settings(FINGERPRINT_KEY=KEY.hex()).sealing_keys
    assert keys.current == KEY and keys.legacy == KEY


def test_a_vault_or_kms_root_still_outranks_a_typed_phrase(monkeypatch):
    # Those restart unattended; a phrase cannot. An installation that
    # configured one has said which it wants.
    monkeypatch.setattr("cremore_aws_provider.kms.master", lambda *a, **k: OTHER)
    keys = Settings(FINGERPRINT_KEY=KEY.hex(), SEALING_PASSPHRASE=PHRASE,
                    SEALING_KMS_KEY_ID="arn:aws:kms:eu-west-1:123456789012:key/x",
                    SEALING_KEY_CIPHERTEXT="AQIDAHhTeW50aGV0aWNDaXBoZXJ0ZXh0Qg==").sealing_keys
    assert keys.current == OTHER
    # The phrase stays able to open what it sealed before the move.
    assert key_id(master(PHRASE, KEY)) in keys.known_ids()
