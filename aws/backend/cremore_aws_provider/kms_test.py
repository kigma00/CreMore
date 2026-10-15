"""The sealing master kept in KMS: what a copy of .env is worth without it.

The point of the KMS source is that the value on disk is a ciphertext. These
tests pin that the master only ever comes back through one Decrypt call pinned
to the named CMK, that nothing else on that client is reachable, and that every
way it can fail refuses rather than sealing credentials under a weak master.
"""

from __future__ import annotations

import base64
from typing import ClassVar

import pytest

from cremore.secretstore.sealed import key_id, seal_token, unseal
from cremore_aws_provider import kms
from cremore_aws_provider.aws_readonly import ReadOnlyViolation, readonly_client

MASTER = bytes.fromhex("ab" * 32)
OLD_MASTER = bytes.fromhex("cd" * 32)
HEX_KEY = bytes.fromhex("ef" * 32)
BLOB = base64.b64encode(b"a KMS ciphertext blob, opaque here" * 3).decode()
OLD_BLOB = base64.b64encode(b"the ciphertext this installation is leaving").decode()
CMK = "arn:aws:kms:ap-northeast-2:123456789012:key/2f7c5e1a-0000-4000-8000-0123456789ab"
TOKEN = "synthetic-connection-token-" + "x" * 16


class FakeKms:
    """Records what the sealing path asks of KMS, and answers as KMS does."""

    def __init__(self, keys: dict[bytes, bytes] | None = None, error: Exception | None = None):
        self.keys = keys or {}
        self.error = error
        self.calls: list[tuple[str, dict]] = []

    def decrypt(self, **kwargs):
        self.calls.append(("decrypt", kwargs))
        if self.error:
            raise self.error
        return {"KeyId": kwargs.get("KeyId"), "Plaintext": self.keys.get(kwargs["CiphertextBlob"])}


class Denied(Exception):
    """Shaped like botocore's ClientError, naming detail and all."""

    response: ClassVar[dict] = {
        "Error": {"Code": "AccessDeniedException",
                  "Message": "User: arn:aws:sts::123456789012:assumed-role/ops/session is not authorized"}}


# -- the master comes back, and nothing else does ------------------------------


def test_the_master_comes_back_through_one_decrypt_pinned_to_the_named_key():
    client = FakeKms({base64.b64decode(BLOB): MASTER})
    assert kms.master(BLOB, CMK, client=client) == MASTER
    # Naming the CMK is what makes a swapped blob fail in KMS rather than open
    # under whichever key it happens to name.
    assert client.calls == [("decrypt", {"CiphertextBlob": base64.b64decode(BLOB), "KeyId": CMK})]


def test_the_sealing_path_cannot_reach_anything_but_decrypt():
    wrapped = readonly_client(FakeKms(), "kms")
    for forbidden in ("encrypt", "generate_data_key", "schedule_key_deletion", "create_grant"):
        with pytest.raises(ReadOnlyViolation):
            getattr(wrapped, forbidden)


def test_a_key_arn_carries_its_own_region_and_a_bare_id_falls_back():
    assert kms.region_of(CMK) == "ap-northeast-2"
    assert kms.region_of("arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/abc") == "us-gov-west-1"
    assert kms.region_of("alias/cremore-sealing", "eu-west-1") == "eu-west-1"
    assert kms.region_of("2f7c5e1a-0000-4000-8000-0123456789ab", "eu-west-1") == "eu-west-1"
    assert kms.region_of("", None) is None


# -- every way it fails refuses ------------------------------------------------


def test_a_ciphertext_that_is_not_base64_is_refused_before_aws_is_called():
    client = FakeKms()
    with pytest.raises(kms.SealingKmsError, match="SEALING_KEY_CIPHERTEXT_MALFORMED"):
        kms.master("not a ciphertext!", CMK, client=client)
    assert client.calls == []


def test_a_refused_decrypt_reports_a_code_and_not_the_sdk_detail():
    with pytest.raises(kms.SealingKmsError) as caught:
        kms.master(BLOB, CMK, client=FakeKms(error=Denied()))
    assert "SEALING_KMS_DECRYPT_FAILED: AccessDeniedException" in str(caught.value)
    assert "assumed-role" not in str(caught.value)
    # The cause is dropped so the SDK detail cannot surface through it either.
    assert caught.value.__cause__ is None


@pytest.mark.parametrize("plaintext", [None, b"", b"too short", "not bytes"])
def test_a_key_that_is_not_32_bytes_is_refused_rather_than_sealed_under(plaintext):
    client = FakeKms({base64.b64decode(BLOB): plaintext})
    with pytest.raises(kms.SealingKmsError, match="SEALING_KMS_RETURNED_UNUSABLE_KEY"):
        kms.master(BLOB, CMK, client=client)


def test_a_ciphertext_without_a_named_key_is_refused():
    with pytest.raises(kms.SealingKmsError, match="SEALING_KMS_KEY_ID is required"):
        kms.master(BLOB, "   ", client=FakeKms())


# -- what the installation ends up with ----------------------------------------


def settings(monkeypatch, opened: dict[str, bytes], **env):
    """Settings whose KMS calls are answered from ``opened``, keyed by ciphertext."""
    from cremore.config import Settings

    def fake_master(ciphertext, named_key, region=None, client=None):
        assert named_key == CMK, "the configured CMK is the one asked for"
        assert region == "ap-northeast-2", "the region comes from the key ARN"
        return opened[ciphertext.strip()]

    monkeypatch.setattr(kms, "master", fake_master)
    return Settings(FINGERPRINT_KEY=HEX_KEY.hex(), SEALING_KMS_KEY_ID=CMK, **env)


def test_a_kms_held_master_seals_instead_of_the_key_on_this_disk(monkeypatch):
    keys = settings(monkeypatch, {BLOB: MASTER}, SEALING_KEY_CIPHERTEXT=BLOB,
                    SEALING_KEY=OLD_MASTER.hex()).sealing_keys
    # An installation that moved its master into KMS does not quietly fall back
    # to the hex copy it was moving away from.
    assert keys.current == MASTER
    assert seal_token(keys, TOKEN).startswith("sealed:v2:" + key_id(MASTER))
    # The hex key and FINGERPRINT_KEY still open what they sealed.
    assert set(keys.known_ids()) == {key_id(MASTER), key_id(OLD_MASTER), key_id(HEX_KEY)}


def test_rotating_to_a_new_kms_ciphertext_keeps_the_old_one_readable(monkeypatch):
    before = seal_token(OLD_MASTER, TOKEN)
    keys = settings(monkeypatch, {BLOB: MASTER, OLD_BLOB: OLD_MASTER},
                    SEALING_KEY_CIPHERTEXT=BLOB,
                    SEALING_KEY_CIPHERTEXT_PREVIOUS=OLD_BLOB).sealing_keys
    assert unseal(keys, before) == {"token": TOKEN}
    assert keys.current_id == key_id(MASTER), "the previous ciphertext opens, it does not seal"


def test_no_kms_setting_leaves_the_installation_exactly_as_it_was(monkeypatch):
    from cremore.config import Settings

    def refuse(*args, **kwargs):
        raise AssertionError("KMS must not be reached when no ciphertext is configured")

    monkeypatch.setattr(kms, "master", refuse)
    keys = Settings(FINGERPRINT_KEY=HEX_KEY.hex()).sealing_keys
    assert keys.current == HEX_KEY and keys.legacy == HEX_KEY


# -- caught at start-up, without reaching AWS ----------------------------------


def test_startup_refuses_a_ciphertext_with_no_cmk_to_open_it():
    from cremore.config import Settings

    with pytest.raises(ValueError, match="requires SEALING_KMS_KEY_ID"):
        Settings(FINGERPRINT_KEY=HEX_KEY.hex(), SEALING_KEY_CIPHERTEXT=BLOB).validate_sealing()


def test_startup_refuses_what_is_malformed_without_calling_aws(monkeypatch):
    from cremore.config import Settings

    def refuse(*args, **kwargs):
        raise AssertionError("start-up must not call AWS")

    monkeypatch.setattr(kms, "master", refuse)
    base = {"FINGERPRINT_KEY": HEX_KEY.hex(), "SEALING_KMS_KEY_ID": CMK}
    with pytest.raises(kms.SealingKmsError, match="MALFORMED"):
        Settings(**base, SEALING_KEY_CIPHERTEXT="not a ciphertext!").validate_sealing()
    with pytest.raises(kms.SealingKmsError, match="MALFORMED"):
        Settings(**base, SEALING_KEY_CIPHERTEXT_PREVIOUS=f"{BLOB},nope!").validate_sealing()
    with pytest.raises(ValueError, match="SEALING_KEY must be strict hexadecimal"):
        Settings(**base, SEALING_KEY="zz" * 32).validate_sealing()
    with pytest.raises(ValueError, match="SEALING_KEY_PREVIOUS must decode to at least 32 bytes"):
        Settings(**base, SEALING_KEY_PREVIOUS="ab" * 16).validate_sealing()
    # Well formed: nothing raises, and nothing was asked of AWS.
    Settings(**base, SEALING_KEY_CIPHERTEXT=BLOB, SEALING_KEY_CIPHERTEXT_PREVIOUS=OLD_BLOB,
             SEALING_KEY=MASTER.hex(), SEALING_KEY_PREVIOUS=OLD_MASTER.hex()).validate_sealing()
