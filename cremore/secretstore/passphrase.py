"""The sealing master derived from a supplied passphrase.

This is for the installation that has no AWS, no Vault, and no OS keyring to
put a key in -- a headless Linux server reached over SSH is the case the other
roots do not cover. ``secret-tool`` needs a desktop session; KMS needs an AWS
account; Vault needs Vault. A passphrase needs a person.

Typing it avoids an .env copy; it does not prove disk absence. Docker retains
injected environment across existing-container restarts. Container recreation
requires the same phrase to be supplied again::

    read -rs -p "CreMore sealing passphrase: " SEALING_PASSPHRASE
    export SEALING_PASSPHRASE
    docker compose up -d
    unset SEALING_PASSPHRASE

The salt is derived from ``FINGERPRINT_KEY`` rather than configured. That key
already exists in every installation and can never rotate, so it is stable by
construction and needs no new variable that must not change. It also means the
passphrase alone does not open a stolen database, and a stolen ``.env`` alone
does not either if it does not contain the phrase. Both inputs are needed;
their actual persistence depends on the deployment's injection mechanism.
"""

from __future__ import annotations

import unicodedata

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# NIST SP 800-63B sets no composition rules and an 8-character floor for a
# memorized secret. This one opens every stored credential, so the floor is
# higher -- and long is the only thing that helps, which is what the refusal says.
MIN_LENGTH = 12
_SALT_INFO = b"cremore/sealing-passphrase-salt/v1"
_SALT_LENGTH = 16
# Interactive scrypt: about a quarter of a second and 64 MiB per derivation.
# It runs when a credential is sealed and when a worker starts, not per scan.
_COST, _BLOCK, _PARALLEL = 2 ** 16, 8, 1


class SealingPassphraseError(ValueError):
    """The passphrase could not be turned into a master key."""


def salt_for(fingerprint_key: bytes) -> bytes:
    """A stable, installation-specific salt, with no variable to keep in step."""
    if not fingerprint_key:
        raise SealingPassphraseError("SEALING_PASSPHRASE requires FINGERPRINT_KEY to derive its salt")
    return HKDF(hashes.SHA256(), _SALT_LENGTH, salt=None, info=_SALT_INFO).derive(fingerprint_key)


def master(value: str, fingerprint_key: bytes) -> bytes:
    """Derive the sealing master from a typed passphrase."""
    # NFKC, because the same phrase typed on a Korean keyboard and on a Mac can
    # be different byte sequences for the same characters, and the master would
    # then differ between the two without anything saying why.
    text = unicodedata.normalize("NFKC", value or "").strip()
    if len(text) < MIN_LENGTH:
        raise SealingPassphraseError(
            f"SEALING_PASSPHRASE must be at least {MIN_LENGTH} characters; length is the only thing that helps")
    return Scrypt(salt=salt_for(fingerprint_key), length=32,
                  n=_COST, r=_BLOCK, p=_PARALLEL).derive(text.encode("utf-8"))
