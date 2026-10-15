"""Keyed digests of identity values (emails, logins, IdP user ids, SAML/SCIM ids).

CreMore links a provider account to a person only when both name the same value,
and never stores the IdP side's emails or logins: an IdP collector keeps only these
digests, keyed by a key derived from FINGERPRINT_KEY, so a leaked database cannot
list an organization's people. The digest ignores what kind of value it is, because
a SAML NameID may carry an IdP's user id, login or email, whichever it was set to.
"""

from __future__ import annotations

import hashlib
import hmac
import unicodedata

# What an IdP says a value is; a provider account's value carries a basis instead.
KINDS = ("IDP_USER_ID", "LOGIN", "EMAIL")
# How an account came to name a value. EXACT bases link on their own; candidate
# bases only ever suggest a link an administrator confirms.
EXACT_BASES = ("SCIM_EXTERNAL_ID", "SAML_NAME_ID", "EXTERNAL_UID", "IDP_OBJECT_ID", "VERIFIED_EMAIL")
CANDIDATE_BASES = ("UNVERIFIED_EMAIL", "PROVIDER_LOGIN")
BASES = EXACT_BASES + CANDIDATE_BASES
_CONTEXT = b"cremore-identity-key-v1"


def derive(fingerprint_key: bytes) -> bytes:
    if not isinstance(fingerprint_key, bytes | bytearray) or len(fingerprint_key) < 32:
        raise ValueError("IDENTITY_KEY_UNAVAILABLE")
    return hmac.new(bytes(fingerprint_key), _CONTEXT, hashlib.sha256).digest()


def key_id(derived: bytes) -> str:
    """Names the key in stored records, so a rotated FINGERPRINT_KEY is noticed, not mismatched."""
    return hashlib.sha256(b"cremore-identity-key-id|" + derived).hexdigest()


def normalize(value) -> str | None:
    if not isinstance(value, str):
        return None
    text = unicodedata.normalize("NFKC", value).strip().casefold()
    return text if 0 < len(text) <= 512 and text.isprintable() else None


def digest(derived: bytes, value) -> str | None:
    text = normalize(value)
    return None if text is None else hmac.new(derived, text.encode(), hashlib.sha256).hexdigest()


class Digester:
    """What a collector receives: it can digest values, never read the key."""

    __slots__ = ("_key", "key_id")

    def __init__(self, fingerprint_key: bytes):
        self._key = derive(fingerprint_key)
        self.key_id = key_id(self._key)

    def __call__(self, value) -> str | None:
        return digest(self._key, value)

    def __repr__(self) -> str:
        return "Digester(key_id=" + self.key_id[:12] + "...)"
