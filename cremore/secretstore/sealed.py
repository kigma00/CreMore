"""Connection credentials encrypted by CreMore itself (no external secret store).

A token entered in the dashboard is sealed with AES-256-GCM and kept in the
connection's ``secret_ref``. It travels the same path as a ``vault://`` pointer:
copied into job payloads (never served by the API) and opened by the worker just
before a scan.

Shared installations retain v1/v2 compatibility. Isolated deployments use v3:

``sealed:v1:<base64url(nonce || ciphertext)>``
    The original. It records nothing about which key sealed it, so changing the
    key made every stored credential unreadable at once and there was no way to
    hold two keys while moving between them. Still read, never written.

``sealed:v2:<key_id>:<base64url(nonce || ciphertext)>``
    Written in shared mode. ``key_id`` says which master opened it, so an installation can
    hold the key it is moving to and the key it is moving from at the same time.
    That is what makes rotation possible at all, and it is what lets the master
    live somewhere other than a file on this disk -- a KMS, a vault, an OS
    keychain -- because changing where it comes from is changing which key it is.

``sealed:v3:<header>.<wrapped_key>.<ciphertext>``
    RSA-OAEP-SHA256 wraps a random AES-256-GCM key. The header and wrapped key
    are authenticated, including the provider, execution purpose and immutable
    authentication authority. Only the assigned worker holds a private key;
    the API admits credentials with public keys. See :mod:`.isolation`.

``key_id`` is an HKDF output over the master, not a hash of it, so it cannot be
run backwards. It is not a secret: an error that cannot open a credential names
the id it needed, because an operator has to be able to tell *which* key is
missing.
"""

from __future__ import annotations

import base64
import json
import os
import re

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PREFIX = "sealed:"
V1_PREFIX = "sealed:v1:"
V2_PREFIX = "sealed:v2:"
V3_PREFIX = "sealed:v3:"
_INFO = b"cremore/connection-secret/v1"
_INFO_V2 = b"cremore/connection-secret/v2"
_ID_INFO = b"cremore/sealing-key-id/v1"
_ID_LENGTH = 8  # 16 hex characters
_MAX_TOKEN = 8192
# A GitHub App's private key is a PEM in base64, which is larger than any token.
_MAX_FIELD = 32768


class SealedSecretError(ValueError):
    pass


def is_sealed(ref: str | None) -> bool:
    return isinstance(ref, str) and (ref.startswith((V1_PREFIX, V2_PREFIX))
        or bool(re.fullmatch(r"sealed:v3:[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+", ref)))


def public_ref(ref: str | None, *, include_reference: bool = False) -> str | None:
    """What the API serves instead of the ciphertext.

    The version travels because it is not a secret and a reader should not be
    told v1 about a v2 credential.
    """
    if ref is None:
        return None
    if is_sealed(ref):
        return ref[:len(V1_PREFIX) - 1]
    if include_reference:
        # Only an authorized configuration editor needs the external KV path.
        from cremore.secretstore.resolver import SecretRefError, parse_ref
        try:
            parse_ref(ref)
        except SecretRefError:
            pass
        else:
            return ref
    # Old installations may contain values that predate sealed-only admission.
    # A public projection must not repeat that value even if it cannot be read.
    return "configured"


def key_id(master: bytes) -> str:
    """A stable, non-reversible name for one master key."""
    if not master:
        raise SealedSecretError("SEALING_KEY_REQUIRED")
    return HKDF(hashes.SHA256(), _ID_LENGTH, salt=None, info=_ID_INFO).derive(master).hex()


def _cipher(master: bytes | None, info: bytes) -> AESGCM:
    if not master:
        raise SealedSecretError("SEALING_KEY_REQUIRED: a key is needed to store credentials")
    return AESGCM(HKDF(hashes.SHA256(), 32, salt=None, info=info).derive(master))


class SealingKeys:
    """The key new credentials are sealed with, and every key that can open one.

    ``current`` seals. ``previous`` only opens, which is what lets an
    installation move to a new key without re-entering every credential, and
    ``legacy`` opens the v1 format, which carries no key id to look up.
    """

    def __init__(self, current: bytes | None, legacy: bytes | None = None,
                 previous: tuple[bytes, ...] = ()) -> None:
        self.current = current or None
        self.legacy = legacy or None
        self.previous = tuple(key for key in previous if key)
        # Current last so that a key held in more than one slot resolves to the
        # one that seals, which is the one an operator would expect to see named.
        held = [*self.previous, self.legacy, self.current]
        self._by_id: dict[str, bytes] = {key_id(key): key for key in held if key}

    @classmethod
    def of(cls, value) -> SealingKeys:
        """Accept a keyring, raw master bytes, or nothing."""
        if isinstance(value, cls):
            return value
        return cls(value, value)

    @property
    def current_id(self) -> str | None:
        return key_id(self.current) if self.current else None

    def opener(self, wanted: str) -> bytes:
        key = self._by_id.get(wanted)
        if key is None:
            # Naming the id is the point: the operator has to know which key to
            # restore. The id is an HKDF output, not the key.
            raise SealedSecretError(f"SEALING_KEY_NOT_AVAILABLE: {wanted}")
        return key

    def known_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._by_id))


def seal_token(keys, token: str) -> str:
    """Seal a single token. The common case, and the shape v1 could hold."""
    if not isinstance(token, str):
        raise SealedSecretError("token must be a string")
    token = token.strip()
    if not token or len(token) > _MAX_TOKEN or any(ord(c) < 0x20 or ord(c) == 0x7F for c in token):
        raise SealedSecretError("token must be 1-8192 printable characters")
    return seal_fields(keys, {"token": token})


def seal_fields(keys, fields: dict, *, binding=None) -> str:
    """Seal a set of named values under the current key.

    A GitHub App is three values that only mean anything together -- the app id,
    the installation id and the private key -- and an installation with no
    secret store had no way to hold them, so it used a long-lived token instead.
    The envelope was always a JSON object; only ``seal_token`` insisted the
    object have exactly one key called ``token``.
    """
    if not isinstance(fields, dict) or not fields:
        raise SealedSecretError("a stored credential must have at least one field")
    for name, value in fields.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name):
            raise SealedSecretError("field name must be a plain identifier")
        if not isinstance(value, str) or not value or len(value) > _MAX_FIELD:
            raise SealedSecretError(f"{name} must be 1-{_MAX_FIELD} characters")
    from cremore.secretstore.isolation import RecipientKeys

    if isinstance(keys, RecipientKeys):
        if binding is None:
            raise SealedSecretError("CREDENTIAL_BINDING_REQUIRED")
        return keys.seal(fields, binding)
    keys = SealingKeys.of(keys)
    if not keys.current:
        raise SealedSecretError("SEALING_KEY_REQUIRED: a key is needed to store credentials")
    identifier = keys.current_id
    nonce = os.urandom(12)
    # The key id is authenticated with the ciphertext, so it cannot be edited to
    # point at a different key that the installation also holds.
    associated = _INFO_V2 + identifier.encode()
    body = _cipher(keys.current, _INFO_V2).encrypt(nonce, json.dumps(fields).encode(), associated)
    return V2_PREFIX + identifier + ":" + base64.urlsafe_b64encode(nonce + body).decode()


def unseal(keys, ref: str, *, binding=None) -> dict:
    """Open a stored credential, whichever format and key it was written with."""
    if not is_sealed(ref):
        raise SealedSecretError("stored credential is malformed")
    from cremore.secretstore.isolation import RecipientKeys

    if isinstance(keys, RecipientKeys):
        if not ref.startswith(V3_PREFIX):
            raise SealedSecretError("LEGACY_CREDENTIAL_MIGRATION_REQUIRED")
        return keys.open(ref, binding)
    if ref.startswith(V3_PREFIX):
        raise SealedSecretError("CREDENTIAL_PRIVATE_KEY_UNAVAILABLE")
    keys = SealingKeys.of(keys)
    try:
        if ref.startswith(V2_PREFIX):
            identifier, _, payload = ref[len(V2_PREFIX):].partition(":")
            if not re.fullmatch(r"[0-9a-f]{16}", identifier) or not payload:
                raise SealedSecretError("stored credential is malformed")
            master, info = keys.opener(identifier), _INFO_V2
            associated = _INFO_V2 + identifier.encode()
        else:
            # v1 records no key id, so only the key it was written with -- the
            # one derived from FINGERPRINT_KEY -- can open it.
            master, info, associated = keys.legacy or keys.current, _INFO, _INFO
            payload = ref[len(V1_PREFIX):]
        raw = base64.b64decode(payload.encode("ascii"), altchars=b"-_", validate=True)
        data = json.loads(_cipher(master, info).decrypt(raw[:12], raw[12:], associated))
    except SealedSecretError:
        raise
    except (InvalidTag, ValueError, TypeError) as exc:
        raise SealedSecretError(
            "stored credential could not be decrypted; the sealing key changed or data was altered"
        ) from exc
    if not isinstance(data, dict):
        raise SealedSecretError("stored credential is malformed")
    return data
