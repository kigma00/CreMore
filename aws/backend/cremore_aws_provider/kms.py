"""The sealing master held by AWS KMS instead of by this disk.

What sits in the environment is a KMS ciphertext: a 32-byte data key encrypted
under a customer master key. A copy of ``.env`` or of the database is useless on
its own, because turning the ciphertext back into the master needs
``kms:Decrypt`` on that CMK -- granted to the workload identity this process
already runs as (an EC2 instance profile, an ECS task role, EKS IRSA, or an
operator's ``aws sso login`` session), never to a file kept next to it.

Produce one without the plaintext key ever existing outside KMS::

    aws kms generate-data-key-without-plaintext \
      --key-id <cmk> --key-spec AES_256 --query CiphertextBlob --output text

That value goes in ``SEALING_KEY_CIPHERTEXT``, and the CMK in
``SEALING_KMS_KEY_ID``. The CMK is named rather than left to the ciphertext to
say which key is expected, so a blob swapped for one encrypted under a different
CMK is refused by KMS instead of quietly opening.

Rotating means generating another and moving the old ciphertext into
``SEALING_KEY_CIPHERTEXT_PREVIOUS``, which opens stored credentials but seals no
new one. The key identifier in each ``sealed:v2:`` reference is what makes that
work: see :mod:`cremore.secretstore.sealed`.
"""

from __future__ import annotations

import base64
import binascii
import re

MIN_KEY_BYTES = 32
_KEY_ARN_REGION = re.compile(r"^arn:aws[a-z0-9-]*:kms:([a-z0-9-]+):")


class SealingKmsError(ValueError):
    """The sealing master could not be recovered from KMS."""


def decode(ciphertext: str) -> bytes:
    """The stored ciphertext as bytes. Checked without calling AWS."""
    try:
        return base64.b64decode(ciphertext.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SealingKmsError(
            "SEALING_KEY_CIPHERTEXT_MALFORMED: expected the base64 CiphertextBlob "
            "that kms generate-data-key-without-plaintext prints") from exc


def region_of(key_id: str, fallback: str | None = None) -> str | None:
    """The region a key ARN names, falling back for a bare id or an alias."""
    match = _KEY_ARN_REGION.match(key_id or "")
    return match[1] if match else fallback


def master(ciphertext: str, key_id: str, region: str | None = None, client=None) -> bytes:
    """Ask KMS to turn one stored ciphertext back into its master key.

    Called when a credential is sealed or a worker starts, not per scan, so it
    is left uncached: a stale master would be harder to reason about than the
    occasional call.
    """
    from cremore_aws_provider.aws_identity import error_code
    from cremore_aws_provider.aws_readonly import readonly_client

    blob = decode(ciphertext)
    if not key_id.strip():
        raise SealingKmsError("SEALING_KMS_KEY_ID is required to open SEALING_KEY_CIPHERTEXT")
    if client is None:
        import boto3

        client = boto3.Session().client("kms", region_name=region or region_of(key_id))
    # Read-only wrapped like every other scanner client: this path can call
    # Decrypt and nothing else, whatever the workload identity is allowed.
    client = readonly_client(client, "kms")
    try:
        result = client.decrypt(CiphertextBlob=blob, KeyId=key_id.strip())
    except Exception as exc:  # noqa: BLE001 -- an SDK error can carry request detail; report a fixed code.
        raise SealingKmsError(f"SEALING_KMS_DECRYPT_FAILED: {error_code(exc)}") from None
    plaintext = result.get("Plaintext") if isinstance(result, dict) else None
    if not isinstance(plaintext, bytes | bytearray) or len(plaintext) < MIN_KEY_BYTES:
        # A CMK that opened something other than a data key. Refuse rather than
        # seal every stored credential under a short or empty master.
        raise SealingKmsError(
            f"SEALING_KMS_RETURNED_UNUSABLE_KEY: at least {MIN_KEY_BYTES} bytes are required")
    return bytes(plaintext)
