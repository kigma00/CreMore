"""Private provider-hash evidence, distinct from the credential HMAC contract.

GitHub returns standard Base64 SHA-256 in ``hashed_token``. Decode it only in
memory and immediately key it for this installation; the vendor hash is never
put in facts, checkpoints, native exports or ordinary API responses.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re

from cremore.coverage.metadata_models import MetadataValueMatch
from cremore_github_provider.credential_digest import SCHEME, comparison_fingerprint

TOKEN_TYPES = frozenset({"classic_pat", "fine_grained_pat", "oauth_app_user_token", "github_app_user_token"})


def provider_sha256(value):
    if not isinstance(value, str) or len(value) != 44:
        raise ValueError("GITHUB_INVALID_PROVIDER_DIGEST")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("GITHUB_INVALID_PROVIDER_DIGEST") from None
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("GITHUB_INVALID_PROVIDER_DIGEST")
    return decoded


def context_key(context):
    try:
        key = context["engine"].config.fingerprint_key
        if (not isinstance(key, bytes) or len(key) < 32
                or context["key_id"] != hashlib.sha256(key).hexdigest()):
            raise ValueError
        for field in ("engine_digest", "policy_digest"):
            if not isinstance(context[field], str) or not re.fullmatch(r"[0-9a-f]{64}", context[field]):
                raise ValueError
    except (KeyError, TypeError, AttributeError, ValueError):
        raise ValueError("GITHUB_COMPARISON_CONTEXT_REQUIRED") from None
    return key


def keyed(value, context):
    """The installation-keyed form of one GitHub ``hashed_token``."""
    return comparison_fingerprint(provider_sha256(value), context_key(context))


def value_match(row, reference, context, *, observed_at):
    if row.get("hashed_token") is None:
        return None
    if row.get("item_type") != "credential" or row.get("credential_type") not in TOKEN_TYPES:
        raise ValueError("GITHUB_INVALID_PROVIDER_DIGEST")
    return match(keyed(row["hashed_token"], context), reference, context, observed_at=observed_at)


def match(fingerprint, reference, context, *, observed_at):
    return MetadataValueMatch(
        evidence="PROVIDER_DIGEST", reference=reference, credential_type="GITHUB_TOKEN",
        fingerprint=fingerprint, scheme=SCHEME, key_id=context["key_id"], material_kind="credential",
        engine_digest=context["engine_digest"], policy_digest=context["policy_digest"], read_at=observed_at,
    )
