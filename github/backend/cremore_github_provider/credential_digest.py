"""Passive, installation-keyed comparison with GitHub's documented token hash."""

import hashlib
import hmac

SCHEME = "github-token-sha256/hmac-sha256-v1"
DOMAIN = b"cremore/github-token-sha256/v1\x00"


def comparison_fingerprint(provider_digest: bytes, key: bytes) -> str:
    if not isinstance(provider_digest, bytes) or len(provider_digest) != 32:
        raise ValueError("GITHUB_INVALID_PROVIDER_DIGEST")
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("GITHUB_COMPARISON_KEY_REQUIRED")
    return hmac.new(key, DOMAIN + provider_digest, hashlib.sha256).hexdigest()


def token_fingerprint(token: bytes, key: bytes) -> str:
    """Hash exact observed bytes without authenticating or retaining the token."""
    return comparison_fingerprint(hashlib.sha256(token).digest(), key)
