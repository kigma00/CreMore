"""Resolve connection credentials and dispatch read-only identity checks."""
from __future__ import annotations

from cremore_aws_provider.credential_check import check_s3
from cremore_github_provider.credential_check import check_github
from cremore_notion_provider.credential_check import check_notion

from cremore.collectors.credential_result import ACTIVE, INDETERMINATE, REJECTED, CredentialCheck

__all__ = [
    "ACTIVE", "INDETERMINATE", "REJECTED", "CredentialCheck",
    "check_github", "check_notion", "check_s3", "run_credential_check",
]


def run_credential_check(payload: dict, *, http_client_factory=None, s3_client_factory=None,
                         sts_client_factory=None, secret_resolver=None) -> CredentialCheck:
    """Dispatch a ``credential-check`` job payload to the provider check.

    ``payload`` carries the connection's provider and non-secret scope plus its
    ``secret_ref``; the token is resolved here and never persisted.
    """

    from cremore.secretstore.resolver import SecretRefError, inject_secret
    from cremore.sources.registry import PROVIDERS

    provider = str(payload.get("provider", "")).lower()
    source = PROVIDERS.get(provider)
    if source is None:
        raise ValueError(f"unsupported provider for credential check: {provider!r}")
    resolved = payload
    if source.TOKEN_AUTH:
        if http_client_factory is None:
            raise ValueError(f"{provider} credential check requires an http client factory")
        try:
            resolved = inject_secret(
                provider,
                payload,
                secret_resolver,
                github_client_factory=http_client_factory,
            )
        except SecretRefError:
            return CredentialCheck(REJECTED, error="SECRET_UNAVAILABLE")
    return source.check_credential(
        resolved,
        http_client_factory=http_client_factory,
        s3_client_factory=s3_client_factory,
        sts_client_factory=sts_client_factory,
    )
