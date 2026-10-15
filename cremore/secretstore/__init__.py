"""Optional external secret store integration (Apache-2.0)."""

from cremore_vault_provider.secretstore import SecretStoreError, VaultKubernetesTokenSource, VaultKV

from cremore.secretstore.resolver import SecretRefError, SecretResolver, inject_secret, parse_ref

__all__ = [
    "SecretRefError",
    "SecretResolver",
    "SecretStoreError",
    "VaultKV",
    "VaultKubernetesTokenSource",
    "inject_secret",
    "parse_ref",
]
