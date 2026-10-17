"""Optional external secret store integration (Apache-2.0)."""

from cremore.secretstore.resolver import SecretRefError, SecretResolver, inject_secret, parse_ref
from cremore.secretstore.vault import SecretStoreError, VaultKubernetesTokenSource, VaultKV

__all__ = [
    "SecretRefError",
    "SecretResolver",
    "SecretStoreError",
    "VaultKV",
    "VaultKubernetesTokenSource",
    "inject_secret",
    "parse_ref",
]
