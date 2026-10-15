"""Azure Key Vault secret metadata for the shared coverage runtime.

Default collection lists secret properties. Explicit ``vault_value`` and
``include_values`` enable passive value fingerprinting without raw storage.
The original native adapter mapped Key Vault's
``updated_on`` to ``last_rotated_at``. ``updated_on`` is the last time any
property of the secret changed -- a tag edit, an enable, a new expiry -- so
that mapping reports a rotation that did not happen. Nothing here writes
``last_rotated_at``; the shared fact allowlist does not contain the name.

What can be said about rotation is said from versions: a secret's versions are
the times a new value was actually set. What cannot be said is reported as a
reason rather than filled in from a tag, because a tag is an operator's own
declaration and not the provider's state.
"""

SOURCE_COMMIT = "9668d97bac78c6574cda9cfd0b2753c7eae4bb2b"
# The data-plane API version this package's response grammar is written against.
API_VERSION = "2025-07-01"
CONTRACT_VERSION = "azure_key_vault.1"
