"""Resolve a connection's ``secret_ref`` to its secret data at scan time.

A connection stores either a pointer (``vault://<path>``) resolved against the
secret store, or a token sealed by CreMore (``sealed:v1:…`` / ``sealed:v2:…``, see
:mod:`cremore.secretstore.sealed`). The worker resolves it just before building a
collector; the plaintext stays in memory for the scan and is never written back
to the repository or served by the API.
"""

from __future__ import annotations

from cremore.secretstore.sealed import SealedSecretError, is_sealed, unseal
from cremore.secretstore.vault import SecretStoreError, VaultKV, kv_path
from cremore.sources.registry import TOKEN_KINDS

_SCHEME = "vault://"


class SecretRefError(ValueError):
    pass


def parse_ref(ref: str) -> str:
    """Return the KV path from a ``vault://<path>`` reference."""

    if not isinstance(ref, str) or not ref.startswith(_SCHEME):
        raise SecretRefError("secret_ref must use vault://<path>")
    try:
        return kv_path(ref[len(_SCHEME):])
    except SecretStoreError:
        raise SecretRefError("secret_ref has an invalid path") from None


class SecretResolver:
    """Opens sealed tokens, and reads ``vault://`` references when a store is wired."""

    def __init__(self, kv: VaultKV | None = None, sealing_key=None, *, binding=None) -> None:
        """``sealing_key`` is a SealingKeys ring, or one master's bytes."""
        self.kv = kv
        self.sealing_key = sealing_key
        self.binding = binding

    def bound(self, binding):
        return SecretResolver(self.kv, self.sealing_key, binding=binding)

    def resolve(self, ref: str, *, binding=None) -> dict:
        from cremore.secretstore.isolation import RecipientKeys

        if is_sealed(ref):
            data = unseal(self.sealing_key, ref, binding=binding or self.binding)
            if set(data) != {"vault_ref"}:
                return data
            ref = data["vault_ref"]
        elif isinstance(self.sealing_key, RecipientKeys):
            # The API may write DB references but must not select arbitrary Vault paths.
            raise SecretRefError("LEGACY_CREDENTIAL_MIGRATION_REQUIRED")
        path = parse_ref(ref)
        if self.kv is None:
            raise SecretRefError("vault:// reference but no SECRET_STORE_URL is configured")
        return self.kv.read(path)


def inject_secret(
    kind: str,
    payload: dict,
    resolver: SecretResolver | None,
    *,
    github_client_factory=None,
    http_client_factory=None,
) -> dict:
    """Return a payload copy with the resolved secret merged in for this job kind.

    Only provider kinds that authenticate with a per-connection token
    get a ``token`` injected; S3 uses the scanner's own AWS
    identity, so it needs no secret here. A payload without a ``secret_ref``, or
    one that already carries an explicit ``token``, is returned unchanged.
    """

    ref = payload.get("secret_ref")
    if not ref or resolver is None or payload.get("token"):
        return payload
    if kind not in TOKEN_KINDS:
        return payload
    try:
        data = resolver.resolve(ref)
    except (SecretStoreError, SealedSecretError):
        raise SecretRefError("could not resolve secret_ref: SECRET_REF_RESOLUTION_FAILED") from None
    if not isinstance(data, dict):
        raise SecretRefError("SECRET_REF_DATA_INVALID")
    github = (
        kind in ("github", "github-org")
        or payload.get("provider") == "github"
        or payload.get("source_type") == "github"
    )
    app_fields = (
        data.get("GITHUB_APP_ID"),
        data.get("GITHUB_APP_INSTALLATION_ID"),
        data.get("GITHUB_APP_PRIVATE_KEY_BASE64"),
    )
    token = None
    if github and all(app_fields):
        if github_client_factory is None:
            raise SecretRefError("GitHub App authentication has no HTTP client")
        from cremore_github_provider.github_auth import GitHubAppTokenSource, GitHubAuthError

        # Mint the installation token against the connection's own host. The
        # payload already carries base_url = api_base(github_host); without it an
        # enterprise (GHES) App would issue tokens against api.github.com.
        base_url = payload.get("base_url")
        host_kwargs = {"base_url": base_url} if base_url else {}
        try:
            # Scans only read: the token holds read access whatever else the App may do.
            token = GitHubAppTokenSource(github_client_factory, *app_fields, read_only=True,
                                        organization=payload.get("app_organization"), **host_kwargs)
        except GitHubAuthError as exc:
            raise SecretRefError(f"invalid GitHub App secret: {exc.code}") from exc
    if token is None:
        token = data.get("token") or data.get("access_token")
        if not isinstance(token, str) or not 1 <= len(token) <= 32768 \
                or any(not ch.isprintable() or ch.isspace() for ch in token):
            raise SecretRefError("SECRET_REF_TOKEN_INVALID")
    if not token:
        raise SecretRefError("secret has no supported credential fields")
    merged = dict(payload)
    merged["token"] = token
    return merged
