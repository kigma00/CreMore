"""A connection's own login to a Vault/OpenBao cluster the worker reads directly.

The installation's secret-store identity is never used for such a connection
(design decision 10). Kubernetes and JWT logins read one token file the
deployment mounted for this connection under ``VAULT_CONNECTION_TOKEN_DIR`` --
the connection names a file, so it cannot point the login at an arbitrary path,
and the installation's own login token is refused outright. A token login opens
the value sealed on arrival. TLS is verified, with the connection's CA when it
carries one, and redirects are never followed.
"""

from __future__ import annotations

import os
import ssl

from .secretstore import SecretStoreError, VaultKubernetesTokenSource


class ConnectionLoginError(SecretStoreError):
    pass


def _inside(directory: str, path: str) -> bool:
    try:
        return os.path.commonpath([directory, path]) == directory
    except ValueError:
        return False


def tls_verify(spec):
    """A context trusting only the connection's CA when it names one."""
    return ssl.create_default_context(cadata=spec.tls_ca_pem) if spec.tls_ca_pem else True


def connection_token(spec, client, *, token_dir: str, install_token_file: str = "", resolver=None):
    """Return a token or a refreshing token source for this connection alone."""
    auth = spec.server_auth
    if auth is None:
        raise ConnectionLoginError("VAULT_CONNECTION_LOGIN_NOT_CONFIGURED")
    if auth.method == "token":
        ref = spec.secret_refs.get("vault_token")
        if not ref or resolver is None:
            raise ConnectionLoginError("VAULT_CONNECTION_TOKEN_UNAVAILABLE")
        try:
            token = resolver.resolve(ref).get("token")
        except Exception:  # noqa: BLE001 -- a backend error can carry the resolved value.
            token = None
        if not isinstance(token, str) or not token or any(ch.isspace() for ch in token):
            raise ConnectionLoginError("VAULT_CONNECTION_TOKEN_UNAVAILABLE")
        return token
    if not token_dir:
        raise ConnectionLoginError("VAULT_CONNECTION_TOKEN_DIR_NOT_CONFIGURED")
    directory = os.path.realpath(token_dir)
    # Kubernetes projects tokens through symlinks inside the same volume, so
    # the resolved file must stay inside the directory, not beside it.
    path = os.path.realpath(os.path.join(directory, auth.token_file))
    if not _inside(directory, path):
        raise ConnectionLoginError("VAULT_CONNECTION_TOKEN_FILE_OUTSIDE_DIRECTORY")
    if install_token_file and path == os.path.realpath(install_token_file):
        raise ConnectionLoginError("VAULT_CONNECTION_TOKEN_FILE_REFUSED")
    return VaultKubernetesTokenSource(client, spec.endpoint, auth.role, auth_mount=auth.mount,
                                      token_file=path, namespace=auth.namespace)
