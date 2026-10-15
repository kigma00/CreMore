"""HashiCorp Vault / OpenBao KV v2 client.

A thin, read-and-write client for the KV v2 secrets engine, used to look up or
publish a managed secret's current value (for example, the value a rotation
promotes). The HTTP client is injected so it is testable without a server, and
so the token is supplied by the deployment rather than assembled here.

KV v2 API: GET/PUT ``{base}/v1/{mount}/data/{path}`` with an ``X-Vault-Token``.
https://openbao.org/api-docs/secret/kv/kv-v2/

An installation that already runs Vault can also keep the master that seals
stored connection credentials there rather than on its own disk; see
``sealing_master`` at the end of this module.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from urllib.parse import quote, urlsplit

from cremore.http_client import bounded_request

_WORKLOAD_JWT_MAX_BYTES = 64 << 10
_VAULT_TOKEN_MAX_CHARS = 64 << 10


class SecretStoreError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def kv_path(value: str) -> str:
    """A bounded logical path; URL quoting belongs at the HTTP boundary."""
    if not isinstance(value, str) or not 1 <= len(value) <= 2048 \
            or any(not ch.isprintable() or ch == "\\" for ch in value):
        raise SecretStoreError("SECRET_STORE_PATH_INVALID")
    path = value.strip("/")
    if any(part in ("", ".", "..") for part in path.split("/")):
        raise SecretStoreError("SECRET_STORE_PATH_INVALID")
    return path


def _base_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        if parsed.scheme in ("http", "https") and parsed.hostname and not (
            parsed.username or parsed.password or parsed.query or parsed.fragment
        ) and all(ch.isprintable() and not ch.isspace() for ch in value):
            return value.rstrip("/")
    except (TypeError, ValueError):
        pass
    raise SecretStoreError("SECRET_STORE_URL_INVALID")


class VaultKubernetesTokenSource:
    """Log in with a projected service-account JWT and cache the leased token."""

    def __init__(
        self,
        client,
        base_url: str,
        role: str,
        *,
        auth_mount: str = "kubernetes",
        token_file: str = "/run/cremore-vault/token",
        namespace: str = "",
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.client = client
        self.base_url = _base_url(base_url)
        self.role = role
        self.auth_mount = quote(kv_path(auth_mount), safe="/")
        self.token_file = token_file
        # An auth mount inside a Vault Enterprise namespace logs in there.
        self.extra = {"headers": {"X-Vault-Namespace": namespace}} if namespace else {}
        self.monotonic = monotonic
        self._token = ""
        self._valid_until = 0.0
        self._refresh_skew = 0.0

    def invalidate(self) -> None:
        self._token = ""
        self._valid_until = 0.0

    def __call__(self) -> str:
        now = self.monotonic()
        if self._token and now + self._refresh_skew < self._valid_until:
            return self._token
        jwt = self._read_jwt()
        try:
            response = bounded_request(
                self.client,
                "POST",
                f"{self.base_url}/v1/auth/{self.auth_mount}/login",
                json={"role": self.role, "jwt": jwt},
                max_response_bytes=1 << 20,
                timeout=10.0,
                follow_redirects=False,
                **self.extra,
            )
        except Exception:  # noqa: BLE001 - HTTP adapters expose provider-specific errors
            raise SecretStoreError("SECRET_STORE_AUTH_UNREACHABLE") from None
        status = getattr(response, "status_code", 0)
        if status in (400, 401, 403):
            raise SecretStoreError("SECRET_STORE_AUTH_REJECTED")
        if status != 200:
            raise SecretStoreError("SECRET_STORE_AUTH_UNAVAILABLE")
        try:
            auth = response.json()["auth"]
            token = auth["client_token"]
            lease = int(auth["lease_duration"])
        except (KeyError, TypeError, ValueError):
            raise SecretStoreError("SECRET_STORE_AUTH_MALFORMED") from None
        if (
            not isinstance(token, str)
            or not token
            or len(token) > _VAULT_TOKEN_MAX_CHARS
            or any(ch.isspace() or not ch.isprintable() for ch in token)
            or lease <= 0
        ):
            raise SecretStoreError("SECRET_STORE_AUTH_MALFORMED")
        self._token = token
        self._valid_until = now + lease
        self._refresh_skew = min(60.0, lease / 2)
        return token

    def _read_jwt(self) -> str:
        try:
            with open(self.token_file, "rb") as handle:
                raw = handle.read(_WORKLOAD_JWT_MAX_BYTES + 1)
        except OSError:
            raise SecretStoreError("SECRET_STORE_WORKLOAD_TOKEN_UNAVAILABLE") from None
        if not raw or len(raw) > _WORKLOAD_JWT_MAX_BYTES:
            raise SecretStoreError("SECRET_STORE_WORKLOAD_TOKEN_INVALID")
        try:
            token = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            raise SecretStoreError("SECRET_STORE_WORKLOAD_TOKEN_INVALID") from None
        if not token or any(ch.isspace() for ch in token):
            raise SecretStoreError("SECRET_STORE_WORKLOAD_TOKEN_INVALID")
        return token


class VaultKV:
    def __init__(self, client, base_url: str, token: str | Callable[[], str], *, mount: str = "secret", timeout: float = 10.0) -> None:
        self.client = client
        self.base_url = _base_url(base_url)
        self.token = token
        self.mount = quote(kv_path(mount), safe="/")
        self.timeout = timeout

    def _url(self, path: str) -> str:
        return f"{self.base_url}/v1/{self.mount}/data/{quote(kv_path(path), safe='/')}"

    def _headers(self) -> dict[str, str]:
        token = self.token() if callable(self.token) else self.token
        if not isinstance(token, str) or not 1 <= len(token) <= _VAULT_TOKEN_MAX_CHARS \
                or any(ch.isspace() or not ch.isprintable() for ch in token):
            raise SecretStoreError("SECRET_STORE_AUTH_UNAVAILABLE")
        return {"X-Vault-Token": token}

    def _request(self, method: str, path: str, **kwargs):
        for attempt in range(2):
            try:
                response = bounded_request(
                    self.client,
                    method,
                    path,
                    headers=self._headers(),
                    timeout=self.timeout,
                    follow_redirects=False,
                    **kwargs,
                )
            except SecretStoreError:
                raise
            except Exception:  # noqa: BLE001 - HTTP adapters expose provider-specific errors
                raise SecretStoreError("SECRET_STORE_UNREACHABLE") from None
            if getattr(response, "status_code", 500) != 403 or attempt:
                return response
            invalidate = getattr(self.token, "invalidate", None)
            if not callable(invalidate):
                return response
            invalidate()
        raise SecretStoreError("SECRET_STORE_FORBIDDEN")  # pragma: no cover

    def read(self, path: str, *, version: int | None = None) -> dict:
        """Return the secret's data map. Raises SecretStoreError on failure."""

        url = self._url(path)
        params = {"version": str(version)} if version is not None else None
        resp = self._request("GET", url, params=params)
        status = getattr(resp, "status_code", 500)
        if status == 404:
            raise SecretStoreError("SECRET_NOT_FOUND")
        if status == 403:
            raise SecretStoreError("SECRET_STORE_FORBIDDEN")
        if status != 200:
            raise SecretStoreError(f"SECRET_STORE_HTTP_{status}")
        try:
            data = resp.json()["data"]["data"]
        except (KeyError, TypeError, ValueError):
            raise SecretStoreError("SECRET_STORE_MALFORMED") from None
        if not isinstance(data, dict):
            raise SecretStoreError("SECRET_STORE_MALFORMED")
        return data

    def write(self, path: str, data: dict) -> int:
        """Write a new version of the secret; returns the new version number."""

        resp = self._request("POST", self._url(path), json={"data": data})
        status = getattr(resp, "status_code", 500)
        if status == 403:
            raise SecretStoreError("SECRET_STORE_FORBIDDEN")
        if status not in (200, 204):
            raise SecretStoreError(f"SECRET_STORE_HTTP_{status}")
        try:
            return int(resp.json()["data"]["version"])
        except (KeyError, TypeError, ValueError):
            return 0


def kv_from_settings(settings, client=None) -> VaultKV:
    """A KV client wired the way the deployment configured one.

    The worker keeps its client for the life of the process; a caller that only
    needs one read passes its own and closes it.
    """
    if client is None:
        import httpx

        client = httpx.Client(timeout=10.0)
    token = settings.secret_store_token
    if settings.secret_store_auth_mode == "kubernetes":
        token = VaultKubernetesTokenSource(
            client,
            settings.secret_store_url,
            settings.secret_store_kubernetes_role,
            auth_mount=settings.secret_store_kubernetes_auth_mount,
            token_file=settings.secret_store_kubernetes_token_file,
        )
    return VaultKV(client, settings.secret_store_url, token, mount=settings.secret_store_mount)


def sealing_master(kv: VaultKV, path: str, field: str = "key") -> bytes:
    """The master that seals stored credentials, held at one KV path.

    An installation that already runs Vault can keep the master there instead of
    on this disk: the process authenticates as its workload (Kubernetes auth) or
    with a token scoped to this one path, and nothing long-lived is written
    beside it. Rotating means writing a new value and leaving the old path in
    ``SEALING_KEY_VAULT_PATH_PREVIOUS``, which opens stored credentials but
    seals no new one.
    """
    data = kv.read(path.strip("/"))
    value = data.get(field) if isinstance(data, dict) else None
    if not isinstance(value, str) or not value.strip():
        raise SecretStoreError("SEALING_KEY_VAULT_FIELD_MISSING")
    try:
        master = bytes.fromhex(value.strip())
    except ValueError:
        raise SecretStoreError("SEALING_KEY_VAULT_FIELD_NOT_HEX") from None
    if len(master) < 32:
        # A short master is worse than a loud failure: every stored credential
        # would be sealed under it.
        raise SecretStoreError("SEALING_KEY_VAULT_KEY_TOO_SHORT: at least 32 bytes are required")
    return master
