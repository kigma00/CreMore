"""Resolve a GitHub host to its REST API base and web base.

A discovered GitHub token carries no host, so verification, capability probing
and the "open original" link all need to be told which GitHub the token and the
scanned repository belong to. The host comes from the connection being scanned
(``config.github_host``), never from scanned content.

* github.com (Enterprise Cloud, the default): API ``https://api.github.com``,
  web ``https://github.com``.
* GitHub Enterprise Server (self-hosted): API ``https://HOST/api/v3``, web
  ``https://HOST``.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

_HOST = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9]([a-z0-9-]{0,62}))+$")
PUBLIC_API = "https://api.github.com"
PUBLIC_WEB = "https://github.com"


def normalize_host(value: str | None) -> str:
    """The bare hostname of an operator-supplied GitHub host, or "" for github.com.

    Rejects anything that is not a plain https host (no path, port, credentials);
    raises ``ValueError`` so a bad connection config fails closed rather than
    letting the verifier call an arbitrary URL.
    """
    raw = str(value or "").strip()
    if not raw:
        return ""
    parts = urlsplit(raw if "://" in raw else f"https://{raw}")
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or parts.username or parts.password or parts.port not in (None, 443):
        raise ValueError("GITHUB_HOST_MUST_BE_PLAIN_HTTPS")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("GITHUB_HOST_MUST_NOT_INCLUDE_A_PATH")
    if not _HOST.fullmatch(host):
        raise ValueError("GITHUB_HOST_INVALID")
    if host in ("github.com", "api.github.com", "www.github.com"):
        return ""
    if host.startswith("api.") and host.endswith(".ghe.com"):
        return host[4:]
    return host


def api_base(host: str | None) -> str:
    normalized = normalize_host(host)
    if normalized.endswith(".ghe.com"):
        return f"https://api.{normalized.removeprefix('api.')}"
    return PUBLIC_API if not normalized else f"https://{normalized}/api/v3"


def web_base(host: str | None) -> str:
    normalized = normalize_host(host)
    return PUBLIC_WEB if not normalized else f"https://{normalized}"


def is_public(host: str | None) -> bool:
    return not normalize_host(host)


def host_from_api_base(api: str) -> str:
    """Bare host for an API base built by :func:`api_base` ("" for github.com)."""
    if not api or api == PUBLIC_API:
        return ""
    host = api.removeprefix("https://").split("/", 1)[0].lower()
    if host.startswith("api.") and host.endswith(".ghe.com"):
        return host[4:]
    return "" if host in ("github.com", "api.github.com") else host if _HOST.fullmatch(host) else ""
