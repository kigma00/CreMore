"""Existing endpoint, path and common enterprise-source configuration rules."""

from urllib.parse import urlsplit


def https_base(value):
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 33 for c in value):
        raise ValueError("INVALID_PROVIDER_ENDPOINT")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
            or any(part in (".", "..") for part in parsed.path.split("/")) or "%" in parsed.path or "\\" in value):
        raise ValueError("HTTPS_PROVIDER_ENDPOINT_REQUIRED")
    return value.rstrip("/")


def path(value, *, literal=False):
    if not isinstance(value, str) or len(value) > 1024 or any(ord(c) < 32 for c in value) or "\\" in value or any(p in (".", "..") for p in value.split("/")):
        raise ValueError("INVALID_SOURCE_PATH")
    return value if literal else value.strip("/")


def enterprise_fields(value, allowed, *, literal_paths=False):
    if not isinstance(value, dict):
        raise ValueError("UNSUPPORTED_PROVIDER")  # noqa: TRY004 -- preserve the public config error contract.
    allowed = set(allowed) | {"prefixes", "paths", "excluded_paths", "excluded_prefixes", "max_requests", "max_objects", "declaration"}
    if value.keys() - allowed:
        raise ValueError("UNSUPPORTED_SOURCE_CONFIG_FIELD")
    out = dict(value)
    for key in ("prefixes", "paths", "excluded_prefixes", "excluded_paths"):
        if key in out:
            if not isinstance(out[key], list) or len(out[key]) > 100:
                raise ValueError("INVALID_PATH_SCOPE")
            out[key] = [path(v, literal=literal_paths) for v in out[key]]
    for key in ("max_requests", "max_objects"):
        if key in out and (type(out[key]) is not int or not 1 <= out[key] <= 100000):
            raise ValueError("INVALID_SOURCE_LIMIT")
    return out
