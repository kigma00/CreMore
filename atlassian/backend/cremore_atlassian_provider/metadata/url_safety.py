"""Prevent URL-carried credentials from entering common metadata or machine batches."""

import re
from urllib.parse import parse_qsl, urlsplit

from .snapshot import secret_name

_URL = re.compile(r"(?i)(?:\b[a-z][a-z0-9+.-]*://|(?<![:\w])//)[^\s<>\"']+")
_SIGNED_FIELDS = {
    "sig",
    "signature",
    "credential",
    "xamzsignature",
    "xamzcredential",
    "awsaccesskeyid",
    "authorization",
    "auth",
}


def unsafe_url(value):
    if not isinstance(value, str):
        return False
    for match in _URL.finditer(value):
        try:
            parsed = urlsplit(match.group())
            if parsed.username is not None or parsed.password is not None:
                return True
            for component in (parsed.query, parsed.fragment):
                for name, _ in parse_qsl(component, keep_blank_values=True, max_num_fields=256):
                    compact = re.sub(r"[^a-z0-9]", "", name.lower())
                    if secret_name(name) or compact in _SIGNED_FIELDS:
                        return True
        except ValueError:
            return True
    return False


def contains_unsafe_url(value):
    if isinstance(value, dict):
        return any(unsafe_url(key) or contains_unsafe_url(child) for key, child in value.items())
    if isinstance(value, list):
        return any(contains_unsafe_url(child) for child in value)
    return unsafe_url(value)
