# Adapted from publish/develop_atlassian 49abdc11a998f61917e151ab276e84c7a21815ea (atlassian_collector/snapshot.py).
"""Preserve provider metadata before field selection; omit secret-bearing fields."""

import math
import re

REDACTED = {"_cremore_omitted": "sensitive_value"}
SECRET_NAMES = {
    "token",
    "apitoken",
    "apikey",
    "key",
    "authorization",
    "proxyauthorization",
    "cookie",
    "setcookie",
    "credentials",
    "credential",
    "password",
    "passwd",
    "secret",
    "clientsecret",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "privatekey",
    "signingkey",
    "secretkey",
    "tokenvalue",
    "keyvalue",
    "credentialvalue",
    "clientassertion",
    "assertion",
    "jwt",
    "authorizationcode",
}
JWK_SECRET_PARAMETERS = frozenset(("d", "p", "q", "dp", "dq", "qi", "oth", "k"))


def secret_name(name):
    compact = re.sub(r"[^a-z0-9]", "", name.lower())
    return (
        compact in SECRET_NAMES
        or "password" in compact
        or "privatekey" in compact
        or "clientsecret" in compact
        or compact.endswith(("secret", "secretvalue", "accesstoken", "token", "keyvalue"))
    )


def metadata_snapshot(
    value, *, sensitive_values=(), max_nodes=100000, max_depth=32, reason_codes=()
):
    """Retain JSON names/types/values without coercion; report omissions explicitly.

    Field names and free text remain untrusted. This is not a guarantee that every
    possible secret can be detected: output stays private and never goes to stdout.
    """
    stats = {"secret_fields_omitted": 0, "sensitive_values_omitted": 0, "truncated_nodes": 0}
    remaining = max_nodes

    def visit(item, depth, parent_name=None):
        nonlocal remaining
        if remaining <= 0 or depth > max_depth:
            stats["truncated_nodes"] += 1
            return {"_cremore_omitted": "snapshot_limit"}
        remaining -= 1
        if isinstance(item, dict):
            out = {}
            jwk = "kty" in item or parent_name == "keys"
            for index, (name, child) in enumerate(item.items()):
                if remaining <= 0:
                    omitted = len(item) - index
                    stats["truncated_nodes"] += omitted
                    marker = "_cremore_omitted_tail"
                    while marker in item:
                        marker += "_"
                    out[marker] = {"_cremore_omitted": "snapshot_limit", "entries": omitted}
                    break
                if not isinstance(name, str):
                    remaining -= 1
                    stats["truncated_nodes"] += 1
                    continue
                if any(secret and secret in name for secret in sensitive_values):
                    remaining -= 1
                    stats["sensitive_values_omitted"] += 1
                    continue
                documented_reason = (
                    parent_name == "reason"
                    and name == "key"
                    and isinstance(child, str)
                    and child in reason_codes
                )
                if (secret_name(name) and not documented_reason) or (
                    jwk and name in JWK_SECRET_PARAMETERS
                ):
                    remaining -= 1
                    # Keep the field name and omission state, never its value.
                    out[name] = dict(REDACTED)
                    stats["secret_fields_omitted"] += 1
                else:
                    out[name] = visit(child, depth + 1, name)
            return out
        if isinstance(item, list):
            out = []
            for index, child in enumerate(item):
                if remaining <= 0:
                    omitted = len(item) - index
                    stats["truncated_nodes"] += omitted
                    out.append({"_cremore_omitted": "snapshot_limit", "entries": omitted})
                    break
                out.append(visit(child, depth + 1, parent_name))
            return out
        if isinstance(item, str):
            if (
                any(secret and secret in item for secret in sensitive_values)
                or "PRIVATE KEY-----" in item
                or "PGP PRIVATE KEY BLOCK" in item
                or re.match(r"(?i)^\s*(bearer|basic)\s+\S+", item)
            ):
                stats["sensitive_values_omitted"] += 1
                return dict(REDACTED)
            return item
        if (
            item is None
            or type(item) in (bool, int)
            or (type(item) is float and math.isfinite(item))
        ):
            return item
        stats["truncated_nodes"] += 1
        return {"_cremore_omitted": "unsupported_json_value"}

    return visit(value, 0), stats


def field_catalog(value):
    """Private field/type catalog without sample values; preserve array boundaries."""
    found = {}

    def visit(item, path):
        kind = "null" if item is None else type(item).__name__
        found.setdefault(path, set()).add(kind)
        if isinstance(item, dict):
            for name, child in item.items():
                # Escape JSON Pointer delimiters so keys cannot collide.
                visit(child, path + "/" + name.replace("~", "~0").replace("/", "~1"))
        elif isinstance(item, list):
            for child in item:
                visit(child, path + "/[]")

    visit(value, "")
    return {path: sorted(kinds) for path, kinds in sorted(found.items())}
