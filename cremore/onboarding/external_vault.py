"""Vaults CreMore has no built-in collector for, in the connection wizard (docs/EXTERNAL_VAULT.md).

The customer's environment reads the vault with the CreMore CLI -- from the JSON
Lines export the vault's own tool writes, or with an installed reader plugin -- and
sends only fingerprints. CreMore holds no credential for it, so the CLI reports what
it could read when it uploads.
"""

from __future__ import annotations

import re

_READER = re.compile(r"[a-z][a-z0-9_-]{0,63}")

DESCRIPTORS = [{
    "provider": "external_vault",
    "label": "Other vault", "label_ko": "기타 금고",
    "category": "vault",
    "editions": [{"id": "self_managed", "label": "Any vault", "label_ko": "모든 금고"}],
    "target": [
        {"name": "product", "label": "Product", "label_ko": "제품", "kind": "text", "required": True,
         "hint": "CyberArk, 1Password, Doppler"},
        {"name": "prefixes", "label": "Declared path prefixes", "label_ko": "선언 경로 접두어", "kind": "list",
         "required": True, "hint": "prod/, shared/"},
    ],
    "purposes": {"vault": {"permissions": [
        {"id": "read_items", "label": "Read the declared items", "label_ko": "선언한 항목 읽기"}]}},
    "auth_methods": [
        {"id": "jsonl", "label": "JSON Lines export through the CreMore CLI", "label_ko": "CreMore CLI로 JSON Lines 내보내기",
         "renewal": "NONE", "purposes": ["vault"], "fields": []},
        {"id": "reader", "label": "Reader plugin in the CreMore CLI", "label_ko": "CreMore CLI의 읽기 플러그인",
         "renewal": "NONE", "purposes": ["vault"],
         "fields": [{"name": "reader", "label": "Reader", "label_ko": "읽기 플러그인", "kind": "text", "public": True}]},
    ],
}]


class OnboardingValueError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def target(provider, edition, values):
    from cremore.coverage.models import scope_path

    try:
        prefixes = [scope_path(prefix) for prefix in values.get("prefixes") or []]
    except ValueError:
        raise OnboardingValueError("EXTERNAL_VAULT_PREFIX_INVALID") from None
    if not prefixes:
        raise OnboardingValueError("EXTERNAL_VAULT_DECLARED_SCOPE_REQUIRED")
    return {"product": values["product"], "prefixes": prefixes}


def credential(provider, method, fields):
    if method == "reader" and not _READER.fullmatch(fields.get("reader", "")):
        raise OnboardingValueError("VAULT_READER_ID_INVALID")
    return {}


def check(connection, purpose, secrets, context):
    return [{"permission": "read_items", "status": "NOT_REPORTED", "detail": "CUSTOMER_CLI_REPORTS_ON_UPLOAD"}]


def children(connection, purpose, plan):
    target_ = connection["target"]
    spec = {"name": connection["name"], "provider": "external_vault", "product": target_["product"],
            "prefixes": target_["prefixes"]}
    if connection["auth_method"] == "reader":
        spec["reader"] = (target_.get("auth") or {}).get("reader", "")
    return [{"kind": "coverage", "purpose": purpose, "spec": spec, "collector_token": True}]
