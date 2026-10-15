"""Custom-rule payload validation and response projection."""

from __future__ import annotations

from pydantic import ValidationError

from cremore.api.http_support import (
    http_error,
    isoformat,
)
from cremore.detection.custom import (
    RuleError,
    custom_credential_type,
    validate_rule,
)
from cremore.domain.models import (
    CustomRule,
)

# What a request may set; the revision and who changed the rule come from the server.
RULE_FIELDS = tuple(f for f in CustomRule.model_fields if f not in ("id", "created_at", "updated_at", "revision", "updated_by"))


MAX_SAMPLE = 64 * 1024


def present_rule(r) -> dict:
    return {
        "id": str(r.id),
        "name": r.name,
        "description": r.description,
        "enabled": r.enabled,
        "rule_type": r.rule_type,
        "keywords": list(r.keywords),
        "pattern": r.pattern,
        "severity": r.severity,
        "revision": r.revision,
        "scope_accounts": [],
        "scope_sources": list(r.scope_sources),
        "include_globs": list(r.include_globs),
        "exclude_globs": list(r.exclude_globs),
        "exclude_words": list(r.exclude_words),
        "provider_candidates": list(r.provider_candidates),
        "content_kinds": list(r.content_kinds),
        "category": r.category,
        "credential_type": custom_credential_type(r.name),
        "updated_by": r.updated_by,
        "responsible_team_candidate": r.responsible_team_candidate,
        "fixture_tests": list(r.fixture_tests),
        "exception_reason": r.exception_reason,
        "review_due_at": r.review_due_at,
        "created_at": isoformat(r.created_at) or "",
        "updated_at": isoformat(r.updated_at) or "",
    }


def rule_from_body(body: dict, *, base: CustomRule | None = None) -> CustomRule:
    """A validated rule from a dashboard payload (unknown keys ignored)."""

    if not isinstance(body, dict):
        raise http_error(422, "rule must be an object")
    data = base.model_dump() if base is not None else {}
    data.update({k: body[k] for k in RULE_FIELDS if k in body})
    data.pop("id", None)
    data.pop("created_at", None)
    data.pop("updated_at", None)
    data.pop("updated_by", None)
    try:
        rule = CustomRule(**{k: v for k, v in data.items() if k != "revision"},
                          revision=(base.revision if base is not None else 1))
    except ValidationError as exc:
        raise http_error(422, f"rule is invalid: {exc.errors()[0].get('msg', 'validation error')}")
    rule.name = rule.name.strip()
    try:
        validate_rule(rule)
    except RuleError as exc:
        raise http_error(422, str(exc))
    return rule
