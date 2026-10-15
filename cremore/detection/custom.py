"""Operator-authored regex rules as engine definitions.

A custom rule is a single SECRET expression the operator supplies through the
dashboard. It runs beside the built-in catalog, but its matches are reported
under the synthetic ``custom`` provider with a rule-derived credential type and
the operator's severity — never as a provider-verified credential. Patterns are
validated to be RE2-safe (no lookaround or backreferences), bounded, and unable
to match trivial input, so a careless rule cannot flood the installation.
"""

from __future__ import annotations

import hashlib
import re as _re
from dataclasses import dataclass

from cremore.detection.engine import Engine, EngineConfig
from cremore.detection.falsepositives import FPPolicy
from cremore.detection.models import (
    CatalogEntry,
    Definition,
    DetectorInput,
    PatternDef,
    PatternRole,
    ResourceRef,
)
from cremore.detection.regex import USING_RE2, compile_bytes

MAX_PATTERN_LENGTH = 1000
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
# What a rule's value is, for built-in detectors and operator rules alike: the rule list's Type column.
CATEGORIES = ("token", "apikey", "secret", "account", "privkey", "conn", "webhook", "other")
_UNSAFE = _re.compile(r"\(\?[=!<]|\(\?P=|\\[1-9]")

# google-re2 is a required dependency, and its linear-time matching is what makes
# an operator's own pattern safe to run over untrusted content. If the extension
# ever fails to load the module falls back to the standard library, where a
# pattern like (a+)+b can hang the worker. Built-in detectors are reviewed;
# operator patterns are not, so they are refused rather than run on a backtracking
# engine while the promise silently no longer holds.
_NO_RE2 = "the regex engine that bounds matching time is unavailable; custom rules are refused"
_TRIVIAL = (b"", b" ", b"\n", b"x", b"=", b"://", b"the quick brown fox")
_MARKER = "CREMORE_SYNTHETIC_A1B2C3D4"
_MARKER_2 = "CREMORE_SYNTHETIC_E5F6G7H8"

# Synthetic fixtures the dashboard lets an operator save expectations for.
# Every marker is synthetic; no real credential shape appears here.
FIXTURES: dict[str, str] = {
    "SYNTHETIC_TOKEN": f"token = {_MARKER}\n",
    "SYNTHETIC_ID_ONLY": f"client_id = {_MARKER}\n",
    "DUPLICATE_LOCATIONS": f"token = {_MARKER}\n# elsewhere\ntoken = {_MARKER}\n",
    "STRUCTURED_MULTIPLE": f'{{"token": "{_MARKER}", "secret": "{_MARKER_2}"}}\n',
    "EXCLUDED_CONTEXT": f"example token = {_MARKER}  # test fixture, sample only\n",
    "NEUTRAL_TEXT": "The quick brown fox jumps over the lazy dog. Release notes v1.2.3.\n",
}
FIXTURE_DEFAULT_EXPECTED = {fid: fid not in ("SYNTHETIC_ID_ONLY", "NEUTRAL_TEXT") for fid in FIXTURES}


class RuleError(ValueError):
    """The rule is not safe or not usable as a detector."""


def custom_credential_type(name: str) -> str:
    """The dashboard recognises CUSTOM_RULE_<sha256(name)> as a rule-derived type."""

    return "CUSTOM_RULE_" + hashlib.sha256(name.encode("utf-8")).hexdigest().upper()


def rule_detection_policy(rule) -> dict:
    """Fields that change which evidence an operator rule detects or retains."""
    return {key: getattr(rule, key) for key in (
        "pattern", "keywords", "scope_sources", "include_globs", "exclude_globs", "exclude_words")}


def validate_rule(rule) -> None:
    """Raise :class:`RuleError` unless the rule is safe to compile and run."""

    name = (rule.name or "").strip()
    if not name or len(name) > 128:
        raise RuleError("name is required (at most 128 characters)")
    if rule.rule_type != "regex":
        raise RuleError("rule_type must be 'regex'")
    if rule.severity not in SEVERITIES:
        raise RuleError(f"severity must be one of {', '.join(SEVERITIES)}")
    if rule.category is not None and rule.category not in CATEGORIES:
        raise RuleError(f"category must be one of {', '.join(CATEGORIES)}")
    if len(rule.keywords) > 32 or any(not isinstance(k, str) or not k.strip() or len(k) > 64 for k in rule.keywords):
        raise RuleError("keywords must be up to 32 non-empty strings")
    for field in ("scope_sources", "include_globs", "exclude_globs", "exclude_words", "provider_candidates",
                  "content_kinds"):
        values = getattr(rule, field)
        if len(values) > 32 or any(not isinstance(v, str) or len(v) > 256 for v in values):
            raise RuleError(f"{field} must be up to 32 strings")
    # Integration: the allowed sources come from the content-source registry instead of a copied
    # literal; the list and the message are unchanged. Imported here so importing the detection
    # engine stays free of the provider source modules (the API that validates rules loads them).
    from cremore.sources.registry import SOURCE_TYPES

    allowed = (*SOURCE_TYPES, "inline")
    if any(s not in allowed for s in rule.scope_sources):
        raise RuleError(f"scope_sources may only contain {', '.join(allowed)}")
    for fixture in rule.fixture_tests:
        if not isinstance(fixture, dict) or fixture.get("id") not in FIXTURES or not isinstance(fixture.get("expected"), bool):
            raise RuleError("fixture_tests entries must be {id: <known fixture>, expected: bool}")
    validate_pattern(rule.pattern)


def validate_pattern(expr: str) -> None:
    if not isinstance(expr, str) or not expr.strip():
        raise RuleError("pattern is required")
    if not USING_RE2:
        raise RuleError(_NO_RE2)
    if len(expr) > MAX_PATTERN_LENGTH:
        raise RuleError(f"pattern must be at most {MAX_PATTERN_LENGTH} characters")
    if _UNSAFE.search(expr):
        raise RuleError("pattern must not use lookaround or backreferences (RE2-safe expressions only)")
    try:
        compiled = compile_bytes(expr)
    except Exception as exc:  # re/re2 raise their own error types
        raise RuleError(f"pattern does not compile: {type(exc).__name__}") from exc
    for noise in _TRIVIAL:
        m = compiled.search(noise)
        if m is not None and (m.end() - m.start()) > 0:
            raise RuleError("pattern matches trivial input; it would flag almost anything")
        if m is not None and noise == b"":
            raise RuleError("pattern matches the empty string")


def rule_definition(rule) -> Definition:
    """Compile-ready definition for an already-validated rule."""

    compiled = compile_bytes(rule.pattern)
    named_secret = compiled.group_index("secret") >= 1
    pattern = PatternDef(
        expr=rule.pattern,
        role=PatternRole.SECRET,
        secret_group="secret" if named_secret else "",
        # Without a named/positional group the whole match is the value.
        whole_match=not named_secret and compiled.num_groups() == 0,
    )
    return Definition(
        catalog=CatalogEntry(
            id=f"custom-{rule.id}" if rule.id else f"custom-{custom_credential_type(rule.name)[-12:]}",
            name=rule.name,
            provider="custom",
            credential_type=custom_credential_type(rule.name),
            description=rule.description or "Operator-authored rule.",
            keywords=tuple(k.lower() for k in rule.keywords),
            match_strategy="operator rule",
            source_url="",
            provenance="operator",
            custom=True,
            confidence="low",
        ),
        patterns=(pattern,),
        detector_name=f"CustomRule:{rule.name}",
    )


def excluded_by_words(rule, line: str) -> bool:
    lowered = (line or "").lower()
    return any(w and w.lower() in lowered for w in rule.exclude_words)


@dataclass(frozen=True)
class RuleTestResult:
    matched: bool


def evaluate_rule_sample(rule, sample: str) -> RuleTestResult:
    """Run one rule alone over a sample. Placeholder suppression is disabled so
    the operator sees what the *pattern* does; scope filters still apply."""

    validate_rule(rule)
    engine = Engine(EngineConfig(fp_policy=FPPolicy(retain=True)), definitions=[rule_definition(rule)])
    detections = engine.scan(DetectorInput(data=sample.encode("utf-8"), resource=ResourceRef(source_type="inline")))
    matched = any(not excluded_by_words(rule, d.redacted_line) for d in detections)
    return RuleTestResult(matched=matched)
