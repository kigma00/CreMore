import pytest

from cremore.detection.custom import (
    FIXTURES,
    RuleError,
    custom_credential_type,
    rule_definition,
    validate_rule,
)
from cremore.detection.custom import (
    evaluate_rule_sample as run_rule,
)
from cremore.domain.models import CustomRule


def rule(**kw) -> CustomRule:
    base = {"name": "Internal token", "pattern": r"(?P<secret>CREMORE_SYNTHETIC_[A-Z0-9]{8})", "keywords": ["cremore_synthetic"]}
    base.update(kw)
    return CustomRule(**base)


def test_rule_matches_its_marker_and_reports_under_custom_provider():
    d = rule_definition(rule())
    assert d.catalog.provider == "custom" and d.catalog.custom and d.catalog.confidence == "low"
    assert d.catalog.credential_type == custom_credential_type("Internal token")
    assert d.catalog.credential_type.startswith("CUSTOM_RULE_") and len(d.catalog.credential_type) == 12 + 64
    assert run_rule(rule(), FIXTURES["SYNTHETIC_TOKEN"]).matched is True
    assert run_rule(rule(), FIXTURES["NEUTRAL_TEXT"]).matched is False


def test_exclude_words_suppress_a_match_in_context():
    assert run_rule(rule(), FIXTURES["EXCLUDED_CONTEXT"]).matched is True
    assert run_rule(rule(exclude_words=["example", "sample"]), FIXTURES["EXCLUDED_CONTEXT"]).matched is False


def test_whole_match_pattern_without_groups_works():
    assert run_rule(rule(pattern=r"CREMORE_SYNTHETIC_[A-Z0-9]{8}"), FIXTURES["SYNTHETIC_TOKEN"]).matched is True


@pytest.mark.parametrize("pattern,reason", [
    (r"(?=x)secret", "lookaround"),
    (r"(a)\1", "backreferences"),
    (r"x*", "empty string"),
    (r".+", "trivial"),
    ("", "required"),
    ("(unclosed", "compile"),
    ("a" * 1001, "at most"),
])
def test_unsafe_or_overbroad_patterns_are_rejected(pattern, reason):
    with pytest.raises(RuleError) as info:
        validate_rule(rule(pattern=pattern))
    assert reason in str(info.value)


def test_rule_metadata_is_bounded():
    with pytest.raises(RuleError):
        validate_rule(rule(severity="URGENT"))
    # The allowed list now comes from the source registry; the message must stay byte-identical.
    with pytest.raises(RuleError, match=r"^scope_sources may only contain s3, github, notion, gitlab, gcp, confluence, "
                                        r"bitbucket, azure_blob, azure_devops, website, inline$"):
        validate_rule(rule(scope_sources=["ftp"]))
    validate_rule(rule(scope_sources=["s3", "azure_devops", "inline"]))
    with pytest.raises(RuleError):
        validate_rule(rule(fixture_tests=[{"id": "NOPE", "expected": True}]))
    with pytest.raises(RuleError):
        validate_rule(rule(name=""))


def test_custom_patterns_are_refused_when_the_linear_time_engine_is_missing(monkeypatch):
    """RE2 is what makes an operator's own pattern safe over untrusted content.
    The module falls back to the standard library if the extension will not load,
    where (a+)+b can hang the worker, so the fallback must refuse rather than run
    the pattern while the guarantee no longer holds."""

    from cremore.detection import custom

    monkeypatch.setattr(custom, "USING_RE2", True)
    custom.validate_pattern(r"AKIA[0-9A-Z]{16}")  # fine while the engine is there

    monkeypatch.setattr(custom, "USING_RE2", False)
    with pytest.raises(custom.RuleError) as refused:
        custom.validate_pattern(r"AKIA[0-9A-Z]{16}")
    assert "bounds matching time" in str(refused.value)
