"""Regression corpus for the generic hardcoded-credential detectors.

Every sample here is synthetic. The corpus deliberately contains both halves of
the problem: code references that must never be reported, and real-but-awkward
credentials (weak, repetitive, unquoted, code-looking) that must survive. A
filter that only removes noise is not enough — dropping a weak password is a
worse failure than showing a false positive.
"""

from __future__ import annotations

import pytest

from cremore.detection import DetectorInput, Engine, ResourceRef
from cremore.detection.catalog import builtin_definitions
from cremore.detection.engine import EngineConfig

SQ = chr(39)


def generic_hits(text: str) -> set[str]:
    found = Engine(EngineConfig()).scan(
        DetectorInput(data=text.encode("utf-8"), resource=ResourceRef()))
    return {d.credential_type for d in found if d.credential_type.startswith("GENERIC")}


# Code references: the literal text can never be the credential itself.
@pytest.mark.parametrize("sample", [
    "password: PropTypes.string,",                 # type annotation
    "password = getPassword()",                    # call
    "pwd = decrypt(secretValue)",                  # call argument
    "password: process.env.DB_PASS",               # environment lookup
    'password="${DB_PASSWORD}"',                   # shell/CI substitution
    "password: {{ vault_password }}",              # template substitution
    "client_secret: z.string()",                   # schema type
    'api_secret = config.get("api_secret")',       # accessor call
    "self.password = self.password_value",         # attribute reference
])
def test_unambiguous_code_references_are_not_reported(sample):
    assert generic_hits(sample) == set()


# Real credentials, including the shapes an over-eager filter would delete.
@pytest.mark.parametrize("sample,expected", [
    ('password = "test1234"', "GENERIC_PASSWORD"),
    ('password: "hunter2!"', "GENERIC_PASSWORD"),
    (f"password = {SQ}Str0ngPass!{SQ}", "GENERIC_PASSWORD"),
    ('"password": "hunter2!"', "GENERIC_PASSWORD"),          # JSON key
    ("password: s3cretValue123", "GENERIC_PASSWORD"),        # unquoted YAML
    ("PASSWORD=alpha.beta.gamma", "GENERIC_PASSWORD"),       # unquoted .env, dotted
    ("DB_HOST=x\nPASSWORD=alpha.beta.gamma\nOTHER=y", "GENERIC_PASSWORD"),
    ("connect(password=Sup3rSecret1, host=db)", "GENERIC_PASSWORD"),
    ('client_secret = "aB3dE5fG7hJ9kL1mN2pQ4r"', "GENERIC_SECRET"),
])
def test_real_credentials_survive_the_context_filter(sample, expected):
    assert expected in generic_hits(sample)


def test_weak_and_repetitive_passwords_are_still_reported():
    # These fail an entropy floor, which is why the generic detectors no longer
    # apply one: a weak password is exactly what an operator needs to see.
    # FPPolicy annotates them as low-entropy review signals instead.
    for value in ("aaaabbbb", "password", "12341234", "aaaaaaaa1"):
        assert generic_hits(f'password = "{value}"') == {"GENERIC_PASSWORD"}


def test_a_quoted_literal_is_kept_even_when_it_looks_like_code():
    # Quoting changes the meaning: this is a string, not a call.
    assert generic_hits('password = "getPassword()"') == {"GENERIC_PASSWORD"}
    assert generic_hits("password = getPassword()") == set()


def test_the_shared_provider_detector_helper_is_untouched():
    # The context filter must stay on the two generic detectors; provider keys
    # built with labeled_secret_detector keep their own rules.
    generic = [d for d in builtin_definitions() if d.catalog.provider == "generic"
               and d.catalog.credential_type.startswith("GENERIC_")]
    assert {d.catalog.id for d in generic} >= {
        "generic-password-assignment-v1", "generic-secret-assignment-v1"}
    # A provider key built with the shared helper still matches its own way: the
    # unquoted-delimiter and code-reference rules are generic-only.
    labelled = next(d for d in builtin_definitions() if d.catalog.id == "ai21-api-key-v1")
    assert labelled.catalog.match_strategy == "labelled value (config key adjacent)"
    # Assembled at run time so the file itself never holds a credential-shaped literal.
    value = "aB3dE5fG7hJ9kL1mN2pQ4r" + "S6tU8vW0xY"
    found = Engine(EngineConfig()).scan(DetectorInput(
        data=f'ai21_api_key = "{value}"'.encode(), resource=ResourceRef()))
    assert any(d.credential_type == "AI21_API_KEY" for d in found)


def test_an_empty_assignment_never_borrows_the_next_line():
    # `POSTGRES_PASSWORD=` with nothing after it must not report the following
    # line (`FINGERPRINT_KEY=`) as the password. Seen in a real .env.example.
    assert generic_hits("POSTGRES_PASSWORD=\nFINGERPRINT_KEY=\n") == set()
    assert generic_hits("password:\n  nested: value1234\n") == set()


def test_a_bare_value_ends_at_a_comma_or_semicolon():
    found = Engine(EngineConfig()).scan(DetectorInput(
        data=b"connect(password=Sup3rSecret1, host=db)", resource=ResourceRef()))
    hints = {d.identifier_hint for d in found if d.credential_type == "GENERIC_PASSWORD"}
    # The delimiter is not part of the credential, so it is not in the hint.
    assert hints and not any(h.endswith((",", ";")) for h in hints)
    assert generic_hits("pwd=Sup3rSecret1; host=db") == {"GENERIC_PASSWORD"}


def test_spacing_on_the_same_line_is_still_accepted():
    assert generic_hits("password:\ts3cretValue123\n") == {"GENERIC_PASSWORD"}
    assert generic_hits("PASSWORD =  alpha.beta.gamma\n") == {"GENERIC_PASSWORD"}


# The label only looks assigned: the ":" belongs to an ARN or to a string literal.
SPLIT_ARN = 'const name = entry.arn.split(":secret:")[1]?.replace(/-[A-Za-z0-9]{6}$/, "") || entry.arn;'
ARN_NAME = "SecretId: arn:aws:secretsmanager:us-west-2:123456789012:secret:MyTestDatabaseSecret-a1b2c3"


@pytest.mark.parametrize("sample", [SPLIT_ARN, SPLIT_ARN.replace('"', SQ), ARN_NAME])
def test_colon_segments_that_are_not_assignments_are_not_reported(sample):
    assert generic_hits(sample) == set()


# Near misses of those contexts are real assignments and must stay reported.
@pytest.mark.parametrize("sample,expected", [
    ('{"service:secret": "actual-shared-signing-value"}', "GENERIC_SECRET"),
    ('onepassword = "My1Password!"', "GENERIC_PASSWORD"),   # product name in key and value
    ('onepassword: "Xy7pQ2mZ"', "GENERIC_PASSWORD"),
    ("dbpassword=Xy7pQ2mZ9", "GENERIC_PASSWORD"),              # glued config names
    ("MYSQLPASSWORD=Xy7pQ2mZ9", "GENERIC_PASSWORD"),
])
def test_assignments_near_the_excluded_contexts_are_kept(sample, expected):
    assert expected in generic_hits(sample)


def test_masking_and_detection_share_the_context_judgement():
    found = Engine(EngineConfig()).scan(DetectorInput(
        data=(SPLIT_ARN + ' password = "hunter2!!"').encode(), resource=ResourceRef()))
    assert [d.credential_type for d in found] == ["GENERIC_PASSWORD"]
    # Only the real password is masked; the ARN handling code stays readable.
    assert 'split(":secret:")[1]?.replace' in found[0].redacted_line


def test_context_is_judged_inside_decoded_content():
    import base64

    def decoded_hits(text):
        found = Engine(EngineConfig()).scan(DetectorInput(
            data=base64.b64encode(text.encode()), resource=ResourceRef()))
        return {d.credential_type for d in found if d.decoder_type}

    assert decoded_hits('{"service:secret": "actual-shared-signing-value"}') == {"GENERIC_SECRET"}
    assert decoded_hits(SPLIT_ARN) == set()


def test_setup_placeholders_are_flagged_for_review_not_dropped():
    found = Engine(EngineConfig()).scan(DetectorInput(
        data=b"JOB_SECRET=replace-with-a-long-random-value\nDASHBOARD_PASSWORD=replace-me-please",
        resource=ResourceRef()))
    signals = {d.credential_type: d.extra_safe_data.get("fp_signal") for d in found}
    assert signals == {"GENERIC_SECRET": "wordlist", "GENERIC_PASSWORD": "wordlist"}
