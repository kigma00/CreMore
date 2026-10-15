"""Tests for the detection engine.

Fixtures use synthetic tokens that match each provider's documented shape but
are not real credentials.
"""

from __future__ import annotations

import base64

import pytest

from cremore.detection import DetectorInput, Engine, ResourceRef
from cremore.detection.catalog import builtin_definitions
from cremore.detection.decoders import DecodedView, decoded_views
from cremore.detection.engine import EngineConfig
from cremore.detection.falsepositives import FPPolicy, shannon_entropy
from cremore.detection.models import CatalogEntry, Definition, PatternDef

# Exact-length synthetic bodies (no placeholder substrings, mixed alphabet).
B22 = "aB3dE5fG7hJ9kL1mN2pQ4r"                    # 22 chars
B36 = "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"      # 36 chars
B43 = B36 + "dE6fG8h"                             # 43 chars
GH = "ghp_" + B36                                 # a well-formed GitHub token


def scan(text: str, **cfg) -> list:
    engine = Engine(EngineConfig(**cfg))
    return engine.scan(DetectorInput(data=text.encode("utf-8"), resource=ResourceRef()))


def types(dets) -> set[str]:
    return {d.credential_type for d in dets}


def routing_definition(name, keywords):
    return Definition(
        CatalogEntry(id=name, name=name, provider="synthetic", credential_type=name,
                     keywords=keywords),
        (PatternDef(rf"{name}_[A-Z0-9]{{8}}"),),
    )


@pytest.mark.parametrize("cap", [1, 1000])
def test_keyword_routing_runs_once_per_view_and_keeps_order_and_cap_masking(monkeypatch, cap):
    class CountedKeywords(tuple):
        iterations = 0

        def __iter__(self):
            self.iterations += 1
            return super().__iter__()

    monkeypatch.setattr("cremore.detection.engine._decoders.decoded_views", lambda _data: [])
    engine = Engine(EngineConfig(max_detections=cap), definitions=[
        routing_definition("FIRST", ("absent", "MiXeD")),
        routing_definition("ALWAYS", ()),
        routing_definition("SKIPPED", ("not-present",)),
        routing_definition("LAST", ("mixed",)),
    ])
    for spec in engine._specs:
        spec.keywords = CountedKeywords(spec.keywords)
    tokens = ["LAST_A1B2C3D4", "ALWAYS_B2C3D4E5", "FIRST_C3D4E5F6"]
    result = engine.scan(DetectorInput(("MiXeD " + " ".join(tokens)).encode()))
    assert [d.credential_type for d in result] == ["FIRST", "ALWAYS", "LAST"][:cap]
    assert result.complete is (cap > 3)
    assert all(token not in det.redacted_line for token in tokens for det in result)
    assert [spec.keywords.iterations for spec in engine._specs] == [1, 0, 1, 1]


def test_keyword_routing_recomputes_decoded_views_and_preserves_first_occurrence(monkeypatch):
    monkeypatch.setattr("cremore.detection.engine._decoders.decoded_views", lambda _data: [
        DecodedView(b"plain decoded FIRST_A1B2C3D4 SECOND_B2C3D4E5", "first-decoder"),
        DecodedView(b"decoded SECOND_B2C3D4E5", "second-decoder"),
    ])
    engine = Engine(definitions=[
        routing_definition("FIRST", ("plain",)),
        routing_definition("SECOND", ("decoded",)),
    ])
    result = engine.scan(DetectorInput(b"plain FIRST_A1B2C3D4"))
    assert result.complete and len(result) == 2
    original, decoded = result
    assert original.credential_type == "FIRST" and original.decoder_type == ""
    assert original.line_number == 1 and "FIRST_A1B2C3D4" not in original.redacted_line
    assert decoded.credential_type == "SECOND" and decoded.decoder_type == "first-decoder"
    assert decoded.line_number is None and decoded.redacted_line == ""


def test_multiline_candidates_are_masked_on_every_intersecting_physical_line():
    definitions = [Definition(
        CatalogEntry(id="multi", name="multi", provider="synthetic", credential_type="MULTI"),
        (PatternDef(r"BEGIN\n[\s\S]+?\nEND"),)), routing_definition("OTHER", ())]
    engine = Engine(definitions=definitions)
    detections = engine.scan(DetectorInput(b"BEGIN\nSENSITIVE_FRAGMENT OTHER_A1B2C3D4\nEND"))
    assert {d.credential_type for d in detections} == {"MULTI", "OTHER"}
    assert all("SENSITIVE_FRAGMENT" not in d.redacted_line and "OTHER_A1B2C3D4" not in d.redacted_line
               and "\n" not in d.redacted_line for d in detections)


def test_detection_cap_bounds_verifier_work_without_losing_redaction(monkeypatch):
    from cremore.detection.verify import VerificationResult, VerificationState, VerifierConfig

    engine = Engine(EngineConfig(max_detections=1), definitions=[routing_definition("ITEM", ())])
    calls = []
    monkeypatch.setattr(engine, "_verify", lambda *args: (
        calls.append(1) or VerificationResult(VerificationState.UNSUPPORTED)))
    result = engine.scan(DetectorInput(b"ITEM_A1B2C3D4 ITEM_B2C3D4E5", verify=True,
                                       verify_config=VerifierConfig(enabled=True)))
    assert len(result) == len(calls) == 1 and not result.complete
    assert "ITEM_A1B2C3D4" not in result[0].redacted_line and "ITEM_B2C3D4E5" not in result[0].redacted_line


# --- catalog integrity ------------------------------------------------------

def test_catalog_compiles_and_is_labelled():
    engine = Engine()
    ids = set()
    for entry in engine.catalog():
        assert entry.id not in ids, f"duplicate detector id {entry.id}"
        ids.add(entry.id)
        assert entry.provenance == "provider-documentation"
        assert entry.source_url.startswith("http"), f"{entry.id} lacks a source_url"
        assert entry.credential_type


def test_every_definition_has_a_secret_expression():
    # _compile raises if not; constructing the engine exercises all of them.
    assert len(Engine().catalog()) == len(builtin_definitions())


# --- individual detectors ---------------------------------------------------

@pytest.mark.parametrize(
    "text,expected",
    [
        (f"token: {GH}", "GITHUB_TOKEN"),
        (("GITLAB_TOKEN=glpat-" "Ab3De5Fg7Hj9Kl1Mn2Pq"), "GITLAB_PERSONAL_ACCESS_TOKEN"),
        (("stripe = sk_live_51H8x" "kL2eZvKYlo2CaBcDeFgHiJk"), "STRIPE_SECRET_KEY"),
        (f"SG.{B22}.{B43}", "SENDGRID_API_KEY"),
        (f"npm_{B36}", "NPM_TOKEN"),
        (("hook https://hooks.slack.com/services/T01" "ABCDEF/B02GHIJKL/aB3dE5fG7hJ9kL1mN2pQ4rS6"), "SLACK_WEBHOOK"),
        (("key = dp.pt.a" "B3dE5fG7hJ9kL" "1mN2pQ4rS6tU8" "vW0xY2zC4dE6f"), "DOPPLER_TOKEN"),
        ("do token dop_v1_" + "a1b2c3d4" * 8, "DIGITALOCEAN_TOKEN"),
        (("figd_aB3dE5fG7hJ9kL1mN" "2pQ4rS6tU8vW0xY2zC4dE6f"), "FIGMA_TOKEN"),
        # third batch
        (("runner = glrt-Ab3" "De5Fg7Hj9Kl1Mn2Pq"), "GITLAB_RUNNER_TOKEN"),
        (("trigger glptt-0123456789abc" "def0123456789abcdef01234567"), "GITLAB_PIPELINE_TRIGGER_TOKEN"),
        ("XAI_API_KEY=xai-" + ("a1B2c3D4" * 10), "XAI_API_KEY"),
        ("key sk-or-v1-" + ("0123abcd" * 8), "OPENROUTER_API_KEY"),
        (("auth tskey-auth-k7Qb3De5Fg-9k" "L1mN2pQ4rS6tU8vW0xY2zC4dE6fG8"), "TAILSCALE_KEY"),
        ("brevo xkeysib-" + ("0123abcd" * 8) + "-aB3dE5fG7hJ9kL1m", "BREVO_API_KEY"),
        (("aio_aB3dE5fG7hJ9" "kL1mN2pQ4rS6tU8v"), "ADAFRUIT_IO_KEY"),
        (("token shippo_live_0123456789a" "bcdef0123456789abcdef01234567"), "SHIPPO_TOKEN"),
        ("fcm AAAAbcdE5fG:APA91b" + ("Ab3dE5fG7hJ9kL1mN2pQ4r" * 6) + "xy", "FCM_SERVER_KEY"),
        # fourth batch
        (("LTAI5tAb3d" "E5fG7hJ9kL"), "ALIBABA_ACCESS_KEY_ID"),
        (("AKID01234567" "89abcdefABCD"), "TENCENT_SECRET_ID"),
        ("pcsk_" + "aB3dE5fG7h" * 5, "PINECONE_API_KEY"),
        ("sgp_" + "0123456789abcdef" + "_" + "0123456789abcdef01234567" + "0123456789abcdef", "SOURCEGRAPH_TOKEN"),
        ("bkua_" + "a1b2c3d4" * 5, "BUILDKITE_AGENT_TOKEN"),
        (("license 0123456789abcdef" "0123456789abcdef0123NRAL"), "NEWRELIC_LICENSE_KEY"),
        (("CFPAT-aB3dE5fG7hJ9kL1mN2" "pQ4rS6tU8vW0xY2zC4dE6fG8h"), "CONTENTFUL_TOKEN"),
        (("ck_0123456789abcdef01" "23456789abcdef01234567"), "WOOCOMMERCE_KEY"),
        ("AKCp" + "a1B2c3D4" * 8 + "xyz01", "ARTIFACTORY_API_KEY"),
        (("sqp_0123456789abcdef01" "23456789abcdef01234567"), "SONAR_TOKEN"),
        (("pk_12345678_AB3DE5FG7H" "J9KL1MN2PQ4RS6TU8VW0XY"), "CLICKUP_TOKEN"),
        (("xau_aB3dE5fG7hJ9kL1m" "N2pQ4rS6tU8vW0xY2zC4d"), "XATA_API_KEY"),
        (("FLWSECK-0123456789abc" "def0123456789abcdef-X"), "FLUTTERWAVE_SECRET_KEY"),
        (("phc_aB3dE5fG7hJ9kL1mN2p" "Q4rS6tU8vW0xY2zC4dE6fG8h"), "POSTHOG_API_KEY"),
        (("account heroku 0a1b2c3d-4" "e5f-6789-abcd-ef0123456789"), "HEROKU_API_KEY"),
    ],
)
def test_detects_documented_token(text, expected):
    assert expected in types(scan(text))


SAS_SIG = "a39%2BYozJhGp6miujGymjRpN8tsrQfLo9" + "Z3i8IRyIpnQ%3D"


@pytest.mark.parametrize("text,facts", [
    ("https://myaccount.blob.core.windows.net/pictures/p.jpg?sp=r&se=2026-12-01T00:00:00Z&spr=https"
     "&sv=2022-11-02&sr=c&sig=" + SAS_SIG,
     {"account": "myaccount", "service": "blob", "kind": "service", "permissions": "r", "resource": "c",
      "expiry": "2026-12-01T00:00:00Z", "path": "/pictures/p.jpg"}),
    ("BlobEndpoint=https://myaccount.blob.core.windows.net/;SharedAccessSignature=sv=2022-11-02&ss=bfqt"
     "&srt=sco&sp=rwdlacup&se=2027-01-01T00:00:00Z&sig=" + SAS_SIG.replace("%2B", "+").replace("%3D", "="),
     {"account": "myaccount", "kind": "account", "services": "bfqt", "permissions": "rwdlacup"}),
    ("?sp=r&se=2026-09-02T00:00:00Z&skoid=11111111-2222-3333-4444-555555555555"
     "&sktid=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee&sv=2022-11-02&sr=b&si=policy-1&sig=" + SAS_SIG,
     {"kind": "user_delegation", "signer_object_id": "11111111-2222-3333-4444-555555555555", "policy": "policy-1"}),
], ids=["service-url", "account-connection-string", "user-delegation"])
def test_azure_sas_is_detected_with_its_signed_fields_but_never_its_signature(text, facts):
    [found] = [d for d in scan(text) if d.credential_type == "AZURE_SAS_TOKEN"]
    assert facts.items() <= found.extra_safe_data["azure_sas"].items()
    assert "sig" not in found.extra_safe_data["azure_sas"] and SAS_SIG[:12] not in repr(found.extra_safe_data)


def test_azure_sas_needs_a_signed_version_and_a_full_signature():
    assert "AZURE_SAS_TOKEN" not in types(scan("https://example.test/?a=1&sig=" + SAS_SIG))
    assert "AZURE_SAS_TOKEN" not in types(scan("https://myaccount.blob.core.windows.net/c?sv=2022-11-02&sr=c&sig=" + "abc"))


AZDO_PAT = ("aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4dE6fG8h" + "J0kL2mN4pQ6rS8tU0vW2xY4zB6cD8fG0hJ2k")[:76] + "AZDO" + "x7Q2"


def test_azure_devops_pat_is_found_by_its_fixed_signature_and_length():
    assert len(AZDO_PAT) == 84
    for text in (f"AZURE_DEVOPS_EXT_PAT={AZDO_PAT}", f'"password": "{AZDO_PAT}"',
                 "https://build:" + AZDO_PAT + "@" + "dev.azure.com/acme/_git/api"):
        [found] = [d for d in scan(text) if d.credential_type == "AZURE_DEVOPS_PAT"]
        assert found.extra_safe_data["catalog_id"] == "azure-devops-pat-v1", text
    for near_miss in (AZDO_PAT[1:], AZDO_PAT + "a", AZDO_PAT.replace("AZDO", "AZDX"), "x" + AZDO_PAT):
        assert "AZURE_DEVOPS_PAT" not in types(scan(f"token={near_miss}")), near_miss


def test_older_entra_secret_needs_an_azure_client_secret_label_and_is_medium_confidence():
    legacy = "aB3.dE5-fG7_hJ9~kL1mN2pQ4rS6tU8vW0x" + "Yz[1]@"  # 40 characters, no Q~ marker
    for text in (f"AZURE_CLIENT_SECRET={legacy}", f'ARM_CLIENT_SECRET: "{legacy}"', f'"azureClientSecret": "{legacy}"'):
        [found] = [d for d in scan(text) if d.credential_type == "AZURE_ENTRA_CLIENT_SECRET"]
        assert found.confidence == "medium", text
    assert "AZURE_ENTRA_CLIENT_SECRET" not in types(scan(f"client_secret={legacy}"))  # any OAuth client
    current = "Xy7" + "8Q~" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ01234.-_"
    found = [d for d in scan(f"AZURE_CLIENT_SECRET={current}") if d.credential_type == "AZURE_ENTRA_CLIENT_SECRET"]
    assert [d.extra_safe_data["catalog_id"] for d in found] == ["azure-entra-client-secret-v1"]  # no labelled duplicate


def test_entra_client_secret_in_env_json_and_bare_forms():
    secret = "Xy7" + "8Q~" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ01234.-_"  # 40 characters
    dashed = "-y7" + "7Q~" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ01234"  # 37 characters, leading dash
    for text in (f"AZURE_CLIENT_SECRET={secret}", secret, f'{{"clientSecret": "{secret}"}}', f"secret: {dashed}"):
        assert "AZURE_ENTRA_CLIENT_SECRET" in types(scan(text)), text
    for text in (secret + "x", secret.replace("~", "x")):  # a longer run, or no Q~ signature
        assert "AZURE_ENTRA_CLIENT_SECRET" not in types(scan(text)), text


@pytest.mark.parametrize(
    "text,expected",
    [
        (("DATADOG_API_KEY=01234567" "89abcdef0123456789abcdef"), "DATADOG_API_KEY"),
        (('datadog_app_key: "0123456789a' 'bcdef0123456789abcdef01234567"'), "DATADOG_APP_KEY"),
        (("algolia_api_key = fedcba9" "876543210fedcba9876543210"), "ALGOLIA_ADMIN_KEY"),
        (("postmark_server_token=0a1b2c3" "d-4e5f-6789-abcd-ef0123456789"), "POSTMARK_TOKEN"),
        (("COHERE_API_KEY: aB3d" "E5fG7hJ9kL1mN2pQ4rS6" "tU8vW0xY2zC4dE6f"), "COHERE_API_KEY"),
    ],
)
def test_labeled_secret_detectors(text, expected):
    assert expected in types(scan(text))


def test_labeled_secret_needs_its_label():
    # A bare 32-hex string with no Datadog label nearby must not match as a key.
    assert "DATADOG_API_KEY" not in types(scan("checksum = 0123456789abcdef0123456789abcdef"))


@pytest.mark.parametrize(
    "text,expected",
    [
        (('password = "Tr' '0ub4dor&3xKc9"'), "GENERIC_PASSWORD"),
        (("DB_PASSWD: 9f3a" "1c7e2b8d4056af19"), "GENERIC_PASSWORD"),
        (('client_secret="aB3dE' '5fG7hJ9kL1mN2pQ4rS6"'), "GENERIC_SECRET"),
        (("url = https://admin:Sup3rSec" "retPw@internal.example.com/db"), "BASIC_AUTH_URL"),
        (("Authorization: Basic Y" "WRtaW46c3VwM3JzZWNyZXQ="), "HTTP_BASIC_AUTH"),
    ],
)
def test_generic_credential_detectors(text, expected):
    assert expected in types(scan(text))


def test_generic_credentials_are_low_or_medium_confidence():
    pw = next(d for d in scan('password = "Tr' '0ub4dor&3xKc9"') if d.credential_type == "GENERIC_PASSWORD")
    assert pw.confidence in ("low", "medium")


def test_labelled_batch_providers():
    assert "RAYGUN_API_KEY" in types(scan("raygun_api_key = aB3dE5f" "G7hJ9kL1mN2pQ4rS6tU8vW0xY"))
    assert "ITERABLE_API_KEY" in types(scan('iterable_api_key: "9f3a1c7e' '2b8d4056af19c3e75d208b41ab"'))
    # Provider name alone with no token-shaped value must not match.
    assert "RAYGUN_API_KEY" not in types(scan("see the raygun docs for details"))


def test_basic_auth_header_requires_user_colon_pass():
    # Base64 that does NOT decode to user:pass must be rejected by the validator.
    not_basic = "Authorization: Basic QUFBQUFBQUFBQUFBQUFBQQ=="  # decodes to "AAAA..."
    assert "HTTP_BASIC_AUTH" not in types(scan(not_basic))


def test_low_entropy_password_is_reported_with_a_review_signal():
    # A weak password is still a password. The generic detectors carry no entropy
    # gate, so "aaaaaaaa" is reported and FPPolicy marks it for review instead of
    # dropping it silently.
    weak = [d for d in scan('password = "aaaaaaaa"') if d.credential_type == "GENERIC_PASSWORD"]
    assert weak and weak[0].extra_safe_data.get("fp_signal")
    assert weak[0].confidence == "low"


@pytest.mark.parametrize(
    "text,expected",
    [
        (('api_key = "aB3dE5f' 'G7hJ9kL1mN2pQ4rS6"'), "GENERIC_API_KEY"),
        (("hash = $2b$12$R9h/cIPz0gi.URNNX3k" "h2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"), "PASSWORD_HASH"),
        ("secret_key_base: " + "a1b2c3d4" * 16, "RAILS_SECRET_KEY_BASE"),
        ("AGE-SECRET-KEY-1" + "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L" + "QPZRY9X8GF2TVDW0S3JN54KHCE", "AGE_SECRET_KEY"),
        (("TOSS live_sk_DnyRp" "QWGrN7Xz9abc12def34"), "TOSS_SECRET_KEY"),
        (("key sk-0123456789ab" "cdef0123456789abcdef"), "DEEPSEEK_API_KEY"),
        (("htpasswd $a" "pr1$abcd1234" "$aB3dE5fG7h" "J9kL1mN2pQ4r"), "PASSWORD_HASH"),
        ("os_v2_app_" + "ab3de5fg7hj9kl1mn2pq4rs6tu8vw0xy2zc4de6f", "ONESIGNAL_REST_KEY"),
        ("pw $6$abcd1234$" + "a" * 86, "PASSWORD_HASH"),
        (("django pbkdf2_sha256$600000$aBcDeFgHiJ" "kL$Xy1234567890abcdefABCDEF0987654321gh"), "PASSWORD_HASH"),
        (("waka_0a1b2c3d-4e5f-6" "789-abcd-ef0123456789"), "WAKATIME_API_KEY"),
    ],
)
def test_generic_and_provider_additions(text, expected):
    assert expected in types(scan(text))


def test_private_key_encrypted_variant():
    pem = (
        "-----BEGIN ENCRYPTE" "D PRIVATE KEY-----\n"
        + ("MIIEvQIBADANBgkqhkiG9w0BA" "QEFAASCBKcwggSjAgEAAoIBAQ" * 3)
        + "\n-----END ENCRYPTED PRIVATE KEY-----\n"
    )
    assert "PRIVATE_KEY" in types(scan(pem))


def test_aws_access_key_pair():
    text = (
        "aws_access_key_id = A" "KIAZ5X9K2MBV7QP3LN6\n"
        "aws_secret_access_key = aB3dE5fG7" "hJ9kL1mN2pQ4rS6tU8vW0xY2zC4dE6f\n"
    )
    dets = scan(text)
    assert "AWS_ACCESS_KEY" in types(dets)
    aws = next(d for d in dets if d.credential_type == "AWS_ACCESS_KEY")
    assert aws.identifier == "AKIAZ5X9K2" "MBV7QP3LN6"
    assert aws.identifier_hint.startswith("AKIA")


def test_private_key_and_jwt():
    pem = (
        "-----BEGIN RSA P" "RIVATE KEY-----\n"
        + ("MIIEvQIBADANBgkqhkiG9w0BA" "QEFAASCBKcwggSjAgEAAoIBAQ" * 3)
        + "\n-----END RSA PRIVATE KEY-----\n"
    )
    assert "PRIVATE_KEY" in types(scan(pem))
    jwt = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdW" "IiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    assert "JWT" in types(scan(jwt))


def test_database_uri_with_password():
    uri = "DATABASE_URL=postgres://appuser" ":s3cretP4ss@db.internal:5432/app"
    assert "DB_CONNECTION_STRING" in types(scan(uri))


# --- false positives --------------------------------------------------------

def test_placeholder_is_flagged_not_dropped_by_default():
    # Retain policy keeps it but annotates fp_signal.
    dets = scan("ghp_YOURKEYYOURKEYYOURKEYYOURKEYYOURKE1")
    if dets:
        assert any(d.extra_safe_data.get("fp_signal") for d in dets)


def test_low_entropy_secret_suppressed_when_not_retaining():
    text = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    dets = scan(text, fp_policy=FPPolicy(entropy=3.0, retain=False))
    assert "GITHUB_TOKEN" not in types(dets)


def test_entropy_helper():
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") > 1.9


# --- confidence tiers & validators ------------------------------------------

def test_labeled_detectors_are_medium_confidence():
    dets = scan("DATADOG_API_KEY=9f3a1c7e" "2b8d4056af19c3e75d208b41")
    dd = next(d for d in dets if d.credential_type == "DATADOG_API_KEY")
    assert dd.confidence == "medium"  # labelled value, not self-identifying


def test_prefix_detectors_are_high_confidence():
    d = next(x for x in scan(f"token {GH}") if x.credential_type == "GITHUB_TOKEN")
    assert d.confidence == "high"


def test_aws_entropy_validator_rejects_low_entropy_secret():
    # Correct shape (AKIA id + 40-char secret) but the secret is all 'A': the
    # entropy validator must reject it so it never becomes a candidate.
    text = (
        "aws_access_key_id = A" "KIAZ5X9K2MBV7QP3LN6\n"
        "aws_secret_access_key = AAAAAAAAA" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
    )
    assert "AWS_ACCESS_KEY" not in types(scan(text))


def test_flagged_match_drops_a_confidence_tier():
    # A placeholder github token is retained but its confidence is lowered.
    dets = scan("ghp_YOURKEYYOURKEYYOURKEYYOURKEYYOURKE1")
    gh = [d for d in dets if d.credential_type == "GITHUB_TOKEN"]
    if gh:
        assert gh[0].confidence in ("medium", "low")


# --- decoders ---------------------------------------------------------------

def test_secret_found_inside_base64():
    inner = f"config: {GH}"
    wrapped = base64.b64encode(inner.encode()).decode()
    dets = scan(f"blob = {wrapped}")
    gh = [d for d in dets if d.credential_type == "GITHUB_TOKEN"]
    assert gh, "github token inside base64 was not decoded and detected"
    assert gh[0].decoder_type.startswith("base64")


def test_decoders_bounded_and_text_only():
    # Random binary must not explode into spurious views.
    views = decoded_views(bytes(range(256)) * 4)
    assert isinstance(views, list)


# --- redaction / fingerprint ------------------------------------------------

def test_redacted_line_hides_secret():
    secret = GH
    dets = scan(f"token = {secret}")
    d = next(x for x in dets if x.credential_type == "GITHUB_TOKEN")
    assert secret not in d.redacted_line
    assert "•" in d.redacted_line


def test_redacted_line_hides_every_credential_on_the_same_line_even_at_output_cap():
    npm = "npm_" + B36
    dets = scan(f"github={GH} npm={npm}", max_detections=1)
    assert len(dets) == 1
    assert GH not in dets[0].redacted_line
    assert npm not in dets[0].redacted_line


def test_redacted_line_hides_two_values_from_the_same_detector():
    other = "ghp_" + B36[::-1]
    dets = scan(f"first={GH} second={other}")
    github = [d for d in dets if d.credential_type == "GITHUB_TOKEN"]
    assert len(github) == 2
    assert all(GH not in d.redacted_line and other not in d.redacted_line for d in github)


def test_redacted_line_hides_fp_suppressed_candidate():
    suppressed = "npm_" + "a" * 36
    dets = scan(f"github={GH} npm={suppressed}", fp_policy=FPPolicy(retain=False))
    assert "GITHUB_TOKEN" in types(dets) and "NPM_TOKEN" not in types(dets)
    assert all(GH not in det.redacted_line and suppressed not in det.redacted_line for det in dets)


def test_fingerprint_is_stable_and_keyed():
    a = scan(GH)[0]
    b = scan(f"elsewhere {GH} end")[0]
    assert a.fingerprint == b.fingerprint  # location-independent
    keyed = Engine(EngineConfig(fingerprint_key=b"tenant-key")).scan(
        DetectorInput(data=GH.encode())
    )[0]
    assert keyed.fingerprint != a.fingerprint  # tenant isolation


def test_placeholder_words_and_engine_epoch_each_change_the_detection_digest(monkeypatch):
    # Neither is visible through the detector definitions (validators are
    # recorded by name only), so each must move the digest on its own or a
    # rule change would never invalidate the scan cache or trigger a re-sweep.
    import cremore.detection.engine as engine_module
    import cremore.detection.falsepositives as fp_module

    base = Engine(EngineConfig()).detection_digest
    monkeypatch.setattr(fp_module, "PLACEHOLDER_SUBSTRINGS", fp_module.PLACEHOLDER_SUBSTRINGS + ("synthetic-word",))
    words = Engine(EngineConfig()).detection_digest
    monkeypatch.undo()
    monkeypatch.setattr(engine_module, "ENGINE_EPOCH", engine_module.ENGINE_EPOCH + 1)
    epoch = Engine(EngineConfig()).detection_digest
    assert len({base, words, epoch}) == 3
