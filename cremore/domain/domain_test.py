"""Config, domain model and detection->domain mapping tests."""

from __future__ import annotations

import uuid

import pytest

from cremore.config import Settings
from cremore.detection import DetectorInput, Engine, ResourceRef
from cremore.domain.mapping import credential_from_detection, exposure_from_detection
from cremore.domain.models import Credential, CredentialStatus, ExposureStatus


def _github_detection():
    gh = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"
    dets = Engine().scan(DetectorInput(data=f"token: {gh}".encode()))
    return next(d for d in dets if d.credential_type == "GITHUB_TOKEN")


# --- config -----------------------------------------------------------------

KEY = "ab" * 32


def _settings(**overrides):
    return Settings(**{"API_TOKEN": "0" * 32, "FINGERPRINT_KEY": KEY, **overrides})


def test_config_defaults_are_safe(monkeypatch):
    monkeypatch.delenv("CREDENTIAL_VERIFICATION_MODE")  # the real default, not the test guard
    # No built-in admin token: local mode refuses to start until one is set.
    with pytest.raises(ValueError, match="API_TOKEN"):
        _settings(API_TOKEN="").validate_safety()
    with pytest.raises(ValueError, match="API_TOKEN"):
        _settings(API_TOKEN="short").validate_safety()
    s = _settings()
    s.validate_safety()
    # Provider verification is on by default (the dashboard switches it); key
    # actions that change credentials stay off.
    assert s.verification_enabled
    assert not s.action_execution_enabled


@pytest.mark.parametrize("value", ["", "not-hex", "aa aa", "ab" * 31])
@pytest.mark.parametrize("component", ["api", "worker"])
def test_config_requires_a_fingerprint_key_in_every_installation(value, component):
    with pytest.raises(ValueError, match="FINGERPRINT_KEY"):
        _settings(FINGERPRINT_KEY=value).validate_safety(component)


def test_config_verification_defaults_on_needs_no_acknowledgement_and_can_be_locked_off(monkeypatch):
    monkeypatch.delenv("CREDENTIAL_VERIFICATION_MODE")
    for mode in ("local", "oidc"):
        s = _settings(AUTH_MODE=mode, OIDC_ISSUER_URL="https://idp.example.com", OIDC_AUDIENCE="cremore")
        s.validate_safety("api")
        assert s.verification_enabled
    locked = _settings(CREDENTIAL_VERIFICATION_MODE="disabled")
    locked.validate_safety("worker")
    assert not locked.verification_enabled


def test_config_leaves_transport_and_identity_design_to_the_organization():
    # Plain-HTTP issuer, no API TLS, default (unverified) DB URL, HTTP Vault, partial
    # or shared role groups: infrastructure choices, not start-up failures.
    s = _settings(
        AUTH_MODE="oidc", OIDC_ISSUER_URL="http://keycloak.internal/realms/cremore", OIDC_AUDIENCE="cremore",
        OIDC_ADMIN_GROUP="security", OIDC_VIEWER_GROUP="security",
        SECRET_STORE_URL="http://vault.internal:8200", SECRET_STORE_TOKEN="hvs.synthetic",
    )
    s.validate_safety("api")
    s.validate_safety("worker")
    with pytest.raises(ValueError, match="OIDC_ISSUER_URL and OIDC_AUDIENCE"):
        _settings(AUTH_MODE="oidc").validate_safety("api")
    _settings(AUTH_MODE="oidc").validate_safety("worker")


def test_oidc_role_mapping_ignores_unset_roles_and_prefers_the_higher_shared_role():
    from cremore.api.auth import build_verifier

    s = _settings(AUTH_MODE="oidc", OIDC_ISSUER_URL="https://idp.example.com", OIDC_AUDIENCE="cremore",
                  OIDC_VIEWER_GROUP="security", OIDC_ADMIN_GROUP="security")
    assert build_verifier(s, None).config.role_groups == {"security": "admin"}


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("AUTH_MODE", "none", "AUTH_MODE"),
        ("CREDENTIAL_VERIFICATION_MODE", "maybe", "CREDENTIAL_VERIFICATION_MODE"),
        ("MAX_INPUT_BYTES", 0, "MAX_INPUT_BYTES"),
        ("MAX_OBJECT_SIZE_MB", 0, "MAX_OBJECT_SIZE_MB"),
    ],
)
def test_config_rejects_invalid_modes_and_limits(field, value, message):
    with pytest.raises(ValueError, match=message):
        _settings(**{field: value}).validate_safety()


def test_a_retired_switch_left_in_an_env_is_named_rather_than_ignored(caplog, monkeypatch):
    """pydantic ignores unknown variables, so an upgraded installation whose .env
    still says SCAN_SQS_ENABLED=true would just stop consuming its queue."""
    from cremore.config import retired_env_in_use

    monkeypatch.setenv("SCAN_SQS_ENABLED", "true")
    monkeypatch.setenv("IAM_POTENTIAL_ACCESS_ENABLED", "true")
    monkeypatch.setenv("SCAN_SCHEDULES_ENABLED", "false")
    assert retired_env_in_use() == ["IAM_POTENTIAL_ACCESS_ENABLED", "SCAN_SCHEDULES_ENABLED", "SCAN_SQS_ENABLED"]
    with caplog.at_level("WARNING", logger="cremore.config"):
        _settings().validate_safety()          # a warning, never a refusal to boot
    logged = {record.getMessage().split()[0]: record.getMessage() for record in caplog.records}
    assert "/settings/scan-triggers" in logged["SCAN_SQS_ENABLED"] and "is OFF until" in logged["SCAN_SQS_ENABLED"]
    assert "is OFF until" in logged["IAM_POTENTIAL_ACCESS_ENABLED"]
    # Schedules are on by default now: a retired "false" must not read as keeping them off.
    assert "is ON unless it is switched off" in logged["SCAN_SCHEDULES_ENABLED"]


def test_no_retired_name_is_also_a_live_setting():
    """Warning about a variable the model still reads would be a lie."""
    from cremore.config import RETIRED_ENV

    live = {(field.alias or name).upper() for name, field in Settings.model_fields.items()}
    assert not (set(RETIRED_ENV) & live)


def test_config_api_tls_files_are_optional_but_paired():
    with pytest.raises(ValueError, match="TLS_CERT_FILE"):
        _settings(TLS_KEY_FILE="/run/tls/tls.key").validate_safety()
    _settings(TLS_CERT_FILE="/run/tls/tls.crt", TLS_KEY_FILE="/run/tls/tls.key").validate_safety()


def test_config_aws_onboarding_settings_are_optional_but_well_formed():
    # Onboarding is approved in the dashboard; neither setting is required and each stands alone.
    _settings(AWS_ONBOARDING_TEMPLATE_URL="https://example.com/template.yaml").validate_safety()
    _settings(AWS_SCANNER_PRINCIPAL_ARN="arn:aws:iam::123456789012:role/scanner").validate_safety()
    with pytest.raises(ValueError, match="exact IAM role ARN"):
        _settings(AWS_SCANNER_PRINCIPAL_ARN="arn:aws:iam::*:role/scanner").validate_safety()
    with pytest.raises(ValueError, match="must be HTTPS"):
        _settings(AWS_ONBOARDING_TEMPLATE_URL="http://example.com/template.yaml").validate_safety()
    _settings(AWS_REMEDIATION_PROFILE="cremore-remediation").validate_safety()
    with pytest.raises(ValueError, match="AWS_REMEDIATION_PROFILE"):
        _settings(AWS_REMEDIATION_PROFILE="bad profile;rm").validate_safety()


def test_worker_secret_store_supports_static_and_kubernetes_auth():
    static = _settings(SECRET_STORE_URL="https://vault.example.com", SECRET_STORE_TOKEN="hvs.synthetic")
    static.validate_safety("worker")
    assert static.secret_store_enabled

    workload = _settings(
        SECRET_STORE_URL="https://vault.example.com",
        SECRET_STORE_AUTH_MODE="kubernetes",
        SECRET_STORE_KUBERNETES_ROLE="cremore-worker",
    )
    workload.validate_safety("worker")
    assert workload.secret_store_enabled

    with pytest.raises(ValueError, match="SECRET_STORE_KUBERNETES_ROLE"):
        _settings(SECRET_STORE_URL="https://vault.example.com", SECRET_STORE_AUTH_MODE="kubernetes").validate_safety("worker")
    with pytest.raises(ValueError, match="requires SECRET_STORE_TOKEN"):
        _settings(SECRET_STORE_URL="https://vault.example.com").validate_safety("worker")


# --- domain models ----------------------------------------------------------


def test_credential_model_defaults():
    c = Credential(fingerprint="abc", credential_type="GITHUB_TOKEN")
    assert c.credential_status == CredentialStatus.UNKNOWN.value
    assert c.owner_status == "UNKNOWN"


# --- mapping ----------------------------------------------------------------


def test_credential_from_detection():
    det = _github_detection()
    cred = credential_from_detection(det)
    assert cred.fingerprint == det.fingerprint
    assert cred.credential_type == "GITHUB_TOKEN"
    assert cred.provider == "github"
    # The hint keeps a short prefix/suffix but masks the middle of the secret.
    assert "•" in cred.identifier_hint
    assert "aB3dE5fG7hJ9kL1mN2pQ4r" not in cred.identifier_hint


def test_credential_status_reflects_verification():
    det = _github_detection()
    det.extra_safe_data["verification_state"] = "verified"
    assert credential_from_detection(det).credential_status == CredentialStatus.ACTIVE.value
    det.extra_safe_data["verification_state"] = "rejected"
    assert credential_from_detection(det).credential_status == CredentialStatus.INACTIVE.value


def test_exposure_from_detection_source_scope():
    det = _github_detection()
    cid = uuid.uuid4()
    conn = uuid.uuid4()
    resource = ResourceRef(source_type="github", resource="org/repo", location="config.py")
    exp = exposure_from_detection(det, resource, cid, severity="HIGH", source_connection_id=conn)
    assert exp.credential_id == cid
    assert exp.source_connection_id == conn
    assert exp.aws_account_id is None
    assert exp.status == ExposureStatus.OPEN.value
    assert exp.severity == "HIGH"


def test_exposure_from_detection_aws_scope():
    det = _github_detection()
    resource = ResourceRef(
        source_type="s3",
        resource="bucket",
        location="key.txt",
        account_id="123e4567-e89b-12d3-a456-426614174000",
    )
    exp = exposure_from_detection(det, resource, uuid.uuid4(), scan_id=uuid.uuid4())
    assert exp.aws_account_id is not None
    assert exp.source_connection_id is None
    assert exp.first_scan_id is not None
