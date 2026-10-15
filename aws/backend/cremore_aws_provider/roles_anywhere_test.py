"""Synthetic certificates and fake helper output; never calls AWS."""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cremore_aws_provider import aws_identity
from cremore_aws_provider import roles_anywhere as ra


def certificate(directory, *, days=40):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-cremore")])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(UTC) - timedelta(days=2))
            .not_valid_after(datetime.now(UTC) + timedelta(days=days)).sign(key, hashes.SHA256()))
    crt, private = directory / "certificate.pem", directory / "private.pem"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    private.chmod(0o600)
    return crt, private


@pytest.fixture
def configured(tmp_path, monkeypatch):
    crt, key = certificate(tmp_path)
    helper = tmp_path / "aws_signing_helper"
    helper.write_bytes(b"synthetic helper, never executed")
    helper.chmod(0o500)
    base = "arn:aws:rolesanywhere:ap-northeast-2:111122223333:"
    config = {"helper": str(helper), "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
              "certificate": str(crt), "private_key": str(key),
              "trust_anchor_arn": base + "trust-anchor/11111111-1111-1111-1111-111111111111",
              "profile_arn": base + "profile/22222222-2222-2222-2222-222222222222",
              "role_arn": "arn:aws:iam::111122223333:role/team/CreMore"}
    path = tmp_path / "roles-anywhere.json"
    path.write_text(json.dumps(config))
    monkeypatch.setenv(ra.CONFIG_ENV, str(path))
    return path, config


def output():
    return {"Version": 1, "AccessKeyId": "synthetic-access", "SecretAccessKey": "synthetic-secret",
            "SessionToken": "synthetic-session", "Expiration": (datetime.now(UTC) + timedelta(hours=1)).isoformat()}


def test_bridge_reloads_rotated_certificate_and_returns_only_sdk_fields(configured, monkeypatch, capsys):
    path, config = configured
    seen = []
    monkeypatch.setattr(ra, "_run", lambda args: seen.append(args) or json.dumps({**output(), "untrusted": "omit"}))
    assert ra.main(["--config", str(path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert set(result) == set(output())
    assert "--private-key" in seen[0] and config["private_key"] in seen[0]
    assert ra.diagnostic()["state"] == "READY"
    assert ra.diagnostic({"state": "ERROR", "error_code": "CredentialRetrievalError"})["error_code"] == "AWS_ROLES_ANYWHERE_RENEWAL_FAILED"
    certificate(path.parent, days=10)
    assert ra.diagnostic()["state"] == "EXPIRING"
    assert ra.credentials(str(path))["SessionToken"] == "synthetic-session"
    certificate(path.parent, days=-1)
    with pytest.raises(ra.RolesAnywhereError, match="CERTIFICATE_EXPIRED"):
        ra.credentials(str(path))


def test_api_probe_does_not_mask_failed_renewal_with_valid_certificate(configured, monkeypatch):
    import boto3
    from botocore.exceptions import CredentialRetrievalError

    from cremore.api.aws_support import default_identity_probe

    def refused(*args, **kwargs):
        raise CredentialRetrievalError(provider="custom-process", error_msg="synthetic-sensitive-output")

    monkeypatch.setattr(boto3, "Session", lambda: SimpleNamespace(client=refused))
    result = default_identity_probe(SimpleNamespace(aws_region="ap-northeast-2"))()
    assert result["renewal_health"]["error_code"] == "AWS_ROLES_ANYWHERE_RENEWAL_FAILED"
    assert "synthetic-sensitive-output" not in str(result)


def test_only_pinned_bridge_is_a_server_identity_including_role_chains(configured):
    path, _ = configured
    quote = subprocess.list2cmdline if os.name == "nt" else shlex.join
    command = quote([sys.executable, "-m", "cremore_aws_provider.roles_anywhere", "--config", str(path)])
    assert ra.trusted_process(command)
    for bad in (command + " --debug", "aws_signing_helper credential-process", command.replace("-m ", "-c ")):
        assert not ra.trusted_process(bad)
    for method, profiles in [("custom-process", {"default": {"credential_process": command}}),
                             ("assume-role", {"default": {"source_profile": "ra"}, "ra": {"credential_process": command}})]:
        session = SimpleNamespace(get_credentials=lambda method=method: SimpleNamespace(method=method), profile_name="default",
                                  _session=SimpleNamespace(full_config={"profiles": profiles}))
        assert aws_identity.server_workload_source(session) == "roles-anywhere"
    aws_identity.require_server_workload({"kind": "IAM_ROLE", "credential_source": "roles-anywhere"})


@pytest.mark.parametrize("change", ["helper", "target", "key", "extra", "relative"])
def test_untrusted_or_mismatched_configuration_fails_before_execution(configured, monkeypatch, change):
    path, config = configured
    if change == "helper":
        config["helper_sha256"] = "0" * 64
    elif change == "target":
        config["role_arn"] = config["role_arn"].replace("111122223333", "999988887777")
    elif change == "key":
        config["private_key"] = config["certificate"]
    elif change == "extra":
        config["args"] = ["--endpoint", "https://untrusted.invalid"]
    else:
        config["helper"] = "relative.exe"
    path.write_text(json.dumps(config))
    monkeypatch.setattr(ra, "_run", lambda _: pytest.fail("must not launch"))
    assert ra.main(["--config", str(path)]) == 1


@pytest.mark.parametrize("mutation", ["no-expiry", "expired", "naive", "long", "missing-token", "invalid-json"])
def test_never_accepts_nonrefreshable_or_invalid_helper_output(configured, monkeypatch, mutation):
    path, _ = configured
    value = output()
    if mutation == "no-expiry":
        value.pop("Expiration")
    elif mutation == "expired":
        value["Expiration"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    elif mutation == "naive":
        value["Expiration"] = datetime.now(UTC).replace(tzinfo=None).isoformat()
    elif mutation == "long":
        value["Expiration"] = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    elif mutation == "missing-token":
        value["SessionToken"] = ""
    monkeypatch.setattr(ra, "_run", lambda _: "bad-json" if mutation == "invalid-json" else json.dumps(value))
    with pytest.raises(ra.RolesAnywhereError, match="OUTPUT_INVALID"):
        ra.credentials(str(path))


def test_real_process_limits_and_secret_stderr_are_not_propagated(monkeypatch, capsys):
    assert ra._run([sys.executable, "-c", "print('small')"]).strip() == b"small"
    with pytest.raises(ra.RolesAnywhereError, match="OUTPUT_INVALID"):
        ra._run([sys.executable, "-c", "print('x'*40000)"])
    with pytest.raises(ra.RolesAnywhereError, match="HELPER_FAILED"):
        ra._run([sys.executable, "-c", "import sys; print('private stderr',file=sys.stderr);sys.exit(1)"])
    monkeypatch.setattr(ra, "TIMEOUT", 0.1)
    with pytest.raises(ra.RolesAnywhereError, match="TIMEOUT"):
        ra._run([sys.executable, "-c", "import time;time.sleep(10)"])
    assert "private stderr" not in str(capsys.readouterr())


@pytest.mark.skipif(os.name != "posix", reason="POSIX file permissions require Linux verification")
def test_world_readable_private_key_refused(configured):
    path, config = configured
    from pathlib import Path
    Path(config["private_key"]).chmod(0o644)
    with pytest.raises(ra.RolesAnywhereError, match="FILE_PERMISSIONS"):
        ra.load(str(path))


def test_sdk_refresh_and_new_process_restart_use_fresh_temporary_credentials(configured, monkeypatch):
    from botocore.credentials import RefreshableCredentials

    path, _ = configured
    calls = []
    monkeypatch.setattr(ra, "_run", lambda _: calls.append(1) or json.dumps(output()))

    def refresh():
        value = ra.credentials(str(path))
        return {"access_key": value["AccessKeyId"], "secret_key": value["SecretAccessKey"],
                "token": value["SessionToken"], "expiry_time": value["Expiration"]}

    creds = RefreshableCredentials.create_from_metadata(metadata=refresh(), refresh_using=refresh, method="custom-process")
    assert creds.get_frozen_credentials().token == "synthetic-session" and len(calls) == 1
    for _ in range(30):  # repeated renewal boundaries, no wall-clock soak claim
        creds._expiry_time = datetime.now(UTC) + timedelta(seconds=1)
        assert creds.get_frozen_credentials().token == "synthetic-session"
    assert len(calls) == 31
    restarted = RefreshableCredentials.create_from_metadata(metadata=refresh(), refresh_using=refresh, method="custom-process")
    assert restarted.get_frozen_credentials().token == "synthetic-session" and len(calls) == 32


@pytest.mark.skipif(os.name != "posix", reason="Linux executable and installed wheel proof")
def test_installed_sdk_executes_bridge_renews_restarts_and_reloads_certificate(configured):
    from pathlib import Path

    from botocore.credentials import ProcessProvider
    from botocore.exceptions import CredentialRetrievalError

    path, config = configured
    helper = Path(config["helper"])
    helper.chmod(0o700)
    helper.write_text(f"#!{sys.executable}\nimport json\nprint({json.dumps(json.dumps(output()))})\n")
    helper.chmod(0o500)
    config["helper_sha256"] = hashlib.sha256(helper.read_bytes()).hexdigest()
    path.write_text(json.dumps(config))
    command = shlex.join([sys.executable, "-m", "cremore_aws_provider.roles_anywhere", "--config", str(path)])
    provider = ProcessProvider("ra", lambda: {"profiles": {"ra": {"credential_process": command}}})
    credentials = provider.load()
    assert credentials.method == "custom-process"
    assert credentials.get_frozen_credentials().token == "synthetic-session"
    certificate(path.parent, days=10)
    credentials._expiry_time = datetime.now(UTC) + timedelta(seconds=1)
    assert credentials.get_frozen_credentials().token == "synthetic-session"
    assert provider.load().get_frozen_credentials().token == "synthetic-session"
    certificate(path.parent, days=-1)
    credentials._expiry_time = datetime.now(UTC) + timedelta(seconds=1)
    with pytest.raises(CredentialRetrievalError, match="CERTIFICATE_EXPIRED") as refused:
        credentials.get_frozen_credentials()
    assert "synthetic-secret" not in str(refused.value)
    certificate(path.parent, days=40)
    assert provider.load().get_frozen_credentials().token == "synthetic-session"
