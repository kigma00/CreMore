"""What the installation says it keeps locally, and what it must never say.

The point of this view is that an operator who moved the sealing master can
confirm it moved. That only works if the answer comes from what the process
booted with rather than from what somebody intended, and if it never leaks the
thing it is reporting on.
"""

from __future__ import annotations

import json

import pytest

from cremore.config import Settings
from cremore.secretstore import stored_locally
from cremore.secretstore.stored_locally import local_credentials

KEY = "ab" * 32
OTHER = "cd" * 32
CMK = "arn:aws:kms:ap-northeast-2:123456789012:key/2f7c5e1a-0000-4000-8000-0123456789ab"
BLOB = "AQIDAHhCaXBoZXJ0ZXh0QmxvYkZvclRoZVNlYWxpbmdLZXlIZXJlT0s="


def item(view, name):
    return next(one for one in view["items"] if one["name"] == name)


# -- where the master actually is ----------------------------------------------


def test_an_installation_that_set_nothing_is_told_its_master_cannot_rotate():
    view = local_credentials(Settings(FINGERPRINT_KEY=KEY))
    assert view["sealing"]["root"] == "FINGERPRINT_KEY"
    assert view["sealing"]["held_here"] is True
    assert item(view, "sealing master")["rotatable"] is False
    # This is the default, so saying so is the whole value of the screen.
    assert "SEALING_MASTER_CANNOT_ROTATE" in view["reasons"]


def test_a_separate_key_rotates_but_is_still_on_this_disk():
    view = local_credentials(Settings(FINGERPRINT_KEY=KEY, SEALING_KEY=OTHER))
    assert view["sealing"]["root"] == "ENVIRONMENT"
    assert view["sealing"]["held_here"] is True
    assert item(view, "sealing master")["rotatable"] is True
    assert "SEALING_MASTER_HELD_HERE" in view["reasons"]
    assert "SEALING_MASTER_CANNOT_ROTATE" not in view["reasons"]


def test_a_kms_root_leaves_only_a_ciphertext_here(monkeypatch):
    monkeypatch.setattr("cremore_aws_provider.kms.master", lambda *a, **k: bytes.fromhex(OTHER))
    view = local_credentials(Settings(FINGERPRINT_KEY=KEY, SEALING_KMS_KEY_ID=CMK, SEALING_KEY_CIPHERTEXT=BLOB))
    assert view["sealing"]["root"] == "KMS"
    assert view["sealing"]["held_here"] is False
    assert view["reasons"] == []
    assert "kms:Decrypt" in item(view, "sealing master")["reason"]


def test_a_vault_root_wins_over_a_key_that_is_also_configured(monkeypatch):
    monkeypatch.setattr("cremore_vault_provider.secretstore.kv_from_settings", lambda *a, **k: object())
    monkeypatch.setattr("cremore_vault_provider.secretstore.sealing_master", lambda *a, **k: bytes.fromhex(OTHER))
    view = local_credentials(Settings(
        FINGERPRINT_KEY=KEY, SEALING_KEY=OTHER, SEALING_KEY_VAULT_PATH="cremore/sealing-key",
        SECRET_STORE_URL="https://vault.local", SECRET_STORE_TOKEN="s.token"))
    # sealing_keys resolves the same order, so the screen and the worker agree.
    assert view["sealing"]["root"] == "VAULT"
    assert view["sealing"]["held_here"] is False
    assert item(view, "SEALING_KEY")["held_here"] is True


def test_passphrases_and_previous_local_openers_are_reported_even_with_a_remote_root(monkeypatch):
    monkeypatch.setattr("cremore_aws_provider.kms.master", lambda *a, **k: bytes.fromhex(OTHER))
    view = local_credentials(Settings(FINGERPRINT_KEY=KEY, SEALING_KMS_KEY_ID=CMK, SEALING_KEY_CIPHERTEXT=BLOB,
                                      SEALING_PASSPHRASE="synthetic current passphrase",
                                      SEALING_PASSPHRASE_PREVIOUS="synthetic previous passphrase",
                                      SEALING_KEY_PREVIOUS=KEY))
    for name in ("SEALING_PASSPHRASE", "SEALING_PASSPHRASE_PREVIOUS", "SEALING_KEY_PREVIOUS"):
        assert item(view, name)["held_here"] is True
    text = json.dumps(view)
    assert "stored nowhere" not in text and "synthetic current passphrase" not in text
    assert "synthetic previous passphrase" not in text
    assert view["disk_persistence"] == "UNKNOWN"


def test_passphrase_root_is_configuration_material_and_database_url_makes_no_network_claim():
    view = local_credentials(Settings(FINGERPRINT_KEY=KEY, SEALING_PASSPHRASE="synthetic start passphrase",
                                      DATABASE_URL="sqlite:///local.db"))
    assert view["sealing"]["held_here"] is True
    assert "carries the database password" not in item(view, "DATABASE_URL")["reason"]
    assert "never leaves this network" not in json.dumps(view)


# -- never a secret, never a guess ---------------------------------------------


def test_no_configured_value_is_ever_returned():
    view = local_credentials(Settings(
        FINGERPRINT_KEY=KEY, SEALING_KEY=OTHER, API_TOKEN="a" * 40,
        DATABASE_URL="postgresql+psycopg://cremore:SYNTHETIC_PASSWORD@db:5432/cremore",
        SECRET_STORE_URL="https://vault.local", SECRET_STORE_TOKEN="s.SYNTHETIC_TOKEN"))
    serialized = json.dumps(view)
    for secret in (KEY, OTHER, "a" * 40, "SYNTHETIC_PASSWORD", "s.SYNTHETIC_TOKEN"):
        assert secret not in serialized
    # The key identifier is the one thing named, and it is an HKDF output that
    # the refusal for a missing key already prints.
    assert len(view["sealing"]["key_id"]) == 16


def test_the_shared_token_is_listed_only_while_it_can_authenticate():
    local = local_credentials(Settings(FINGERPRINT_KEY=KEY, API_TOKEN="a" * 40))
    assert item(local, "API_TOKEN")["held_here"] is True
    oidc = local_credentials(Settings(FINGERPRINT_KEY=KEY, AUTH_MODE="oidc"))
    assert all(one["name"] != "API_TOKEN" for one in oidc["items"])


def test_workload_auth_reports_the_store_token_as_not_being_here():
    static = local_credentials(Settings(FINGERPRINT_KEY=KEY, SECRET_STORE_URL="https://vault.local",
                                        SECRET_STORE_TOKEN="s.token"))
    assert item(static, "SECRET_STORE_TOKEN")["held_here"] is True
    workload = local_credentials(Settings(FINGERPRINT_KEY=KEY, SECRET_STORE_URL="https://vault.local",
                                          SECRET_STORE_AUTH_MODE="kubernetes",
                                          SECRET_STORE_KUBERNETES_ROLE="cremore"))
    assert item(workload, "SECRET_STORE_TOKEN")["held_here"] is False
    assert item(workload, "SECRET_STORE_TOKEN")["where"] == "WORKLOAD_IDENTITY"


def test_the_oidc_client_secret_is_not_listed_because_this_process_never_holds_it():
    view = local_credentials(Settings(FINGERPRINT_KEY=KEY, AUTH_MODE="oidc",
                                      OIDC_ISSUER_URL="https://idp.example.com", OIDC_AUDIENCE="cremore"))
    # It belongs to oauth2-proxy. An inventory that lists what it cannot see is
    # worse than one that says which parts it speaks for.
    assert all("OIDC" not in one["name"] for one in view["items"])


# -- a status view stays a status view -----------------------------------------


def test_a_store_that_cannot_be_reached_is_reported_rather_than_raised(monkeypatch):
    def refuse(*args, **kwargs):
        raise ConnectionError("synthetic: the store is unreachable")

    monkeypatch.setattr("cremore_vault_provider.secretstore.kv_from_settings", refuse)
    view = local_credentials(Settings(
        FINGERPRINT_KEY=KEY, SEALING_KEY_VAULT_PATH="cremore/sealing-key",
        SECRET_STORE_URL="https://vault.local", SECRET_STORE_TOKEN="s.token"))
    assert view["sealing"]["root"] == "VAULT"
    assert view["sealing"]["key_id"] is None
    assert "SEALING_ROOT_UNREACHABLE" in view["reasons"]
    # The backend's own text can name a host or a path; only the code travels.
    assert "synthetic" not in json.dumps(view)


@pytest.mark.parametrize("env,root", [
    ({}, stored_locally.FINGERPRINT_KEY),
    ({"SEALING_KEY": OTHER}, stored_locally.ENVIRONMENT),
    ({"SEALING_PASSPHRASE": "correct horse battery staple"}, stored_locally.PASSPHRASE),
    ({"SEALING_KMS_KEY_ID": CMK, "SEALING_KEY_CIPHERTEXT": BLOB}, stored_locally.KMS),
    ({"SEALING_KEY_VAULT_PATH": "cremore/sealing-key"}, stored_locally.VAULT),
])
def test_the_root_is_named_without_reaching_anything(env, root):
    # Deciding which root is configured must not call out, or the screen would
    # be unusable exactly when an operator most needs it.
    assert stored_locally.sealing_root(Settings(FINGERPRINT_KEY=KEY, **env)) == root
