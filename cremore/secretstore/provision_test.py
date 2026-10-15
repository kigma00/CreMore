import json
import os
import stat

import pytest
from cryptography.hazmat.primitives import serialization

from cremore.secretstore.isolation import RecipientKeys, binding_for_record
from cremore.secretstore.provision import bindings_for, main, provision
from cremore.secretstore.sealed import SealedSecretError


def plan():
    return {"version": 1, "connections": [
        {"provider": "github", "auth_method": "github_app", "target": {}, "purposes": ["exposure"]},
        {"provider": "github", "auth_method": "github_app", "target": {}, "purposes": ["remediation"]},
    ]}


def test_offline_bundle_is_separate_and_never_overwritten(tmp_path):
    target = tmp_path / "keys"
    assert provision(plan(), target) == {"groups": 2, "roles": ["collector", "remediator"]}
    pub = target / "recipients.json"
    public = RecipientKeys.from_files(pub)
    reader = RecipientKeys.from_files(pub, target / "collector-private.json")
    actor = RecipientKeys.from_files(pub, target / "remediator-private.json")
    binding = binding_for_record(plan()["connections"][0])
    ref = public.seal({"token": "synthetic-test-only"}, binding)
    assert reader.open(ref, binding) == {"token": "synthetic-test-only"}
    for ring in (public, actor):
        with pytest.raises(SealedSecretError):
            ring.open(ref, binding)
    signer = serialization.load_pem_private_key((target / "KEEP-OFF-SERVER/approval-private.pem").read_bytes(), None)
    verifier = serialization.load_pem_public_key((target / "approval-public.pem").read_bytes())
    verifier.verify(signer.sign(b"synthetic-plan"), b"synthetic-plan")
    before = pub.read_bytes()
    with pytest.raises(FileExistsError):
        provision(plan(), target)
    assert pub.read_bytes() == before
    if os.name == "posix":
        assert stat.S_IMODE(target.stat().st_mode) == 0o700
        assert stat.S_IMODE(pub.stat().st_mode) == 0o600


def test_canonical_groups_deduplicate_and_machine_binding_uses_production_validator():
    from cremore.identity.machine import machine_binding, validate

    value = plan()
    value["connections"].append(value["connections"][0])
    assert len(bindings_for(value)) == 2
    idp = {"token_url": "https://idp.example.test/oauth2/token", "client_id": "cremore"}
    value["connections"].append({"provider": "machine_identity", "idp": idp})
    assert bindings_for(value)[-1] == machine_binding(validate({"idp": idp}, None))


def test_cli_does_not_print_key_material_or_overwrite(tmp_path, capsys):
    config = tmp_path / "plan.json"
    config.write_text(json.dumps(plan()))
    main(["--plan", str(config), "--output", str(tmp_path / "bundle")])
    assert "PRIVATE KEY" not in capsys.readouterr().out
    with pytest.raises(SystemExit) as error:
        main(["--plan", str(config), "--output", str(tmp_path / "bundle")])
    assert error.value.code == 1


def test_provider_context_is_normalized_like_onboarding_and_unsupported_purpose_rejected():
    keycloak = {"provider": "keycloak", "auth_method": "oauth_client", "purposes": ["identity"],
        "target": {"address": "https://idp.example.test/", "realm": "staff", "api_path": "/auth/"}}
    context = bindings_for({"version": 1, "connections": [keycloak]})[0]["authority"]
    assert context["api_path"] == "/auth" and context["address"] == "https://idp.example.test"
    with pytest.raises(ValueError):
        bindings_for({"version": 1, "connections": [{**keycloak, "purposes": ["remediation"]}]})
