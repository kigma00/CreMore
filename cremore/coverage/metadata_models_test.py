"""Metadata contracts remain usable without persistence dependencies."""

import subprocess
import sys

import pytest

from cremore.coverage.correlation import is_vault_spec
from cremore.coverage.metadata_models import (
    EntityIdentity,
    EntityObservation,
    MetadataConnectionSpec,
    MetadataOptions,
    MetadataPayloadDigest,
    MetadataProvenance,
    MetadataValueMatch,
    checkpoint_json,
    in_metadata_scope,
    metadata_text,
)


def test_checkpoint_validation_does_not_import_the_database():
    subprocess.run([sys.executable, "-c", """
import sys
from cremore.coverage.metadata_models import checkpoint_json

state = {"cursor": {"page": 2}, "requests": 3}
assert checkpoint_json(state) == state
try:
    checkpoint_json({"cursor": {"access_token": "synthetic"}})
except ValueError as error:
    assert str(error) == "TASK_PAYLOAD_CONTAINS_CONTENT_OR_CREDENTIALS"
else:
    raise AssertionError("Credential fields must be rejected")
assert not any(name == "cremore.db" or name.startswith("cremore.db.")
               or name == "sqlalchemy" or name.startswith("sqlalchemy.")
               for name in sys.modules)
"""], check=True)


@pytest.mark.parametrize("prefix", ["adm_", "secret_"])
def test_notion_admin_and_legacy_values_cannot_enter_metadata_or_checkpoints(prefix):
    material = prefix + "a" * 30
    with pytest.raises(ValueError, match="UNSAFE_METADATA"):
        metadata_text(material)
    with pytest.raises(ValueError, match="UNSAFE_METADATA_CHECKPOINT"):
        checkpoint_json({"cursor": material})
    assert metadata_text("secret_rotation_policy") == "secret_rotation_policy"
    assert metadata_text("non_secret_fields_except_approved_exclusions") == "non_secret_fields_except_approved_exclusions"


def azure_value_spec(**changes):
    return MetadataConnectionSpec.model_validate({
        "name": "Approved vault", "provider": "azure_key_vault",
        "origin": "https://approved-vault.vault.azure.net",
        "scopes": [{"kind": "vault", "id": "approved-vault"}],
        "capabilities": ["vault_metadata", "vault_value"], "auth_type": "workload_identity",
        "options": {"include_values": True}, **changes,
    })


def test_azure_value_comparison_requires_opt_in_but_never_allows_raw_persistence():
    spec = azure_value_spec()
    assert is_vault_spec(spec.model_dump())
    assert not is_vault_spec(azure_value_spec(options={}).model_dump())
    with pytest.raises(ValueError, match="GCP_VALUE_COLLECTION_REQUIRED"):
        azure_value_spec(options={"include_values": True, "store_values": True})
    with pytest.raises(ValueError, match="VALUE_CAPABILITY_REQUIRED"):
        azure_value_spec(capabilities=["vault_metadata"])
    with pytest.raises(ValueError, match="VAULT_VALUE_CAPABILITY_NOT_SUPPORTED"):
        azure_value_spec(provider="azure_entra")


def test_legacy_storage_option_is_consumed_without_reenabling_persistence():
    from cremore.api.metadata_coverage import MetadataChange

    for provider, origin, scopes, capabilities in (
            ("gcp", "https://googleapis.com", [{"kind": "project", "id": "approved"}], ["inventory"]),
            ("notion", "https://api.notion.com", [{"kind": "workspace", "id": "approved"}], ["inventory"])):
        for legacy in ([False, True] if provider == "gcp" else [False]):
            body = {"name": "Approved", "provider": provider, "origin": origin, "scopes": scopes,
                    "capabilities": capabilities, "options": {"store_values": legacy}}
            spec = MetadataConnectionSpec.model_validate(body)
            assert "store_values" not in spec.model_dump()["options"]
            assert not spec.options.include_values
            assert body["options"] == {"store_values": legacy}
            with pytest.raises(ValueError, match="RAW_VALUE_STORAGE_REMOVED"):
                MetadataChange.model_validate({"revision": 1, "spec": body})
            MetadataChange.model_validate({"revision": 1, "spec": spec.model_dump()})
    for invalid in ("true", 1, None):
        with pytest.raises(ValueError, match="GCP_VALUE_COLLECTION_REQUIRED"):
            MetadataConnectionSpec.model_validate({**body, "provider": "gcp", "options": {"store_values": invalid}})


def test_gcp_payload_digest_cannot_bypass_value_scope_or_key_identity():
    spec = MetadataConnectionSpec(name="Approved", provider="gcp", origin="https://googleapis.com",
        scopes=[{"kind": "project", "id": "approved"}], capabilities=["vault_metadata", "vault_value"],
        options={"include_values": True})
    item = EntityObservation(scope=spec.scopes[0], purpose="vault_metadata",
        identity=EntityIdentity(provider="gcp", origin=spec.origin, kind="vault_version", object_id="approved"),
        provenance=MetadataProvenance(operation="gcp.value_access", observed_at="2026-10-02T00:00:00Z"),
        value_match=MetadataValueMatch(evidence="UNRESOLVED", reason="EMPTY",
            reference="projects/approved/secrets/approved/versions/1", key_id="b" * 64,
            engine_digest="c" * 64, policy_digest="d" * 64, read_at="2026-10-02T00:00:00Z"),
        payload_digest=MetadataPayloadDigest(key_id="b" * 64, fingerprint="a" * 64))
    assert in_metadata_scope(spec, item)
    for update in ({"options": MetadataOptions()}, {"capabilities": ["vault_metadata"]}):
        assert not in_metadata_scope(spec.model_copy(update=update), item)
    assert not in_metadata_scope(spec, item.model_copy(update={"value_match": item.value_match.model_copy(
        update={"reference": "projects/unapproved/secrets/approved/versions/1"})}))
    for update in ({"value_match": None}, {"payload_digest": {"key_id": "c" * 64, "fingerprint": "a" * 64}},
                   {"identity": {**item.identity.model_dump(), "provider": "azure_key_vault"}}):
        with pytest.raises(ValueError, match="GCP_PAYLOAD_VALUE_EVIDENCE_REQUIRED"):
            EntityObservation.model_validate({**item.model_dump(), **update})


@pytest.mark.parametrize("reference,accepted", [
    ("https://approved-vault.vault.azure.net/secrets/app/abcd1234", True),
    ("https://approved-vault.vault.azure.net/secrets/app", True),
    ("https://another-vault.vault.azure.net/secrets/app/abcd1234", False),
    ("https://approved-vault.vault.azure.net/secrets/../other", False),
    ("https://approved-vault.vault.azure.net/secrets/app?version=abcd1234", False),
    ("https://approved-vault.vault.azure.net/keys/app", False),
])
def test_azure_value_observations_remain_bound_to_the_approved_vault(reference, accepted):
    spec = azure_value_spec()
    item = EntityObservation(
        scope=spec.scopes[0], purpose="vault_metadata",
        provenance=MetadataProvenance(operation="azure.key_vault.value_access", observed_at="2026-09-25T00:00:00Z"),
        identity=EntityIdentity(provider=spec.provider, origin=spec.origin, kind="vault_item",
                                object_id="secret:approved-vault:app"),
        value_match=MetadataValueMatch(evidence="VALUE", reference=reference, fingerprint="a" * 64,
            credential_type="GITHUB_TOKEN", key_id="b" * 64, engine_digest="c" * 64,
            policy_digest="d" * 64, read_at="2026-09-25T00:00:00Z"),
    )
    assert in_metadata_scope(spec, item) is accepted
    assert not in_metadata_scope(azure_value_spec(options={}), item)


def test_provider_hash_contract_requires_explicit_opt_in_and_exact_inventory_identity():
    spec = MetadataConnectionSpec.model_validate({
        "name": "Enterprise", "provider": "github", "origin": "https://github.com",
        "scopes": [{"kind": "enterprise", "id": "approved"}],
        "capabilities": ["inventory", "issuer_digest"], "options": {"include_provider_hashes": True},
    })
    item = EntityObservation(scope=spec.scopes[0],
        provenance=MetadataProvenance(operation="enterprise_credentials", observed_at="2026-09-25T00:00:00Z"),
        identity=EntityIdentity(provider="github", origin=spec.origin, kind="credential", object_id="inventory:1"),
        value_match=MetadataValueMatch(evidence="PROVIDER_DIGEST", reference="inventory:1", fingerprint="a" * 64,
            scheme="github-token-sha256/hmac-sha256-v1", key_id="b" * 64, engine_digest="c" * 64,
            policy_digest="d" * 64, read_at="2026-09-25T00:00:00Z"))
    assert in_metadata_scope(spec, item)
    assert not in_metadata_scope(spec.model_copy(update={"options": MetadataOptions()}), item)
    assert not in_metadata_scope(spec, item.model_copy(update={"value_match": item.value_match.model_copy(update={"reference": "inventory:2"})}))
    with pytest.raises(ValueError, match="PROVIDER_DIGEST_SCHEME_REQUIRED"):
        MetadataValueMatch.model_validate({**item.value_match.model_dump(), "evidence": "VALUE"})
    with pytest.raises(ValueError, match="ISSUER_DIGEST_CAPABILITY_NOT_SUPPORTED"):
        MetadataConnectionSpec.model_validate({**spec.model_dump(), "provider": "notion"})


def test_storage_key_comparison_cannot_expand_the_approved_account_or_subscription():
    subscription = "11111111-2222-4333-8444-555555555555"
    account = f"/subscriptions/{subscription}/resourceGroups/approved/providers/Microsoft.Storage/storageAccounts/approved"
    spec = MetadataConnectionSpec.model_validate({
        "name": "Storage", "provider": "azure_resource_manager", "origin": "https://management.azure.com",
        "tenant": "22222222-2222-4333-8444-555555555555", "tenant_confirmed": True,
        "scopes": [{"kind": "subscription", "id": subscription}],
        "capabilities": ["inventory", "issuer_value"],
        "options": {"include_values": True, "azure_storage_accounts": [account]},
    })
    item = EntityObservation(scope=spec.scopes[0],
        provenance=MetadataProvenance(operation="azure.storage.keys", observed_at="2026-09-25T00:00:00Z"),
        identity=EntityIdentity(provider=spec.provider, origin=spec.origin, tenant=spec.tenant,
            tenant_confirmed=True, kind="credential", object_id=account + "/keys/key1"),
        value_match=MetadataValueMatch(evidence="VALUE", reference=account + "/keys/key1", fingerprint="a" * 64,
            key_id="b" * 64, engine_digest="c" * 64, policy_digest="d" * 64, read_at="2026-09-25T00:00:00Z"))
    assert in_metadata_scope(spec, item)
    for reference in (account + "/keys/unknown", account.replace("storageAccounts/approved", "storageAccounts/other") + "/keys/key1"):
        assert not in_metadata_scope(spec, item.model_copy(update={"value_match": item.value_match.model_copy(update={"reference": reference})}))
    assert not in_metadata_scope(spec.model_copy(update={"options": MetadataOptions(include_values=True)}), item)
    with pytest.raises(ValueError, match="DUPLICATE_AZURE_STORAGE_ACCOUNT"):
        MetadataOptions(azure_storage_accounts=[account, account])


def test_a_storage_account_in_a_unicode_resource_group_can_be_approved():
    # The ARM inventory accepts Azure's Unicode resource group names, so the approval must too.
    account = ("/subscriptions/11111111-2222-4333-8444-555555555555/resourceGroups/운영-자원(1)"
               "/providers/Microsoft.Storage/storageAccounts/approved")
    assert MetadataOptions(azure_storage_accounts=[account]).azure_storage_accounts == [account]
    with pytest.raises(ValueError, match="INVALID_AZURE_STORAGE_ACCOUNT"):
        MetadataOptions(azure_storage_accounts=[account.replace("운영-자원(1)", "a/b")])


@pytest.mark.parametrize("path", ["https://elsewhere", "/../admin", "/a%2fb", "/a?x=1", "/a\\b", "/a/"])
def test_dc_context_path_is_not_an_arbitrary_request_target(path):
    with pytest.raises(ValueError):
        MetadataOptions(api_path=path)
    assert MetadataOptions(api_path="/bitbucket").api_path == "/bitbucket"


@pytest.mark.parametrize("option", [{"actions_run_days": 7}, {"audit_scope": "enterprise"},
                                    {"enterprise_only": True}, {"run_time_limit_minutes": 30}])
def test_github_only_options_are_refused_for_other_providers(option):
    with pytest.raises(ValueError, match="GITHUB_OPTIONS_NOT_SUPPORTED"):
        azure_value_spec(options={"include_values": True, **option})
    defaults = MetadataOptions()
    assert (defaults.actions_run_days, defaults.audit_scope, defaults.enterprise_only,
            defaults.run_time_limit_minutes) == (None, "both", False, None)


def test_run_time_limit_cap_stays_inside_the_run_lifetime():
    from cremore.coverage.store import RUN_LIFETIME

    for minutes in (0, 301):
        with pytest.raises(ValueError):
            MetadataOptions(run_time_limit_minutes=minutes)
    assert MetadataOptions(run_time_limit_minutes=300).run_time_limit_minutes == 300
    assert 300 * 60 < RUN_LIFETIME.total_seconds()
