"""New vault facts stay distinct from value equality, AWS issuance and validity."""

import pytest

from cremore.coverage.models import ConnectionSpec, Observation, in_scope


def connection(**changes):
    return ConnectionSpec.model_validate({"name": "Vault", "provider": "openbao",
        "endpoint": "https://bao.example.test", "namespaces": ["team"],
        "include_token_accessors": True, "lease_prefixes": ["database/creds/app"], **changes})


def managed(**changes):
    return Observation.model_validate({"reference": "auth/token/accessors/handle-1", "mount": "auth/token",
        "namespace": "team", "evidence": "MANAGED", "credential_type": "VAULT_SERVICE_TOKEN",
        "version_state": "UNKNOWN", "vault_managed": {"kind": "SERVICE_TOKEN"}, **changes})


def test_management_scope_is_separate_from_kv_and_bound_to_enabled_namespace_and_prefix():
    spec = connection()
    assert in_scope(spec, managed())
    assert not in_scope(spec, managed(namespace="other"))
    assert not in_scope(connection(include_token_accessors=False), managed())
    lease = managed(reference="database/creds/app/lease-1", mount="database",
                    credential_type="VAULT_DYNAMIC_LEASE", vault_managed={"kind": "DYNAMIC_LEASE"})
    assert in_scope(spec, lease)
    assert not in_scope(spec, lease.model_copy(update={"reference": "database/creds/other/lease-1"}))
    assert not in_scope(spec, lease.model_copy(update={"reference": "database/creds/app/../escape"}))
    aws = ConnectionSpec(name="AWS", provider="aws_secrets_manager", account_id="123456789012", regions=["us-east-1"])
    assert not in_scope(aws, managed())


@pytest.mark.parametrize("changes", [{"fingerprint": "a" * 64}, {"state": "ACTIVE"},
    {"identifier": "arbitrary"}, {"version_state": "CURRENT"}, {"credential_type": "AWS_ACCESS_KEY"},
    {"vault_managed": {"kind": "SERVICE_TOKEN", "lookup_status": "FAILED", "ttl_seconds": 60}}])
def test_management_cannot_claim_fingerprint_or_validity(changes):
    with pytest.raises(ValueError):
        managed(**changes)


@pytest.mark.parametrize("prefix", ["", "database", "database/../secret", "database/%2fsecret", "database/creds?x=y"])
def test_lease_listing_requires_explicit_safe_prefix(prefix):
    with pytest.raises(ValueError):
        connection(lease_prefixes=[prefix])


def test_new_options_default_off_and_reject_other_providers():
    spec = ConnectionSpec(name="AWS", provider="aws_iam", account_id="123456789012")
    assert not spec.include_previous_versions and not spec.include_token_accessors and not spec.lease_prefixes
    for option in ({"include_previous_versions": True}, {"include_token_accessors": True},
                   {"lease_prefixes": ["database/creds/app"]}):
        with pytest.raises(ValueError):
            ConnectionSpec.model_validate({**spec.model_dump(), **option})


def test_provider_digest_is_private_github_value_comparison_evidence_only():
    row = Observation(reference="app/token", evidence="VALUE", credential_type="GITHUB_TOKEN",
                      fingerprint="a" * 64, provider_digest="b" * 64)
    assert row.provider_digest == "b" * 64
    for changes in ({"credential_type": "GITLAB_TOKEN"}, {"evidence": "UNRESOLVED", "fingerprint": None,
                                                          "reason": "UNRECOGNIZED_MATERIAL"}):
        with pytest.raises(ValueError):
            Observation.model_validate({**row.model_dump(), **changes})
    with pytest.raises(ValueError):
        managed(provider_digest="b" * 64)


def test_issuer_identifier_accepts_only_passive_gcp_email_and_key_id_value_evidence():
    identifier = "serviceAccountKey:app@sample-project.iam.gserviceaccount.com:" + "a" * 40
    row = Observation(reference="app/key", evidence="VALUE", credential_type="GCP_SERVICE_ACCOUNT",
                      fingerprint="a" * 64, issuer_identifier=identifier)
    assert row.issuer_identifier == identifier
    for changes in ({"credential_type": "GITHUB_TOKEN"}, {"issuer_identifier": identifier + ":other"},
                    {"issuer_identifier": identifier.replace("gserviceaccount.com", "example.test")},
                    {"issuer_identifier": identifier.replace("app@", "glpat-synthetic@")},
                    {"issuer_identifier": identifier[:-40] + "../key"}):
        with pytest.raises(ValueError):
            Observation.model_validate({**row.model_dump(), **changes})


@pytest.mark.parametrize("email", ["robot@project.iam.gserviceaccount.com", "123@developer.gserviceaccount.com", "project@appspot.gserviceaccount.com"])
def test_gcp_identifier_uses_the_provider_resource_grammar(email):
    from cremore.coverage.metadata_models import MetadataValueMatch
    identifier = f"serviceAccountKey:{email}:" + "a" * 40
    assert Observation(reference="fixture", evidence="VALUE", credential_type="GCP_SERVICE_ACCOUNT",
                       fingerprint="a" * 64, issuer_identifier=identifier).issuer_identifier == identifier
    assert MetadataValueMatch(evidence="VALUE", reference="fixture", credential_type="GCP_SERVICE_ACCOUNT",
        fingerprint="a" * 64, issuer_identifier=identifier, key_id="a" * 64, engine_digest="b" * 64,
        policy_digest="c" * 64, read_at="2026-09-25T00:00:00Z").issuer_identifier == identifier
    invalid = f"serviceAccountKey:{email}:legacy_key_1"
    with pytest.raises(ValueError):
        Observation(reference="fixture", evidence="VALUE", credential_type="GCP_SERVICE_ACCOUNT",
                    fingerprint="a" * 64, issuer_identifier=invalid)
    with pytest.raises(ValueError):
        MetadataValueMatch(evidence="VALUE", reference="fixture", credential_type="GCP_SERVICE_ACCOUNT",
            fingerprint="a" * 64, issuer_identifier=invalid, key_id="a" * 64, engine_digest="b" * 64,
            policy_digest="c" * 64, read_at="2026-09-25T00:00:00Z")


def test_server_keeps_management_gaps_separate_from_value_storage():
    import uuid

    from cremore.coverage.correlation import report
    from cremore.coverage.models import Batch, Contract, Finish
    from cremore.coverage.store import CoverageStore
    from cremore.db.repository import InMemoryRepository
    repo = InMemoryRepository()
    store = CoverageStore(repo)
    spec = connection()
    owner, _ = store.create(spec, "test")
    contract = Contract(engine_digest="a" * 64).model_dump()
    run = store.start(owner["id"], 1, str(uuid.uuid4()), contract)
    failed = managed(vault_managed={"kind": "SERVICE_TOKEN", "lookup_status": "FAILED"}, reason="LOOKUP_DENIED")
    store.append(owner["id"], run["id"], Batch(index=0, items=[failed]))
    result = store.finish(owner["id"], run["id"], Finish(batch_count=1, item_count=1, status="COMPLETE"))
    # A management gap stays on its row and the run's reasons; it never makes the KV listing partial.
    assert result["status"] == "COMPLETE" and result["completeness"] == "API_LISTING"
    assert "BATCH_TOKEN_INVENTORY_UNSUPPORTED" in result["reasons"]
    view = report(repo, contract)
    [row] = view["items"]
    assert row["origin"] == "MANAGEMENT" and row["state"] == "UNKNOWN" and row["locations"] == []
    assert {"LOOKUP_DENIED", "BATCH_TOKEN_INVENTORY_UNSUPPORTED"} <= set(row["reasons"])
    assert view["summary"]["exposed"] == view["summary"]["matched"] == view["summary"]["managed"] == 0


@pytest.mark.parametrize("reasons", [[], ["VAULT_HTTP_403"], ["VAULT_HTTP_403", "TOKEN_ACCESSOR_LIST_FAILED"]])
def test_an_explicit_failed_kv_submission_is_never_promoted_by_a_reason_the_server_adds(reasons):
    import uuid

    from cremore.coverage.correlation import report, scope_revision
    from cremore.coverage.models import Contract, Finish
    from cremore.coverage.store import CoverageStore
    from cremore.db.repository import InMemoryRepository
    repo = InMemoryRepository()
    store = CoverageStore(repo)
    owner, _ = store.create(connection(mounts=[{"name": "kv", "prefixes": ["app"]}]), "test")
    contract = Contract(engine_digest="a" * 64).model_dump()
    run = store.start(owner["id"], 1, str(uuid.uuid4()), contract)
    # include_token_accessors makes the server add BATCH_TOKEN_INVENTORY_UNSUPPORTED; that never explains a failure.
    result = store.finish(owner["id"], run["id"], Finish(batch_count=0, item_count=0, status="FAILED", reasons=reasons))
    assert result["status"] == "FAILED" and result["completeness"] is None
    repo.put_setting("coverage_scope", {"confirmed": True, "revision": scope_revision(store.list_connections())}, "test")
    view = report(repo, contract)
    assert view["absence_basis"] is None and "COLLECTION_FAILED" in view["scope_reasons"]
