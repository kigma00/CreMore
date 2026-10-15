"""PEM-to-JSON identifier binding is local, bounded and keeps ambiguity."""

import json
from collections.abc import Mapping

import pytest

from cremore_gcp_provider.metadata.linkage import (
    service_account_key_identifier,
    service_account_key_identifiers,
)

from .fake import EMAIL, KEY_ID

PEM = b"-----BEGIN PRIVATE KEY-----\n" + b"A" * 128 + b"\n-----END PRIVATE KEY-----"
IDENTIFIER = f"serviceAccountKey:{EMAIL}:{KEY_ID}"


def candidate(**changes):
    return {"type": "service_account", "client_email": EMAIL, "private_key_id": KEY_ID,
            "private_key": PEM.decode() + "\n", **changes}


def encoded(value):
    return json.dumps(value).encode()


def test_identity_only_helper_reads_no_secret_or_project_field():
    class OnlyIdentifiers(Mapping):
        def __getitem__(self, key):
            if key not in {"type", "client_email", "private_key_id"}:
                raise AssertionError("non-identifier field read")
            return candidate()[key]

        def __iter__(self):
            raise AssertionError("candidate iteration")

        def __len__(self):
            return 3

    assert service_account_key_identifier(OnlyIdentifiers()) == IDENTIFIER


@pytest.mark.parametrize("value", [None, [], "not-json", {},
    candidate(type="authorized_user"), candidate(client_email="not-email"),
    candidate(private_key_id="../key")])
def test_identity_helper_refuses_invalid_candidates(value):
    assert service_account_key_identifier(value) is None


@pytest.mark.parametrize("pem", [PEM, PEM.replace(b"\n", b"\\n"), PEM.replace(b"\n", b"\r\n")])
def test_json_escaped_newlines_bind_to_the_same_detected_pem(pem):
    assert service_account_key_identifiers(encoded(candidate()), pem) == (IDENTIFIER,)


def test_nested_multiline_pretty_json_and_crlf_pem_are_supported():
    data = json.dumps({"keys": [candidate(private_key=PEM.decode().replace("\n", "\r\n"))]}, indent=2).encode()
    assert service_account_key_identifiers(data, PEM) == (IDENTIFIER,)


def test_multiple_objects_pair_only_metadata_attached_to_the_detected_pem():
    other = candidate(private_key_id="f" * 40, private_key=PEM.decode().replace("A", "B"))
    assert service_account_key_identifiers(encoded([candidate(), other]), PEM) == (IDENTIFIER,)


def test_reused_pem_with_multiple_identities_preserves_ambiguity():
    other = candidate(private_key_id="f" * 40)
    result = service_account_key_identifiers(encoded([candidate(), other, candidate()]), PEM)
    assert result == tuple(sorted([IDENTIFIER, f"serviceAccountKey:{EMAIL}:" + "f" * 40]))


def test_unrelated_nearby_email_and_key_id_are_not_cross_paired():
    data = encoded({"private_key": PEM.decode(), "details": {
        "type": "service_account", "client_email": EMAIL, "private_key_id": KEY_ID}})
    assert service_account_key_identifiers(data, PEM) == ()


@pytest.mark.parametrize("data", [
    b"not JSON " + encoded(candidate()),
    encoded(candidate()) + b" extra",
    b'{"private_key":"one","private_key":"two"}',
    b'"not an object"', b'[{"a": NaN}]', b'\xff',
    b" " * (1024 * 1024 + 1),
    b"[" * 40 + encoded(candidate()) + b"]" * 40,
    encoded([candidate(), *[0 for _ in range(1100)]]),
], ids=["invalid-prefix", "trailing-text", "duplicate-fields", "scalar", "nonfinite", "invalid-utf8",
        "oversized", "too-deep", "too-many-nodes"])
def test_invalid_or_unbounded_documents_never_produce_a_partial_link(data):
    assert service_account_key_identifiers(data, PEM) == ()


def test_duplicate_fields_reject_otherwise_matching_json():
    valid = encoded(candidate())
    ambiguous = b'{"client_email":"unexpected",' + valid[1:]
    assert service_account_key_identifiers(ambiguous, PEM) == ()


def test_malformed_or_unrelated_pem_does_not_bind():
    assert service_account_key_identifiers(encoded(candidate()), PEM.replace(b"A", b"B")) == ()
    assert service_account_key_identifiers(encoded(candidate()), b"not pem") == ()
    assert service_account_key_identifiers(encoded(candidate()), b"x" * 20000) == ()


def test_private_key_and_unrelated_fields_never_appear_in_result():
    data = encoded(candidate(project_id="untrusted-project", access_token="DO_NOT_RETAIN"))
    result = service_account_key_identifiers(data, PEM)
    assert result == (IDENTIFIER,)
    assert "PRIVATE KEY" not in repr(result) and "DO_NOT_RETAIN" not in repr(result)


def test_standalone_and_product_share_the_same_functions():
    from cremore_gcp import linkage

    assert service_account_key_identifier is linkage.service_account_key_identifier
    assert service_account_key_identifiers is linkage.service_account_key_identifiers


def test_value_projection_preserves_private_provider_digest_without_exposing_native_metadata():
    from types import SimpleNamespace

    from cremore_gcp_provider.metadata import adapter
    from cremore_gcp_provider.metadata.normalization import observation, value_match

    from .fake import PROJECT, spec

    context = {"key_id": "a" * 64, "engine_digest": "b" * 64, "policy_digest": "c" * 64}
    observed = SimpleNamespace(evidence="VALUE", credential_type="GITHUB_TOKEN", fingerprint="d" * 64,
                               identifier="", reason=None, provider_digest="e" * 64)
    result = value_match(context, "projects/test-project/locations/global/keys/key-id",
                         observation_row=observed)
    assert result.provider_digest == "e" * 64
    connection = spec()
    entity = observation(connection, connection.scopes[0], {
        "source": "gcp_api_keys", "object_type": "credential", "credential_type": "api_key",
        "project_id": PROJECT, "source_id": "projects/test-project/locations/global/keys/key-id",
        "key_id": "key-id",
    }, value_match=result)
    assert "e" * 64 not in repr(adapter.native_snapshots([entity.model_dump()]))
    assert "e" * 64 not in repr(adapter.compare_records([entity.model_dump()], []))
    del observed.provider_digest
    assert value_match(context, "projects/test-project/locations/global/keys/key-id",
                       observation_row=observed).provider_digest is None


def test_value_projection_preserves_passive_issuer_identifier_with_legacy_default():
    from types import SimpleNamespace

    from cremore_gcp_provider.metadata.normalization import value_match

    context = {"key_id": "a" * 64, "engine_digest": "b" * 64, "policy_digest": "c" * 64}
    observed = SimpleNamespace(evidence="VALUE", credential_type="GCP_SERVICE_ACCOUNT",
                               fingerprint="d" * 64, identifier="", reason=None,
                               issuer_identifier=IDENTIFIER)
    result = value_match(context, "projects/test-project/secrets/key/versions/1",
                         observation_row=observed)
    assert result.issuer_identifier == IDENTIFIER
    assert result.provider_digest is None
    del observed.issuer_identifier
    assert value_match(context, "projects/test-project/secrets/key/versions/1",
                       observation_row=observed).issuer_identifier == ""
