"""What an Azure Key Vault listing may and may not be read as saying.

The native adapter's one wrong claim is the first thing tested here: it filled
``last_rotated_at`` from ``updated_on``, so editing a tag reported a rotation.
Everything else covers a way this collection could report something untrue --
a pinned vault that a response redirects away from, a partial page counted as a
complete listing, or an operator's tag standing in for the provider's state.
"""

from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace

import pytest

from cremore.coverage.metadata_models import MetadataConnectionSpec
from cremore.coverage.providers import validate_record as shared_validate
from cremore_azure_provider.metadata import adapter, transport
from cremore_azure_provider.metadata.normalization import (
    ROTATION_UNKNOWN,
    TAGS_OMITTED,
    UPDATED_IS_NOT_ROTATION,
    epoch,
)

VAULT = "acme-prod"
ORIGIN = f"https://{VAULT}.vault.azure.net"
SPEC = {
    "schema_version": 2, "name": "Acme production vault", "provider": "azure_key_vault",
    "origin": ORIGIN, "edition": "cloud", "scopes": [{"kind": "vault", "id": VAULT}],
    "capabilities": ["vault_metadata"], "auth_type": "workload_identity",
    "options": {"mode": "inventory"},
}
CREATED = 1_726_000_000
UPDATED = 1_758_000_000


def spec(**changes):
    return MetadataConnectionSpec.model_validate({**SPEC, **changes})


def secret(name="db-password", *, version="", tags=None, enabled=True, exp=None, updated=UPDATED):
    identifier = f"{ORIGIN}/secrets/{name}" + (f"/{version}" if version else "")
    attributes = {"enabled": enabled, "created": CREATED, "updated": updated,
                  "recoveryLevel": "Recoverable+Purgeable", "recoverableDays": 90}
    if exp is not None:
        attributes["exp"] = exp
    row = {"id": identifier, "attributes": attributes, "contentType": "text/plain"}
    if tags is not None:
        row["tags"] = tags
    return row


class Vault:
    """A synthetic data plane: one response list per path."""

    def __init__(self, responses, *, status=200):
        self.responses, self.calls, self.status = responses, [], status

    def get(self, path, params=None):
        self.calls.append((path, dict(params or {})))
        answer = self.responses.get(path, {"value": []})
        if isinstance(answer, list):
            index = min(sum(1 for call in self.calls if call[0] == path) - 1, len(answer) - 1)
            answer = answer[index]
        if isinstance(answer, transport.ApiError):
            raise answer
        return answer

    @property
    def options(self):
        from cremore.coverage.metadata_models import MetadataOptions
        return MetadataOptions()

    requests = 0


def collect(connection, vault, **kwargs):
    return list(adapter.collect_pages(connection, secrets={}, checkpoint=kwargs.pop("checkpoint", None),
                                      check=lambda: None, transport=vault, **kwargs))


def records(pages):
    return [record for page in pages for record in page.records]


def facts(record):
    from cremore_azure_provider.metadata.normalization import record_values
    return record_values(record.model_dump())


@pytest.mark.parametrize("identifier", ["https://other.vault.azure.net/secrets/example",
                                        ORIGIN + "/secrets/example?extra=value",
                                        ORIGIN + "/secrets/bad_name", "/secrets/example"])
def test_list_identifiers_must_belong_to_the_pinned_vault(identifier):
    pages = collect(spec(), Vault({"/secrets": {"value": [{"id": identifier}, secret()]}}))
    assert pages[-1].status == "PARTIAL"
    assert len([row for row in records(pages) if row.record_type == "entity_observation"]) == 1
    report = next(row for row in records(pages) if row.record_type == "operation_report"
                  and row.provenance.operation == "azure.key_vault.secrets")
    assert report.received_records == 2 and report.saved_records == 1


def test_version_must_belong_to_the_requested_secret():
    pages = collect(spec(options={"sources": ["secrets", "versions"]}), Vault({
        "/secrets": {"value": [secret("first")]},
        "/secrets/first/versions": {"value": [secret("second", version="abc")]} }))
    assert pages[-1].status == "PARTIAL"
    assert not any(row.record_type == "entity_observation" and row.identity.kind == "vault_version"
                   for row in records(pages))


# -- the claim that was wrong -------------------------------------------------


def test_a_property_change_is_never_recorded_as_a_rotation():
    pages = collect(spec(), Vault({"/secrets": {"value": [secret(tags={"team": "payments"})]}}))
    observation = next(r for r in records(pages) if r.record_type == "entity_observation")
    values = facts(observation)
    # The native adapter wrote updated_on into last_rotated_at, so editing a
    # tag reported a rotation that never happened.
    assert values["updated_at"] == epoch(UPDATED)
    assert "last_rotated_at" not in values
    assert "rotation_enabled" not in values
    body = observation.model_dump()
    assert "last_rotated_at" not in str(body)


def test_the_fact_allowlist_itself_refuses_the_name():
    from cremore.coverage.metadata_models import FACT_NAMES

    # Not a convention this package follows: the shared model cannot store it.
    assert "last_rotated_at" not in FACT_NAMES


def test_every_report_says_rotation_was_not_established():
    pages = collect(spec(), Vault({"/secrets": {"value": [secret()]}}))
    report = next(r for r in records(pages) if r.record_type == "operation_report")
    assert ROTATION_UNKNOWN in report.reasons
    assert UPDATED_IS_NOT_ROTATION in report.reasons


def test_an_operator_tag_is_left_out_with_its_reason():
    pages = collect(spec(), Vault({"/secrets": {"value": [
        secret(tags={"rotation_enabled": "true", "next_rotation_at": "2026-12-01"})]}}))
    observation = next(r for r in records(pages) if r.record_type == "entity_observation")
    # A tag is what the operator wrote on the object, not what Azure does.
    assert [(o.path, o.reason) for o in observation.omissions] == [("/tags", TAGS_OMITTED)]
    assert "rotation_enabled" not in str(observation.model_dump())


def test_a_secret_without_tags_records_no_omission():
    pages = collect(spec(), Vault({"/secrets": {"value": [secret()]}}))
    observation = next(r for r in records(pages) if r.record_type == "entity_observation")
    assert observation.omissions == []


# -- what the listing does say ------------------------------------------------


def test_a_secret_is_identified_by_vault_and_name_not_by_its_url():
    pages = collect(spec(), Vault({"/secrets": {"value": [secret("db-password")]}}))
    observation = next(r for r in records(pages) if r.record_type == "entity_observation")
    assert observation.identity.object_id == f"secret:{VAULT}:db-password"
    assert observation.identity.kind == "vault_item"
    assert observation.purpose == "vault_metadata"
    values = facts(observation)
    assert values["resource_name"] == f"{ORIGIN}/secrets/db-password"
    assert values["created_at"] == epoch(CREATED)
    assert values["recoverable_days"] == 90


@pytest.mark.parametrize("row,provider_state,normalized", [
    (secret(enabled=True), "enabled", "ACTIVE"),
    (secret(enabled=False), "disabled", "DISABLED"),
    (secret(exp=CREATED), "expired", "EXPIRED"),
])
def test_state_is_what_the_provider_published_not_a_check(row, provider_state, normalized):
    pages = collect(spec(), Vault({"/secrets": {"value": [row]}}))
    observation = next(r for r in records(pages) if r.record_type == "entity_observation")
    assert observation.provider_state == provider_state
    assert observation.normalized_state == normalized
    # Nothing here tried the secret; the provider said so and that is all.
    assert observation.state_basis == "PROVIDER_REPORTED"


def test_an_attributes_block_without_enabled_is_unknown_rather_than_active():
    row = secret()
    del row["attributes"]["enabled"]
    pages = collect(spec(), Vault({"/secrets": {"value": [row]}}))
    observation = next(r for r in records(pages) if r.record_type == "entity_observation")
    assert observation.normalized_state == "UNKNOWN" and observation.state_basis == "UNKNOWN"


@pytest.mark.parametrize("value", ["1758000000", True, None, 1e30, -1e30])
def test_a_timestamp_that_is_not_unix_seconds_is_not_a_time(value):
    assert epoch(value) is None


def test_versions_are_read_only_when_asked_for_and_carry_their_version_id():
    vault = Vault({"/secrets": {"value": [secret("db-password")]},
                   "/secrets/db-password/versions": {"value": [
                       secret("db-password", version="a1b2c3"), secret("db-password", version="d4e5f6")]}})
    pages = collect(spec(options={"mode": "inventory", "sources": ["secrets", "versions"]}), vault)
    versions = [r for r in records(pages) if getattr(r, "identity", None)
                and r.identity.kind == "vault_version"]
    assert {r.identity.object_id for r in versions} == {
        f"secretVersion:{VAULT}:db-password/versions/a1b2c3",
        f"secretVersion:{VAULT}:db-password/versions/d4e5f6"}
    assert facts(versions[0])["version_id"] in ("a1b2c3", "d4e5f6")


def test_a_source_that_was_not_requested_is_reported_rather_than_left_out():
    pages = collect(spec(), Vault({"/secrets": {"value": [secret()]}}))
    reports = {r.provenance.operation: r for r in records(pages) if r.record_type == "operation_report"}
    # A missing report and an empty one mean different things to a reader.
    assert reports["azure.key_vault.versions"].status == "NOT_REQUESTED"
    assert reports["azure.key_vault.deleted_secrets"].status == "NOT_REQUESTED"
    assert reports["azure.key_vault.secrets"].status == "COMPLETE"


def test_no_secret_listed_is_distinguished_from_versions_found_to_be_empty():
    vault = Vault({"/secrets": {"value": []}})
    pages = collect(spec(options={"mode": "inventory", "sources": ["secrets", "versions"]}), vault)
    report = next(r for r in records(pages)
                  if r.provenance.operation == "azure.key_vault.versions")
    assert "NO_SECRET_LISTED_TO_READ_VERSIONS_FOR" in report.reasons
    assert "/secrets/db-password/versions" not in [call[0] for call in vault.calls]


def test_a_deleted_secret_is_recorded_as_deleted():
    row = {**secret("retired"), "deletedDate": UPDATED}
    pages = collect(spec(options={"mode": "inventory", "sources": ["secrets", "deleted_secrets"]}),
                    Vault({"/secrets": {"value": []}, "/deletedsecrets": {"value": [row]}}))
    observation = next(r for r in records(pages) if getattr(r, "identity", None))
    assert observation.normalized_state == "DELETED"
    assert facts(observation)["deleted_at"] == epoch(UPDATED)


# -- the pinned vault ---------------------------------------------------------


def test_only_the_cursor_of_a_next_link_is_used_never_the_link():
    vault = Vault({"/secrets": [
        {"value": [secret("first")], "nextLink": f"{ORIGIN}/secrets?api-version=7.4&$skiptoken=page2"},
        {"value": [secret("second")]},
    ]})
    pages = collect(spec(), vault)
    assert [call[1].get("$skiptoken") for call in vault.calls if call[0] == "/secrets"] == [None, "page2"]
    assert len([r for r in records(pages) if getattr(r, "identity", None)]) == 2


def test_a_next_link_pointing_somewhere_else_is_refused():
    # Following it would send the bearer token to a host nobody approved.
    with pytest.raises(transport.ApiError):
        transport.skip_token("https://attacker.example.com/secrets?$skiptoken=x")
    with pytest.raises(transport.ApiError):
        transport.skip_token(f"{ORIGIN}/secrets?api-version=7.4")
    assert transport.skip_token("") == ""
    assert transport.skip_token(f"{ORIGIN}/secrets?$skiptoken=abc") == "abc"


def test_a_repeating_cursor_cannot_loop():
    vault = Vault({"/secrets": {"value": [secret()],
                                "nextLink": f"{ORIGIN}/secrets?$skiptoken=same"}})
    pages = collect(spec(), vault)
    assert pages[-1].status == "FAILED"
    assert "INVALID_RESPONSE" in pages[-1].reasons


@pytest.mark.parametrize("path", ["/secrets/db-password/a1b2c3", "/keys/db-key", "/secrets/../admin",
                                  "/secrets/db-password"])
def test_no_path_that_returns_a_value_can_be_requested(path):
    import httpx

    client = httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json={})))
    wire = transport.Transport(client, lambda: "synthetic", origin=ORIGIN,
                               options=spec().options, max_requests=10, api_version="7.4")
    with pytest.raises(ValueError):
        wire.get(path)


@pytest.mark.parametrize("origin", [
    "https://acme-prod.vault.example.com", "https://vault.azure.net",
    "https://acme-prod.vault.azure.net.attacker.test", "https://acme_prod.vault.azure.net",
])
def test_a_host_that_is_not_a_key_vault_is_refused(origin):
    with pytest.raises(ValueError):
        transport.vault_name(origin)


@pytest.mark.parametrize("suffix", ["azure.net", "azure.cn", "usgovcloudapi.net", "microsoftazure.de"])
def test_every_documented_sovereign_suffix_is_accepted(suffix):
    assert transport.vault_name(f"https://acme-prod.vault.{suffix}") == "acme-prod"


@pytest.fixture
def credential_calls(monkeypatch):
    options, scopes = [], []

    class Credential:
        def __init__(self, **kwargs):
            options.append(kwargs)

        def get_token(self, scope):
            scopes.append(scope)
            return SimpleNamespace(token="synthetic-ambient-token")

    identity = ModuleType("azure.identity")
    identity.DefaultAzureCredential = Credential
    monkeypatch.setitem(sys.modules, "azure.identity", identity)
    return options, scopes


@pytest.mark.parametrize("suffix,scope,authority", [
    ("azure.net", "https://vault.azure.net/.default", "login.microsoftonline.com"),
    ("azure.cn", "https://vault.azure.cn/.default", "login.chinacloudapi.cn"),
    ("usgovcloudapi.net", "https://vault.usgovcloudapi.net/.default", "login.microsoftonline.us"),
    ("microsoftazure.de", "https://vault.microsoftazure.de/.default", "login.microsoftonline.de"),
])
def test_ambient_credentials_match_the_vault_cloud(credential_calls, suffix, scope, authority):
    import httpx

    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(200, json={"value": []})

    origin = f"https://{VAULT}.vault.{suffix}"
    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        pages = list(adapter.collect_pages(spec(origin=origin), secrets={}, checkpoint=None,
                                           check=lambda: None, client=client))
    assert pages[-1].status == "COMPLETE"
    assert credential_calls == ([{**PERSONAL, "authority": authority}], [scope])
    assert len(requests) == 1
    assert requests[0].url.host == f"{VAULT}.vault.{suffix}"
    assert requests[0].url.path == "/secrets"
    assert requests[0].headers["authorization"] == "Bearer synthetic-ambient-token"


@pytest.mark.parametrize("args,scope", [
    ((), "https://vault.azure.net/.default"),
    (("https://custom-resource/.default",), "https://custom-resource/.default"),
])
def test_default_token_preserves_default_and_positional_scope(credential_calls, args, scope):
    assert transport.default_token(*args)() == "synthetic-ambient-token"
    assert credential_calls == ([PERSONAL], [scope])


# The worker's identity never comes from a person's sign-in on its host.
PERSONAL = {"exclude_cli_credential": True, "exclude_powershell_credential": True,
            "exclude_developer_cli_credential": True, "exclude_shared_token_cache_credential": True,
            "exclude_visual_studio_code_credential": True, "exclude_interactive_browser_credential": True,
            "exclude_broker_credential": True}


def test_the_ambient_credential_leaves_out_personal_sign_ins(monkeypatch):
    pytest.importorskip("azure.identity")
    monkeypatch.delenv("AZURE_TOKEN_CREDENTIALS", raising=False)
    names = {type(item).__name__ for item in transport.ambient_credential().credentials}
    # An allowlist: a person's credential a later SDK adds to its chain fails here too.
    assert "ManagedIdentityCredential" in names
    assert names <= {"EnvironmentCredential", "WorkloadIdentityCredential", "FailedDACCredential",
                     "ManagedIdentityCredential"}


def test_injected_token_bypasses_ambient_credentials(credential_calls):
    import httpx

    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(200, json={"value": []})

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        pages = list(adapter.collect_pages(spec(origin=f"https://{VAULT}.vault.azure.cn"),
                                           secrets={}, checkpoint=None, check=lambda: None,
                                           client=client, token=lambda: "injected-token"))
    assert pages[-1].status == "COMPLETE"
    assert credential_calls == ([], [])
    assert len(requests) == 1
    assert requests[0].headers["authorization"] == "Bearer injected-token"


def test_invalid_origin_is_refused_before_ambient_authentication(credential_calls):
    with pytest.raises(ValueError, match="AZURE_KEY_VAULT_ORIGIN_REQUIRED"):
        list(adapter.collect_pages(spec(origin="https://unapproved.example.com"), secrets={},
                                   checkpoint=None, check=lambda: None))
    assert credential_calls == ([], [])


# -- the connection contract --------------------------------------------------


@pytest.mark.parametrize("change", [
    {"auth_type": "token", "secret_refs": {"token": "vault://azure/token"}},
    {"capabilities": ["inventory"]},
    {"capabilities": ["vault_metadata", "audit"]},
    {"options": {"mode": "inventory", "include_values": True}},
    {"scopes": [{"kind": "project", "id": VAULT}]},
    {"scopes": [{"kind": "vault", "id": "other-vault"}]},
    {"scopes": [{"kind": "vault", "id": VAULT}, {"kind": "vault", "id": "second"}]},
    {"origin": "https://storage.azure.com"},
    {"edition": "self_managed"},
    {"principal_pin": "some-identity"},
    {"options": {"mode": "inventory", "sources": ["everything"]}},
])
def test_a_connection_this_package_cannot_honour_is_refused(change):
    with pytest.raises(ValueError):
        adapter.validate_spec(spec(**change))


def test_a_scope_that_does_not_name_the_endpoint_is_refused():
    # Records filed under a vault they were not read from would be a lie about
    # where the secret lives.
    with pytest.raises(ValueError):
        adapter.validate_spec(spec(scopes=[{"kind": "vault", "id": "other-vault"}]))


def test_a_record_for_another_vault_is_rejected_by_the_shared_guard():
    pages = collect(spec(), Vault({"/secrets": {"value": [secret()]}}))
    observation = next(r for r in records(pages) if r.record_type == "entity_observation")
    assert shared_validate(spec(), observation) is True
    moved = observation.model_copy(deep=True)
    moved.identity.object_id = "secret:other-vault:db-password"
    assert shared_validate(spec(), moved) is False


def test_a_submitted_record_must_name_this_vaults_own_resource():
    pages = collect(spec(), Vault({"/secrets": {"value": [secret()]}}))
    observation = next(r for r in records(pages) if r.record_type == "entity_observation")
    assert adapter.validate_machine_record(spec(), observation) is True
    elsewhere = observation.model_copy(deep=True)
    elsewhere.provenance.resource_id = "https://other.vault.azure.net/secrets/db-password"
    assert adapter.validate_machine_record(spec(), elsewhere) is False


def test_a_value_match_can_never_come_from_this_package():
    from cremore.coverage.metadata_models import MetadataValueMatch
    from cremore.coverage.models import digest

    pages = collect(spec(), Vault({"/secrets": {"value": [secret()]}}))
    observation = next(r for r in records(pages) if r.record_type == "entity_observation")
    forged = observation.model_copy(deep=True)
    forged.value_match = MetadataValueMatch(
        evidence="VALUE", reference=f"{ORIGIN}/secrets/db-password", fingerprint="a" * 64,
        key_id=digest(["k"]), engine_digest=digest(["e"]), policy_digest=digest(["p"]),
        read_at="2026-09-21T00:00:00+00:00")
    # No path here reads a value, so a value match did not come from a read.
    assert adapter.validate_record(spec(), forged) is False


def test_a_stored_secret_reference_is_refused_at_collection_too():
    with pytest.raises(ValueError):
        list(adapter.collect_pages(spec(), secrets={"token": "x"}, checkpoint=None,
                                   check=lambda: None, transport=Vault({})))


# -- restarting ---------------------------------------------------------------


def test_a_run_resumes_at_its_cursor_instead_of_re_reading():
    vault = Vault({"/secrets": [
        {"value": [secret("first")], "nextLink": f"{ORIGIN}/secrets?$skiptoken=page2"},
        {"value": [secret("second")]},
    ]})
    first = next(iter(adapter.collect_pages(spec(), secrets={}, checkpoint=None,
                                            check=lambda: None, transport=vault)))
    assert first.checkpoint["cursor"]["skiptoken"] == "page2"
    resumed = Vault({"/secrets": {"value": [secret("second")]}})
    pages = collect(spec(), resumed, checkpoint=first.checkpoint,
                    read_records=lambda: [r.model_dump() for r in first.records])
    assert [call[1].get("$skiptoken") for call in resumed.calls if call[0] == "/secrets"] == ["page2"]
    assert any(getattr(r, "identity", None) and r.identity.object_id.endswith("second")
               for r in records(pages))


def test_a_checkpoint_from_a_different_connection_is_refused():
    pages = collect(spec(), Vault({"/secrets": {"value": [secret()]}}))
    with pytest.raises(ValueError):
        collect(spec(name="Renamed"), Vault({}), checkpoint=pages[0].checkpoint,
                read_records=list)


def test_resuming_into_versions_uses_the_names_already_recorded():
    vault = Vault({"/secrets": {"value": [secret("db-password")]},
                   "/secrets/db-password/versions": {"value": [secret("db-password", version="a1")]}})
    scoped = spec(options={"mode": "inventory", "sources": ["secrets", "versions"]})
    pages = collect(scoped, vault)
    secrets_page = next(p for p in pages if p.checkpoint.get("phase") == "secrets")
    stored = [r.model_dump() for r in secrets_page.records]
    resumed = Vault({"/secrets/db-password/versions": {"value": [secret("db-password", version="a1")]}})
    again = collect(scoped, resumed, checkpoint=secrets_page.checkpoint,
                    read_records=lambda: stored)
    # The names come from the committed records, so the listing is not re-read.
    assert "/secrets" not in [call[0] for call in resumed.calls]
    assert any(getattr(r, "identity", None) and r.identity.kind == "vault_version"
               for r in records(again))


@pytest.mark.parametrize("code,status", [
    ("rate_limited", "WAITING"), ("provider_unavailable", "WAITING"),
    ("permission_denied", "FAILED"), ("authentication_failed", "FAILED"),
])
def test_a_provider_failure_is_a_state_not_a_smaller_listing(code, status):
    vault = Vault({"/secrets": transport.ApiError(code, retry_after=30)})
    pages = collect(spec(), vault)
    assert pages[-1].status == status
    if status == "WAITING":
        # A rate limit keeps the cursor and waits; it never records a result.
        assert pages[-1].retry_after_seconds == 30
        assert pages[-1].records == []


def test_a_record_ceiling_makes_the_run_partial():
    vault = Vault({"/secrets": {"value": [secret(f"secret-{index}") for index in range(5)]}})
    pages = collect(spec(max_records=2), vault)
    assert pages[-1].status == "PARTIAL"
    assert "RECORD_BUDGET_EXCEEDED" in pages[-1].reasons


# -- reading the records back -------------------------------------------------


def test_the_native_export_omits_the_claim_it_used_to_make():
    pages = collect(spec(), Vault({"/secrets": {"value": [secret(tags={"team": "x"})]}}))
    stored = [r.model_dump() for r in records(pages)]
    [snapshot] = adapter.native_snapshots(stored)
    assert snapshot["secret_count"] == 1
    entry = snapshot["secrets"][0]
    assert entry["updated_at"] == epoch(UPDATED)
    # Every field the native adapter produced is here except the wrong one.
    assert "last_rotated_at" not in entry
    assert entry["rotation_enabled"] is None and entry["tags"] is None
    assert {row["field"] for row in snapshot["omitted"]} == {
        "last_rotated_at", "rotation_enabled", "tags"}


def test_a_comparison_says_a_property_changed_not_that_a_secret_rotated():
    before = [r.model_dump() for r in records(collect(spec(), Vault({"/secrets": {"value": [secret()]}})))]
    after = [r.model_dump() for r in records(collect(spec(), Vault({"/secrets": {"value": [
        secret(updated=UPDATED + 3600), secret("new-secret")]}})))]
    result = adapter.compare_records(before, after)
    assert result["added"] == [f"secret:{VAULT}:new-secret"]
    assert result["removed"] == []
    assert result["changed"] == [{"object_id": f"secret:{VAULT}:db-password",
                                 "fields": ["updated_at"]}]
    assert UPDATED_IS_NOT_ROTATION in result["notes"]


def test_partial_parent_listing_cannot_prove_version_removal_even_for_legacy_reports():
    connection = spec(max_pages=1, options={"sources": ["secrets", "versions"], "page_size": 1})
    before = [r.model_dump() for r in records(collect(connection, Vault({
        "/secrets": {"value": [secret("previous")]},
        "/secrets/previous/versions": {"value": [secret("previous", version="v1")]}})))]
    pages = collect(connection, Vault({
        "/secrets": {"value": [secret("current")], "nextLink": ORIGIN + "/secrets?$skiptoken=next"},
        "/secrets/current/versions": {"value": [secret("current", version="v2")]}}))
    after = [r.model_dump() for r in records(pages)]
    versions = next(r for r in after if r["record_type"] == "operation_report"
                    and r["provenance"]["operation"] == "azure.key_vault.versions")
    assert pages[-1].status == "PARTIAL" and versions["status"] == "PARTIAL"
    assert "PARENT_LISTING_INCOMPLETE" in versions["reasons"]
    for status in ("PARTIAL", "COMPLETE"):
        versions["status"] = status  # Already saved pre-fix reports must also remain nonauthoritative.
        result = adapter.compare_records(before, after)
        assert result["removed"] == []
        assert any(item["object_id"].startswith("secretVersion:") for item in result["absence_not_evaluated"])
    complete = [r.model_dump() for r in records(collect(connection, Vault({"/secrets": {"value": []}})))]
    assert any(key.startswith("secretVersion:") for key in adapter.compare_records(before, complete)["removed"])


def test_no_accepted_parent_names_is_partial_when_parent_list_was_invalid():
    pages = collect(spec(options={"sources": ["secrets", "versions"]}), Vault({
        "/secrets": {"value": [{"id": "invalid"}]}}))
    versions = next(r for r in records(pages) if r.record_type == "operation_report"
                    and r.provenance.operation == "azure.key_vault.versions")
    assert versions.status == "PARTIAL" and "PARENT_LISTING_INCOMPLETE" in versions.reasons


def test_the_catalog_names_the_rotation_limit_first():
    from cremore.coverage.providers.catalog import descriptor

    entry = descriptor("azure_key_vault")
    assert entry["purpose"] == ["vault_metadata"]
    # The worker's own identity, or the Microsoft connection's app certificate (one envelope, three roles).
    assert entry["auth_secret_roles"] == {"workload_identity": [],
                                          "private_key_jwt": ["client_id", "private_key", "tenant_id"]}
    assert entry["limitations"][0] == "UPDATED_ON_IS_A_PROPERTY_CHANGE_NOT_A_ROTATION"
