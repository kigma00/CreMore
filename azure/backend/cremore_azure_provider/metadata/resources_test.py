"""Key/certificate listing contracts and their scope/value boundaries."""

import pytest

from cremore.coverage.metadata_models import in_metadata_scope
from cremore_azure_provider.metadata import adapter
from cremore_azure_provider.metadata.azure_key_vault_test import ORIGIN, Vault, records, spec


def row(family, name="signing", version=""):
    return {("kid" if family == "keys" else "id"): f"{ORIGIN}/{family}/{name}" + ("/" + version if version else ""),
            "attributes": {"enabled": True, "created": 1700000000},
            "x5t": "fLi3U52HunIVNXubkEnf8tP6Wbo", "cer": "must-not-be-stored",
            "key": {"private": "must-not-be-stored"}, "tags": {"rotation": "false"}}


def collect(connection, vault, **kwargs):
    return list(adapter.collect_pages(connection, secrets={}, checkpoint=kwargs.pop("checkpoint", None),
                                      check=lambda: None, transport=vault, **kwargs))


@pytest.mark.parametrize("family,source,prefix", [("keys", "key_versions", "key"),
                                                 ("certificates", "certificate_versions", "certificate")])
def test_metadata_and_versions_are_distinct_and_never_contain_key_material(family, source, prefix):
    connection = spec(options={"sources": [family, source]})
    pages = collect(connection, Vault({"/" + family: {"value": [row(family)]},
        f"/{family}/signing/versions": {"value": [row(family, version="a1")]}}))
    assert pages[-1].status == "COMPLETE"
    entities = [r for r in records(pages) if r.record_type == "entity_observation"]
    assert len(entities) == 2
    assert entities[0].identity.object_id == f"{prefix}:acme-prod:signing"
    assert entities[1].identity.object_id == f"{prefix}Version:acme-prod:signing/versions/a1"
    assert all(adapter.validate_machine_record(connection, r) and in_metadata_scope(connection, r) for r in entities)
    assert all(r.value_match is None and r.omissions for r in entities)
    assert "must-not-be-stored" not in "".join(p.model_dump_json() for p in pages)
    assert adapter.native_snapshots([r.model_dump() for r in records(pages)])[0]["secret_count"] == 0


def test_key_versions_resume_from_recorded_key_names():
    connection = spec(options={"sources": ["keys", "key_versions"]})
    first = []
    for page in adapter.collect_pages(connection, secrets={}, checkpoint=None, check=lambda: None,
                                      transport=Vault({"/keys": {"value": [row("keys")]}})):
        first.append(page)
        if page.checkpoint["phase"] == "keys":
            break
    vault = Vault({"/keys/signing/versions": {"value": [row("keys", version="a1")]}})
    again = collect(connection, vault, checkpoint=first[-1].checkpoint,
                    read_records=lambda: [r.model_dump() for r in records(first)])
    assert again[-1].status == "COMPLETE"
    assert [path for path, _ in vault.calls] == ["/keys/signing/versions"]


def test_foreign_key_name_in_version_response_is_partial():
    pages = collect(spec(options={"sources": ["keys", "key_versions"]}), Vault({
        "/keys": {"value": [row("keys")]},
        "/keys/signing/versions": {"value": [row("keys", name="other", version="a1")]}}))
    assert pages[-1].status == "PARTIAL" and "INVALID_IDENTIFIERS" in pages[-1].reasons


@pytest.mark.parametrize("source,family", [("deleted_keys", "keys"), ("deleted_certificates", "certificates")])
def test_deleted_metadata_does_not_issue_restore_or_value_requests(source, family):
    deleted = {**row(family), "deletedDate": 1700001000}
    vault = Vault({"/deleted" + family: {"value": [deleted]}})
    pages = collect(spec(options={"sources": [source]}), vault)
    entity = next(r for r in records(pages) if r.record_type == "entity_observation")
    assert entity.normalized_state == "DELETED"
    assert [path for path, _ in vault.calls] == ["/deleted" + family]


def test_key_listing_pagination_stays_on_key_collection():
    vault = Vault({"/keys": [{"value": [row("keys")], "nextLink": ORIGIN + "/keys?$skiptoken=next"},
                              {"value": [row("keys", name="second")]}]})
    pages = collect(spec(options={"sources": ["keys"]}), vault)
    assert pages[-1].status == "COMPLETE"
    assert vault.calls[1][1]["$skiptoken"] == "next"


@pytest.mark.parametrize("source", ["key_versions", "certificate_versions"])
def test_versions_require_corresponding_base_discovery(source):
    with pytest.raises(ValueError, match="RESOURCE_DISCOVERY"):
        adapter.validate_spec(spec(options={"sources": [source]}))


@pytest.mark.parametrize("family,source,prefix", [("keys", "key_versions", "key"),
                                                 ("certificates", "certificate_versions", "certificate")])
def test_partial_parent_listing_keeps_versions_partial_and_never_removed(family, source, prefix):
    versions = {f"/{family}/{name}/versions": {"value": [row(family, name=name, version="a1")]}
                for name in ("first", "second")}
    before = collect(spec(options={"sources": [family, source]}), Vault({
        "/" + family: {"value": [row(family, name="first"), row(family, name="second")]}, **versions}))
    # The parent listing stops at its page limit before it reaches `second`.
    after = collect(spec(max_pages=1, options={"sources": [family, source]}), Vault({
        "/" + family: {"value": [row(family, name="first")], "nextLink": f"{ORIGIN}/{family}?$skiptoken=next"},
        **versions}))
    report = next(r for r in records(after) if r.record_type == "operation_report"
                  and r.provenance.operation == "azure.key_vault." + source)
    assert report.status == "PARTIAL" and "PARENT_LISTING_INCOMPLETE" in report.reasons
    diff = adapter.compare_records([r.model_dump() for r in records(before)],
                                   [r.model_dump() for r in records(after)])
    missing = f"{prefix}Version:acme-prod:second/versions/a1"
    assert missing not in diff["removed"]
    assert {"object_id": missing, "reason": "source_not_completely_listed"} in diff["absence_not_evaluated"]
