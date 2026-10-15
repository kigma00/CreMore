"""The new API's CSV is transient transport, not a stored or user-uploaded file."""

import csv
import io
import json

import pytest

from cremore.coverage.metadata_models import RECORD_ADAPTER
from cremore_github_provider.metadata import adapter
from cremore_github_provider.metadata.exports import (
    MAX_ROW_BYTES,
    ExportError,
    Projection,
    normalize,
    rows,
    timestamp,
)
from cremore_github_provider.metadata.normalization import record_values

from .fake import enterprise_spec
from .test_digest_evidence import VENDOR_HASH, context

HEADERS = ["credential_id", "hashed_token", "fingerprint", "item_type", "credential_type", "display_name",
           "owner_id", "owner", "owner_type", "application_id", "application", "credential_state", "created_at",
           "last_used_at", "expires_at", "expiry_status", "enterprise_authorized", "authorization_count",
           "age_days", "past_expiration_policy", "past_expiration_policy_basis", "scopes", "permissions",
           "repository_selection", "organization_id", "organization"]
AS_OF = "2026-10-05T00:00:00Z"


def row(**values):
    return {**dict.fromkeys(HEADERS, ""), "credential_type": "classic_pat", "credential_id": "17",
            "item_type": "credential", "owner_id": "3", "owner": "person", "owner_type": "user",
            "credential_state": "active", "authorization_count": "2", **values}


def data(*items, headers=HEADERS):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, headers, lineterminator="\n")
    writer.writeheader()
    writer.writerows(items)
    return stream.getvalue().encode()


def chunks(body, size=7):
    return (body[n:n + size] for n in range(0, len(body), size))


def read(body, **kwargs):
    return list(rows(chunks(body), check=lambda: None, **kwargs))


def projection(**kwargs):
    return Projection(kwargs.pop("spec", enterprise_spec(capabilities=["inventory", "relations"])),
                      export="export-1", generated_at=AS_OF, **kwargs)


def test_utf8_multiline_quotes_commas_bom_and_chunk_boundaries():
    display = '배포, "자동화"\r\n두 번째 줄'
    parsed = read(b"\xef\xbb\xbf" + data(row(display_name=display)))
    assert parsed[0][1]["display_name"] == display
    assert parsed[0][0] == 1


def test_no_disk_input_or_output_is_needed_and_unknown_columns_are_discarded():
    parsed = read(data({**row(), "token": "must-not-be-kept"}, headers=[*HEADERS, "token"]))
    assert "token" not in parsed[0][1]
    projected = projection().project(*parsed[0])
    assert "must-not-be-kept" not in json.dumps([i.model_dump() for i in projected])


def test_blank_boolean_is_unknown_not_false_and_blank_expiry_is_not_never():
    unknown, _ = normalize(row(), export="e", index=1)
    assert not {"enterprise_authorized", "past_expiration_policy", "expires_at", "expiry_status"} & unknown.keys()
    explicit, _ = normalize(row(enterprise_authorized="false", past_expiration_policy="true", expiry_status="unknown"),
                            export="e", index=1)
    assert explicit["enterprise_authorized"] is False
    assert explicit["past_expiration_policy"] is True
    assert explicit["expiry_status"] == "unknown"


def test_semicolon_scopes_and_permissions_are_typed():
    result = projection().project(1, row(scopes="repo;read:org", permissions="contents:write; issues:read"))[0]
    assert {(p.name, tuple(p.actions)) for p in result.permissions if p.kind == "permission"} == {
        ("contents", ("write",)), ("issues", ("read",))}
    assert {p.name for p in result.permissions if p.kind == "scope"} == {"repo", "read:org"}


def test_unsorted_organization_rows_count_credential_once_and_preserve_all_grants():
    p = projection()
    collected = []
    for index, values in enumerate((row(organization_id="10", organization="one"), row(credential_id="18"),
                                    row(organization_id="20", organization="two"),
                                    row(organization_id="10", organization="one")), 1):
        collected.extend(p.project(index, values))
    assert len([r for r in collected if r.record_type == "entity_observation"]) == 2
    grants = [r for r in collected if r.record_type == "relation"]
    assert {r.target.object_id for r in grants} == {"organization:10", "organization:20"}
    assert {r.subject.object_id for r in grants} == {"inventory:classic_pat:id:17"}
    for item in collected:
        assert adapter.validate_record(p.spec, RECORD_ADAPTER.validate_python(item.model_dump()))


def test_identity_is_type_plus_id_and_ssh_fingerprint_not_owner_name():
    p = projection()
    one = p.project(1, row())[0]
    two = p.project(2, row(credential_type="fine_grained_pat"))[0]
    ssh = row(credential_type="ssh_key", credential_id="", fingerprint="SHA256:" + "A" * 43)
    three = p.project(3, ssh)[0]
    assert len({r.identity.object_id for r in (one, two, three)}) == 3
    assert not p.project(4, ssh)


@pytest.mark.parametrize("kind,item,expected", [("github_app_installation", "token_issuer_principal", "principal"),
                                                ("federated_jti", "credential", "credential")])
def test_rows_without_stable_id_are_never_merged_by_application_or_owner(kind, item, expected):
    p = projection()
    raw = row(credential_type=kind, credential_id="", item_type=item, application_id="10")
    one, two = p.project(1, raw)[0], p.project(2, raw)[0]
    assert one.identity.kind == expected
    assert one.identity != two.identity
    assert record_values(one)["basis"] == "EXPORT_ROW_ONLY"
    assert one.omissions[-1].reason == "NO_STABLE_PROVIDER_IDENTIFIER"


def test_optional_provider_hash_is_immediately_keyed_never_retained_in_facts():
    spec = enterprise_spec(capabilities=["inventory", "issuer_digest"], options={"include_provider_hashes": True})
    item = projection(spec=spec, value_context=context()).project(1, row(hashed_token=VENDOR_HASH))[0]
    assert item.value_match.evidence == "PROVIDER_DIGEST"
    assert VENDOR_HASH not in item.model_dump_json()
    assert "hashed_token" not in record_values(item)
    assert projection().project(1, row(hashed_token=VENDOR_HASH))[0].value_match is None


def test_restart_rebuilds_dedupe_from_committed_records_not_checkpoint_hashes():
    first = projection().project(1, row(organization_id="10", organization="one"))
    restored = projection(committed=[r.model_dump() for r in first])
    assert restored.project(1, row(organization_id="10", organization="one")) == []
    more = restored.project(2, row(organization_id="20", organization="two"))
    assert len(more) == 1 and more[0].record_type == "relation"


def test_inventory_only_connection_keeps_grant_context_without_enabling_relations():
    spec = enterprise_spec()
    first = projection(spec=spec).project(1, row(organization_id="10", organization="one"))
    assert {r.identity.kind for r in first} == {"credential", "context"}
    assert all(adapter.validate_record(spec, r) for r in first)
    restored = projection(spec=spec, committed=[r.model_dump() for r in first])
    assert not restored.project(1, row(organization_id="10", organization="one"))


def test_conflicting_rows_fail_instead_of_overwriting_the_first_observation():
    p = projection()
    p.project(1, row())
    with pytest.raises(ExportError, match="conflicting_credential"):
        p.project(2, row(credential_state="revoked"))


@pytest.mark.parametrize("patch,code", [({"enterprise_authorized": "0"}, "invalid_boolean"),
    ({"authorization_count": "-1"}, "invalid_number"), ({"created_at": "2026-10-05"}, "invalid_timestamp"),
    ({"organization_id": "10"}, "invalid_organization"), ({"permissions": "contents:write;contents:read"}, "invalid_permissions"),
    ({"credential_type": "unrecognized"}, "unsupported_credential_type"),
    ({"credential_type": "github_app_installation"}, "invalid_item_type"),
    ({"fingerprint": "bad-fingerprint"}, "invalid_fingerprint")])
def test_invalid_cells_are_sanitized_failures(patch, code):
    with pytest.raises(ExportError, match=code):
        projection().project(1, row(**patch))


@pytest.mark.parametrize("body", [b"", b"credential_type\nclassic_pat\n", data(row()) + b'"unterminated',
                                      data(row()).replace(b"person", b"\xff"), data(row()) + b"extra,column\n"])
def test_invalid_documents_do_not_become_complete_empty_inventories(body):
    with pytest.raises(ExportError):
        read(body)


def test_header_duplicates_are_rejected_even_when_required_names_exist():
    with pytest.raises(ExportError, match="invalid_header"):
        read(data(row(), headers=[*HEADERS, "owner"]))


def test_valid_header_only_is_a_valid_empty_export():
    assert read(data()) == []


def test_byte_row_and_multiline_record_budgets_are_real_limits():
    with pytest.raises(ExportError, match="size_limit"):
        read(data(row()), max_bytes=20)
    with pytest.raises(ExportError, match="row_count_limit"):
        read(data(row(), row()), max_rows=1)
    with pytest.raises(ExportError, match="row_limit"):
        read(data(row(display_name="x" * MAX_ROW_BYTES)))
    with pytest.raises(ExportError, match="row_limit"):
        read(data(row(display_name="line\n" * (MAX_ROW_BYTES // 4))))


def test_cancellation_is_checked_during_download_and_parsing():
    class Cancelled(Exception):
        pass
    calls = 0
    def check():
        nonlocal calls
        calls += 1
        if calls > 10:
            raise Cancelled
    with pytest.raises(Cancelled):
        list(rows(chunks(data(row())), check=check))


def test_as_of_accepts_the_documented_utc_form_but_rejects_naive_dates():
    assert timestamp("2026-10-05 00:00:00 UTC") == "2026-10-05T00:00:00+00:00"
    with pytest.raises(ExportError):
        timestamp("2026-10-05 00:00:00")
