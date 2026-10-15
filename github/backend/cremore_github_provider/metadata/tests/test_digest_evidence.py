"""Offline vendor-hash conversion; no credential is sent to an external API."""

import base64
import hashlib
import hmac
import json
from types import SimpleNamespace

import pytest

from cremore.coverage.metadata_models import RECORD_ADAPTER, in_metadata_scope
from cremore_github_provider.credential_digest import DOMAIN
from cremore_github_provider.metadata import adapter
from cremore_github_provider.metadata.digest_evidence import (
    SCHEME,
    comparison_fingerprint,
    provider_sha256,
)
from cremore_github_provider.metadata.normalization import record_values

from .fake import ENTERPRISE, ORG, audit_row, enterprise_spec, inventory_row, spec
from .test_adapter import NOW, drive

KEY = b"synthetic-comparison-key-fixture!!"
MATERIAL = b"synthetic-github-credential-value"
VENDOR_HASH = base64.b64encode(hashlib.sha256(MATERIAL).digest()).decode()


def context(**patch):
    return {"engine": SimpleNamespace(config=SimpleNamespace(fingerprint_key=KEY)),
            "key_id": hashlib.sha256(KEY).hexdigest(), "engine_digest": "a" * 64,
            "policy_digest": "b" * 64, **patch}


def connection():
    return enterprise_spec(capabilities=["inventory", "issuer_digest"],
                           options={"include_provider_hashes": True, "sources": ["org_sso"]})


def scripted(value=VENDOR_HASH, **patch):
    return {
        f"/enterprises/{ENTERPRISE}/credentials/exports": [inventory_row(
            credential_type="classic_pat", hashed_token=value, **patch)],
        f"/enterprises/{ENTERPRISE}/apps/installable_organizations?per_page=100": [],
    }


def evidence_record(rows):
    return next(row for row in rows if row.get("identity", {}).get("kind") == "credential"
                and row.get("provenance", {}).get("operation") == "github.inventory")


def test_enterprise_digest_uses_private_value_match_and_matches_exact_passive_derivation():
    connection_spec = connection()
    transport, _b, records, checkpoint, final = drive(connection_spec, scripted(), enterprise=ENTERPRISE,
                                                    value_context=context())
    assert final.status == "COMPLETE"
    record = evidence_record(records)
    match = record["value_match"]
    expected = hmac.new(KEY, DOMAIN + hashlib.sha256(MATERIAL).digest(), hashlib.sha256).hexdigest()
    assert match["fingerprint"] == expected
    assert match["evidence"] == "PROVIDER_DIGEST" and match["scheme"] == SCHEME
    assert match["reference"] == "inventory:export:classic_pat:export-1:row:1" and match["credential_type"] == "GITHUB_TOKEN"
    assert match["key_id"] == hashlib.sha256(KEY).hexdigest()
    assert match["fingerprint"] != hmac.new(KEY, MATERIAL, hashlib.sha256).hexdigest()
    assert in_metadata_scope(connection_spec, RECORD_ADAPTER.validate_python(record))
    for output in (json.dumps(records), json.dumps(checkpoint), json.dumps(adapter.native_snapshots(records)), str(transport.calls)):
        assert VENDOR_HASH not in output and MATERIAL.decode() not in output
    assert expected not in json.dumps(adapter.native_snapshots(records))


def test_key_rotation_and_case_changes_are_not_equal():
    raw = provider_sha256(VENDOR_HASH)
    assert comparison_fingerprint(raw, KEY) != comparison_fingerprint(raw, b"2" * 32)
    assert comparison_fingerprint(raw, KEY) != comparison_fingerprint(hashlib.sha256(MATERIAL.upper()).digest(), KEY)


@pytest.mark.parametrize("value", ["not-base64", "a" * 44, VENDOR_HASH.rstrip("="),
                                  VENDOR_HASH + "\n", base64.b64encode(b"x" * 31).decode(), 123])
def test_malformed_vendor_hash_keeps_metadata_but_marks_partial_without_persisting_hash(value):
    _t, _b, records, _s, final = drive(connection(), scripted(value), enterprise=ENTERPRISE, value_context=context())
    assert final.status == "PARTIAL" and "INVALID_PROVIDER_DIGEST" in final.reasons
    row = evidence_record(records)
    assert row["value_match"] is None
    assert {"path": "hashed_token", "reason": "INVALID_PROVIDER_DIGEST"} in row["omissions"]
    assert "hashed_token" not in {field["name"] for field in row["facts"]}
    with pytest.raises(ValueError):
        provider_sha256(value)


def test_null_or_missing_hash_means_unavailable_not_empty_hash_or_active_check():
    for row in (inventory_row(credential_type="fine_grained_pat", hashed_token=None),
                inventory_row(credential_type="fine_grained_pat", hashed_token=""),
                inventory_row(credential_type="fine_grained_pat")):
        responses = scripted()
        responses[f"/enterprises/{ENTERPRISE}/credentials/exports"] = [row]
        _t, _b, records, _s, final = drive(connection(), responses, enterprise=ENTERPRISE, value_context=context())
        assert evidence_record(records)["value_match"] is None
        assert final.status == "COMPLETE"


def test_provider_hash_is_explicit_opt_in_and_never_reused_as_existing_credential_hmac():
    ordinary = enterprise_spec(options={"sources": ["org_sso"]})
    _t, _b, records, checkpoint, final = drive(ordinary, scripted(), enterprise=ENTERPRISE)
    assert final.status == "COMPLETE" and evidence_record(records)["value_match"] is None
    assert VENDOR_HASH not in json.dumps(records) + json.dumps(checkpoint)
    with pytest.raises(ValueError):
        adapter.validate_spec(spec(capabilities=["inventory", "issuer_digest"],
                                   options={"include_provider_hashes": True}))


@pytest.mark.parametrize("ctx", [None, {}, context(key_id="c" * 64),
                                context(engine=SimpleNamespace(config=SimpleNamespace(fingerprint_key=b"short")))])
def test_bad_comparison_context_is_rejected_before_provider_io(ctx):
    with pytest.raises(ValueError, match="COMPARISON_CONTEXT"):
        drive(connection(), {}, enterprise=ENTERPRISE, value_context=ctx)


@pytest.mark.parametrize("patch", [
    {"purpose": "vault_metadata"},
    {"value_match": {"reference": "inventory:another"}},
    {"scope": {"kind": "organization", "id": "Other"}},
])
def test_digest_scope_reference_and_purpose_cannot_be_rebound(patch):
    _t, _b, records, _s, _f = drive(connection(), scripted(), enterprise=ENTERPRISE, value_context=context())
    row = evidence_record(records)
    for key, value in patch.items():
        row[key] = {**row[key], **value} if isinstance(value, dict) else value
    assert not in_metadata_scope(connection(), RECORD_ADAPTER.validate_python(row))


def audit_connection():
    return enterprise_spec(capabilities=["inventory", "audit", "issuer_digest"],
                           options={"include_provider_hashes": True, "include_audit_events": True,
                                    "sources": ["org_sso"]})


def audit_page(include="web"):
    from urllib.parse import urlencode

    window = adapter._window(audit_connection(), NOW.isoformat())
    if include == "git":
        window = adapter._git_window(window)
    phrase = urlencode({"include": include, "order": "asc", "phrase": "created:" + window[0] + ".." + window[1]})
    return f"/enterprises/{ENTERPRISE}/audit-log?{phrase}&per_page=100"


def audited(rows, git_rows=()):
    return {**scripted(), audit_page(): rows, audit_page("git"): list(git_rows)}


def test_token_authenticated_audit_entries_are_summarised_per_keyed_token_only():
    other = base64.b64encode(hashlib.sha256(b"synthetic-other-credential").digest()).decode()
    rows = [audit_row("repo.create", _document_id="doc-1", created_at="2026-03-02T00:00:00Z",
                      hashed_token=VENDOR_HASH, repo=f"{ORG}/one"),
            audit_row("repo.update", _document_id="doc-2", created_at="2026-03-01T00:00:00Z",
                      hashed_token=VENDOR_HASH, repo=f"{ORG}/two"),
            audit_row("repo.create", _document_id="doc-3", hashed_token=other),
            audit_row("repo.create", _document_id="doc-4"),
            audit_row("repo.create", _document_id="doc-5", hashed_token="not-base64")]
    transport, _b, records, checkpoint, final = drive(audit_connection(), audited(rows), enterprise=ENTERPRISE,
                                                      value_context=context())
    assert final.status == "COMPLETE"
    activity = {row["value_match"]["fingerprint"]: row for row in records if row.get("event_type") == "token_activity"}
    expected = comparison_fingerprint(hashlib.sha256(MATERIAL).digest(), KEY)
    assert len(activity) == 2
    mine = activity[expected]
    assert record_values(mine) == {
        "events": 2, "first_seen_at": "2026-03-01T00:00:00+00:00", "last_seen_at": "2026-03-02T00:00:00+00:00",
        "action": ["repo.create", "repo.update"], "repo": [f"{ORG}/one", f"{ORG}/two"], "actor": ["octocat"],
        "programmatic_access_type": ["fine_grained_personal_access_token"], "_document_id": ["doc-1", "doc-2"]}
    assert mine["occurred_at"] == "2026-03-02T00:00:00+00:00" and mine["purpose"] == "usage"
    assert mine["event_id"] == mine["value_match"]["reference"] == "token_activity:doc-1"
    assert mine["value_match"]["evidence"] == "PROVIDER_DIGEST" and mine["value_match"]["scheme"] == SCHEME
    assert in_metadata_scope(audit_connection(), RECORD_ADAPTER.validate_python(mine))
    snapshot = json.dumps(adapter.native_snapshots(records))
    for output in (json.dumps(records), json.dumps(checkpoint), snapshot, str(transport.calls)):
        assert VENDOR_HASH not in output and other not in output
    assert expected not in snapshot and "token_activity" not in snapshot


def test_git_events_made_with_the_token_join_its_activity_from_a_seven_day_read():
    rows = [audit_row("repo.create", _document_id="doc-1", created_at="2026-03-01T00:00:00Z", hashed_token=VENDOR_HASH)]
    git = [audit_row("git.clone", _document_id="git-1", created_at="2026-03-04T00:00:00Z", hashed_token=VENDOR_HASH,
                     repo=f"{ORG}/one", programmatic_access_type="Personal access token (classic)"),
           audit_row("git.push", _document_id="git-2", created_at="2026-03-04T01:00:00Z")]  # SSH, no token hash
    transport, _b, records, _s, final = drive(audit_connection(), audited(rows, git), enterprise=ENTERPRISE,
                                              value_context=context())
    assert final.status == "COMPLETE"
    assert ("GET", audit_page("git")) in transport.calls
    assert adapter._git_window(adapter._window(audit_connection(), NOW.isoformat()))[0] == "2026-02-26T00:00:00+00:00"
    activity = [row for row in records if row.get("event_type") == "token_activity"]
    assert sorted(record_values(row)["_document_id"][0] for row in activity) == ["doc-1", "git-1"]
    assert "git.clone" in {action for row in activity for action in record_values(row)["action"]}
    assert not [row for row in records if row.get("event_type", "").startswith("git.")]  # not credential actions
    roster = json.dumps(adapter.native_snapshots(records))
    assert f'"org": "{ENTERPRISE}"' not in roster and VENDOR_HASH not in roster


def test_audit_token_activity_needs_the_provider_hash_opt_in():
    plain = enterprise_spec(capabilities=["inventory", "audit"],
                            options={"include_audit_events": True, "sources": ["org_sso"]})
    _t, _b, records, checkpoint, final = drive(plain, audited([audit_row("repo.create", hashed_token=VENDOR_HASH)]),
                                               enterprise=ENTERPRISE)
    assert final.status == "COMPLETE"
    assert not [row for row in records if row.get("event_type") == "token_activity"]
    assert VENDOR_HASH not in json.dumps(records) + json.dumps(checkpoint)
    assert not [row for row in records if row.get("provenance", {}).get("operation") == "github.git_audit"]


@pytest.mark.parametrize("patch", [{"event_type": "repo.create"}, {"purpose": "issuer_inventory"},
                                   {"value_match": {"reference": "token_activity:doc-9"}}])
def test_token_activity_digest_cannot_be_rebound(patch):
    _t, _b, records, _s, _f = drive(audit_connection(), audited([audit_row("repo.create", hashed_token=VENDOR_HASH)]),
                                    enterprise=ENTERPRISE, value_context=context())
    row = next(row for row in records if row.get("event_type") == "token_activity")
    without_digest = enterprise_spec(capabilities=["inventory", "audit"], options={"include_audit_events": True})
    assert not in_metadata_scope(without_digest, RECORD_ADAPTER.validate_python(row))
    for key, value in patch.items():
        row[key] = {**row[key], **value} if isinstance(value, dict) else value
    assert not in_metadata_scope(audit_connection(), RECORD_ADAPTER.validate_python(row))
