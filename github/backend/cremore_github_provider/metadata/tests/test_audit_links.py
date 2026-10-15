"""Audit entries joined to credentials by exact identifiers only; synthetic records, no network."""

import base64
import hashlib
import json
from urllib.parse import urlencode

import pytest

from cremore.coverage.errors import CoverageError
from cremore_github_provider.metadata import adapter

from .fake import (
    ENTERPRISE,
    FULL,
    ORG,
    SSH_KEY,
    audit_row,
    enterprise_responses,
    enterprise_spec,
    inventory_row,
)
from .test_adapter import NOW, drive
from .test_digest_evidence import KEY, context


def test_a_fine_grained_pat_token_id_never_becomes_a_grant_id_target():
    # user_programmatic_access_id is the token id; fgpat:{org}:{n} entities are keyed by grant id.
    from cremore_github_provider.metadata.normalization import audit_event
    connection = enterprise_spec()
    row = audit_row(user_programmatic_access_id=31)
    row.pop("token_id")
    event = audit_event(connection, connection.scopes[0], row, operation="github.audit", org=ORG)
    assert event is not None and event.target is None
    assert audit_event(connection, connection.scopes[0], audit_row(), operation="github.audit",
                       org=ORG).target.object_id == f"token:{ORG}:41"


def test_flattened_audit_rows_have_a_total_byte_budget_without_partial_results(monkeypatch):
    from cremore_github_provider.metadata import audit_links as module

    link = {"credential": "credential-1", "credential_type": "fine_grained_pat",
            "entities": ["inventory:one", "inventory:two"],
            "events": [{"event_id": "event-1", "relation": "target"},
                       {"event_id": "event-2", "relation": "target"}]}
    result = {"links": [link], "unmatched": []}
    expected = module.audit_link_rows(result)
    assert expected[0]["entities"] == link["entities"] and len(expected) == 2
    monkeypatch.setattr(module, "AUDIT_LINK_BYTES", len(json.dumps(expected[0])) + 64)
    with pytest.raises(CoverageError, match="GITHUB_AUDIT_LINKS_LIMIT_USE_RECORD_PAGES"):
        module.audit_link_rows(result)
    # Unicode escaping and unmatched rows consume the same shared budget.
    monkeypatch.setattr(module, "AUDIT_LINK_BYTES", 20)
    with pytest.raises(CoverageError, match="GITHUB_AUDIT_LINKS_LIMIT_USE_RECORD_PAGES"):
        module.audit_link_rows({"links": [], "unmatched": [{"event_id": "이벤트"}]})
    with pytest.raises(CoverageError, match="GITHUB_AUDIT_LINKS_LIMIT_USE_RECORD_PAGES"):
        module.link_inputs([{"record_type": "entity_observation", "identity": {"object_id": "inventory:one"}}])


MANAGED = base64.b64encode(hashlib.sha256(b"synthetic-managed-classic-pat").digest()).decode()
USER_KEY = "SHA256:" + "u" * 43
DEPLOY_KEY = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(SSH_KEY.split()[1])).digest()).decode().rstrip("=")


def links(*, provider_hashes=True):
    connection = enterprise_spec(
        capabilities=["inventory", "audit"] + (["issuer_digest"] if provider_hashes else []),
        options={"include_audit_events": True, "include_provider_hashes": provider_hashes,
                 "sources": ["org_sso", "org_fgpat", "org_repositories"]})
    window = adapter._window(connection, NOW.isoformat())
    responses = enterprise_responses(window=window)
    responses[f"/enterprises/{ENTERPRISE}/credentials/exports"] = ([
        inventory_row("i1", credential_type="classic_pat", credential_id=21, hashed_token=MANAGED),
        inventory_row("i2", credential_type="fine_grained_pat", credential_id=41),
        inventory_row("i3", credential_type="oauth_app_user_token", credential_id=7),
        inventory_row("i4", credential_type="github_app_user_token", credential_id=7),
        inventory_row("i5", credential_type="oauth_app_user_token", credential_id=8),
        inventory_row("i6", credential_type="ssh_key", fingerprint=USER_KEY + "="),
    ], {})
    phrase = urlencode({"include": "web", "order": "asc", "phrase": "created:" + window[0] + ".." + window[1]})
    responses[f"/enterprises/{ENTERPRISE}/audit-log?{phrase}&per_page=100"] = [
        audit_row("personal_access_token.access_granted", _document_id="e1", user_programmatic_access_id=41),
        audit_row("org_credential_authorization.grant", _document_id="e2", managed_hashed_token=MANAGED),
        audit_row("org_credential_authorization.grant", _document_id="e3", oauth_credential_type="OauthAccess", token_id=8),
        audit_row("org_credential_authorization.grant", _document_id="e4", oauth_credential_type="OauthAccess", token_id=7),
        audit_row("public_key.create", _document_id="e5", fingerprint=USER_KEY),
        audit_row("public_key.create", _document_id="e6", fingerprint=DEPLOY_KEY, repo=FULL),
        audit_row("oauth_access.create", _document_id="e7"),
        audit_row("personal_access_token.access_revoked", _document_id="e8", user_programmatic_access_id=999),
    ]
    _t, _b, records, _s, final = drive(connection, responses, enterprise=ENTERPRISE,
                                       value_context=context() if provider_hashes else None)
    return adapter.native_snapshots(records)["enterprise"]["audit_links"], records, final


def by_credential(result):
    return {link["credential"]: link for link in result["links"]}


def test_events_link_only_by_exact_identifiers_and_sources_of_one_credential_merge():
    result, _records, final = links()
    found = by_credential(result)
    assert found["fine_grained_pat:id:41"]["entities"] == ["fgpat:CreMore-1:31", "inventory:fine_grained_pat:id:41"]
    assert [(e["event_id"], e["relation"], e["basis"]) for e in found["fine_grained_pat:id:41"]["events"]] == [
        ("e1", "target", "documented_fine_grained_pat_target_id")]
    assert "inventory:classic_pat:id:21" in found["classic_pat:id:21"]["entities"]
    assert [(e["event_id"], e["relation"], e["basis"]) for e in found["classic_pat:id:21"]["events"]] == [
        ("e2", "target", "exact_managed_credential_hash")]
    assert [(e["event_id"], e["relation"]) for e in found["oauth_app_user_token:id:8"]["events"]] == [("e3", "associated")]
    assert [e["event_id"] for e in found["ssh_key:fingerprint:" + USER_KEY]["events"]] == ["e5"]
    deploy = found["deploy_key:" + FULL.lower() + ":" + DEPLOY_KEY]
    assert deploy["entities"] == [f"deployKey:{FULL}:81"]
    assert [(e["event_id"], e["basis"]) for e in deploy["events"]] == [("e6", "exact_repository_and_target_fingerprint")]
    assert final.status in ("COMPLETE", "PARTIAL")


def test_ambiguous_unreferenced_and_unobserved_events_stay_unmatched_with_their_reason():
    result, _records, _final = links()
    unmatched = {row["event_id"]: row["reason"] for row in result["unmatched"]}
    # OAuth and GitHub App user tokens share one id namespace: id 7 names two credentials.
    assert unmatched == {"e4": "ambiguous_reference", "e7": "no_exact_reference", "e8": "no_observed_credential"}
    assert result["counts"] == {"events": 8, "linked": 5, "unmatched": 3}


def test_the_managed_hash_links_only_with_the_opt_in_and_is_never_exported():
    result, records, _final = links()
    text = json.dumps(result)
    keyed = next(row for row in records if row.get("event_id") == "e2")["value_match"]["fingerprint"]
    assert MANAGED not in json.dumps(records) and MANAGED not in text
    assert keyed not in json.dumps(adapter.native_snapshots(records))
    assert hashlib.sha256(KEY).hexdigest() not in text
    without, records, _final = links(provider_hashes=False)
    assert all(row.get("value_match") is None for row in records if row.get("record_type") == "provider_event")
    assert {row["event_id"]: row["reason"] for row in without["unmatched"]}["e2"] == "no_exact_reference"
    assert "classic_pat:id:21" not in by_credential(without)


def test_audit_link_view_rows_filter_by_relation_and_credential_type():
    from cremore_github_provider.metadata.audit_links import (
        audit_link_rows,
        audit_links,
        link_inputs,
        select_rows,
    )

    _result, records, _final = links()
    result = audit_links(link_inputs(records))
    assert result == adapter.native_snapshots(records)["enterprise"]["audit_links"]
    rows = audit_link_rows(result)
    assert {row["relation"] for row in rows} == {"target", "associated", "unmatched"}
    assert [row["event_id"] for row in select_rows(rows, relation="associated")] == ["e3"]
    assert {row["event_id"]: row["reason"] for row in select_rows(rows, relation="unmatched")} == {
        "e4": "ambiguous_reference", "e7": "no_exact_reference", "e8": "no_observed_credential"}
    targets = select_rows(rows, relation="target")
    assert {row["event_id"] for row in targets} == {"e1", "e2", "e5", "e6"}
    assert all(row["basis"] and row["credential"] for row in targets)
    assert [row["event_id"] for row in select_rows(rows, credential_type="fine_grained_pat")] == ["e1"]
    assert not select_rows(rows, relation="unmatched", credential_type="fine_grained_pat")
    # What the join keeps of a record is only what it reads.
    from cremore_github_provider.metadata.audit_links import JOIN_FACTS

    reduced = link_inputs(records)
    assert all(set(item) == {"record_type", "event_type", "event_id", "occurred_at", "identity", "value_match", "facts"}
               for item in reduced)
    assert all(fact["name"] in JOIN_FACTS for item in reduced for fact in item["facts"])
    assert sum(len(item["facts"]) for item in reduced) < sum(len(row.get("facts") or []) for row in records
                                                               if row["record_type"] == "provider_event")


def test_organization_audits_link_to_organization_records_without_an_inventory():
    connection = enterprise_spec(capabilities=["inventory", "audit"],
                                 options={"include_audit_events": True, "audit_scope": "organization",
                                          "sources": ["org_fgpat"]})
    window = adapter._window(connection, NOW.isoformat())
    responses = enterprise_responses(window=window)
    responses[f"/enterprises/{ENTERPRISE}/credentials/exports"] = ([], {})
    phrase = urlencode({"include": "web", "order": "asc", "phrase": "created:" + window[0] + ".." + window[1]})
    responses[f"/orgs/{ORG}/audit-log?{phrase}&per_page=100"] = [
        audit_row("personal_access_token.access_granted", _document_id="o1", user_programmatic_access_id=41)]
    _t, _b, records, _s, _f = drive(connection, responses, enterprise=ENTERPRISE)
    found = by_credential(adapter.native_snapshots(records)["enterprise"]["audit_links"])
    assert found["fine_grained_pat:id:41"]["entities"] == ["fgpat:CreMore-1:31"]
    assert [e["event_id"] for e in found["fine_grained_pat:id:41"]["events"]] == ["o1"]
