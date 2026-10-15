"""The shared-runtime contract: scopes, both modes, restart, budgets, evidence."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime
from unittest.mock import patch

from cremore.coverage.metadata_models import in_metadata_scope
from cremore.coverage.providers import validate_record as shared_validate
from cremore_github_provider.metadata import adapter
from cremore_github_provider.metadata.normalization import record_values

from .fake import (
    AUDIT_TOKEN,
    ENTERPRISE,
    ORG,
    OTHER_ORG,
    REPO,
    SECRETS,
    FakeBroker,
    FakeTransport,
    audit_row,
    enterprise_responses,
    enterprise_spec,
    org_responses,
    spec,
)

NOW = datetime(2026, 3, 5, tzinfo=UTC)


def drive(connection, responses, *, stop_after=None, checkpoint=None, committed=None,
          enterprise="", failures=None, refused=(), check=None, transport=None, value_context=None,
          secrets=None):
    committed = list(committed or [])
    if secrets is None:
        secrets = {**SECRETS, "audit_token": AUDIT_TOKEN} if "audit_token" in connection.secret_refs else SECRETS
    transport = transport or FakeTransport(responses, enterprise=enterprise, failures=failures,
                                           check=check)
    broker = FakeBroker(refused=refused)
    state, final = checkpoint or {}, None
    seen, requests = 0, 0
    with patch("cremore_github_provider.metadata.export_http.download", transport.download):
        for attempt in range(3):
            pages = adapter.collect_pages(
                connection, secrets=secrets, checkpoint=state, check=check or (lambda: None),
                transport=transport, broker=broker, now=lambda: NOW,
                value_context=value_context, read_records=(lambda: iter(committed)) if state else None)
            for page in pages:
                seen += 1
                committed.extend(item.model_dump() for item in page.records)
                state = page.checkpoint
                if page.status is not None:
                    final = page
                if stop_after is not None and seen >= stop_after:
                    pages.close()
                    break
            requests += transport.requests
            if (stop_after is not None or final is None or final.status != "WAITING"
                    or final.reasons != ["GITHUB_EXPORT_QUEUED"]):
                break
            transport.requests = 0
    transport.requests = requests
    return transport, broker, committed, state, final


def key(item):
    return (item["record_type"], item.get("identity", {}).get("object_id"),
            item["provenance"]["operation"], item["provenance"]["resource_id"])


class SpecTests(unittest.TestCase):
    def rejects(self, **overrides):
        with self.assertRaises(ValueError):
            adapter.validate_spec(spec(**overrides))

    def test_the_edition_must_agree_with_the_host(self):
        adapter.validate_spec(spec())
        adapter.validate_spec(spec(edition="enterprise_server", origin="https://ghes.example.com"))
        adapter.validate_spec(spec(edition="dedicated", origin="https://acme.ghe.com"))
        self.rejects(edition="enterprise_server")
        self.rejects(edition="enterprise_cloud", origin="https://ghes.example.com")
        self.rejects(edition="dedicated", origin="https://ghes.example.com")
        self.rejects(origin="https://github.com/orgs/x")

    def test_app_authentication_is_required_and_its_roles_are_fixed(self):
        self.rejects(auth_type="bearer", secret_refs={"token": "vault://x"})
        self.rejects(secret_refs={"app_id": "vault://a"})
        self.rejects(secret_refs={"app_id": "vault://a", "private_key": "vault://b",
                                  "client_secret": "vault://c"})
        adapter.validate_spec(spec(secret_refs={"app_id": "vault://a", "private_key": "vault://b",
                                                "installation_id": "vault://c"}))

    def test_a_mode_decides_which_scope_kind_is_allowed(self):
        adapter.validate_spec(enterprise_spec())
        self.rejects(options={"mode": "enterprise"})
        self.rejects(scopes=[{"kind": "enterprise", "id": ENTERPRISE}])
        self.rejects(scopes=[{"kind": "enterprise", "id": ENTERPRISE},
                             {"kind": "organization", "id": ORG}],
                     options={"mode": "enterprise"})
        self.rejects(scopes=[{"kind": "project", "id": ORG}])

    def test_audit_collection_needs_the_audit_capability(self):
        self.rejects(options={"include_audit_events": True})
        adapter.validate_spec(spec(capabilities=["inventory", "audit"],
                                   options={"include_audit_events": True}))

    def test_audit_scope_enterprise_only_and_actions_run_days_are_refused_where_meaningless(self):
        audit = {"capabilities": ["inventory", "audit"]}
        self.rejects(options={"audit_scope": "organization"})
        self.rejects(**audit, options={"include_audit_events": True, "audit_scope": "enterprise"})
        self.rejects(options={"enterprise_only": True})
        self.rejects(options={"actions_run_days": 3})
        adapter.validate_spec(spec(options={"include_actions": True, "actions_run_days": 3}))
        adapter.validate_spec(spec(options={"sources": ["repo_actions_runs"], "actions_run_days": 3}))
        adapter.validate_spec(spec(**audit, options={"include_audit_events": True,
                                                     "audit_scope": "organization"}))
        for options in ({"enterprise_only": True, "sources": ["org_sso"]},
                        {"enterprise_only": True, "include_actions": True},
                        {"enterprise_only": True, "include_audit_events": True, "audit_scope": "organization"}):
            with self.assertRaises(ValueError, msg=options):
                adapter.validate_spec(enterprise_spec(**audit, options=options))
        adapter.validate_spec(enterprise_spec(**audit, options={
            "enterprise_only": True, "include_audit_events": True, "audit_scope": "enterprise"}))

    def test_audit_token_role_is_refused_outside_the_enterprise_audit(self):
        refs = {"app_id": "vault://a", "private_key": "vault://p", "audit_token": "vault://t"}
        self.rejects(secret_refs=refs, capabilities=["inventory", "audit"], options={"include_audit_events": True})
        for changes in ({"capabilities": ["inventory"]},
                        {"capabilities": ["inventory", "audit"],
                         "options": {"include_audit_events": True, "audit_scope": "organization"}}):
            with self.assertRaises(ValueError, msg=changes):
                adapter.validate_spec(enterprise_spec(secret_refs=refs, **changes))
        adapter.validate_spec(enterprise_spec(secret_refs=refs, capabilities=["inventory", "audit"],
                                              options={"include_audit_events": True}))

    def test_a_principal_pin_and_value_reads_are_refused(self):
        self.rejects(principal_pin="cremore-app")
        self.rejects(capabilities=["inventory"], options={"include_values": True})

    def test_an_unknown_source_name_is_refused(self):
        self.rejects(options={"sources": ["org_secrets"]})
        adapter.validate_spec(spec(options={"sources": ["org_sso", "org_fgpat"]}))


class OrganizationModeTests(unittest.TestCase):
    def test_each_source_keeps_its_own_object_kind(self):
        _t, _b, records, _s, final = drive(spec(), org_responses())
        kinds = {(item["identity"]["kind"],
                  item["identity"]["object_id"].split(":", 1)[0])
                 for item in records if item["record_type"] == "entity_observation"}
        self.assertIn(("credential", "sso"), kinds)
        self.assertIn(("public_key", "sso"), kinds)
        self.assertIn(("public_key", "deployKey"), kinds)
        self.assertIn(("installation", "installation"), kinds)
        self.assertIn(("policy", "policy"), kinds)
        self.assertIn(("request", "patRequest"), kinds)
        self.assertEqual(final.status, "COMPLETE")

    def test_a_scope_or_permission_is_typed_and_not_left_as_free_text(self):
        _t, _b, records, _s, _f = drive(spec(), org_responses())
        token = next(item for item in records
                     if item.get("identity", {}).get("object_id") == f"sso:{ORG}:11")
        self.assertEqual({(entry["kind"], entry["name"]) for entry in token["permissions"]},
                         {("scope", "repo"), ("scope", "read:org")})
        grant = next(item for item in records
                     if item.get("identity", {}).get("object_id") == f"fgpat:{ORG}:31")
        self.assertIn(("permission", "contents"),
                      {(entry["kind"], entry["name"]) for entry in grant["permissions"]})

    def test_an_unreadable_source_is_a_failed_report_not_an_empty_one(self):
        responses = dict(org_responses())
        responses.pop(f"/orgs/{ORG}/personal-access-tokens?per_page=100")
        _t, _b, records, _s, final = drive(spec(), responses)
        failed = next(item for item in records
                      if item["record_type"] == "operation_report"
                      and item["provenance"]["operation"] == "github.org_fgpat")
        self.assertEqual(failed["status"], "FAILED")
        self.assertEqual(failed["reasons"], ["GITHUB_HTTP_404"])
        self.assertEqual(final.status, "PARTIAL")

    def test_an_organization_the_app_is_not_installed_on_is_recorded_once(self):
        _t, broker, _r, state, final = drive(spec(), org_responses(),
                                             refused=(("org", ORG.lower()),))
        self.assertEqual(final.status, "PARTIAL")
        self.assertIn("ORGANIZATION_INSTALLATION_GITHUB_HTTP_404", final.reasons)
        self.assertEqual(state["refused"], broker.refused())

    def test_several_organizations_each_get_their_own_scope(self):
        responses = {**org_responses(ORG), **org_responses(OTHER_ORG)}
        connection = spec(scopes=[{"kind": "organization", "id": ORG},
                                  {"kind": "organization", "id": OTHER_ORG}])
        _t, _b, records, _s, _f = drive(connection, responses)
        scopes = {item["scope"]["id"] for item in records}
        self.assertEqual(scopes, {ORG, OTHER_ORG})

    def test_actions_runs_are_only_collected_when_asked_for(self):
        _t, _b, plain, _s, _f = drive(spec(), org_responses())
        self.assertFalse(any(str(item.get("identity", {}).get("object_id", "")).startswith("run:")
                             for item in plain))

        connection = spec(options={"include_actions": True, "audit_lookback_days": 7})
        window = adapter._window(connection, NOW.isoformat())
        created = window[0][:10] + ".." + window[1][:10]
        runs = f"/repos/{ORG}/{REPO}/actions/runs"
        responses = dict(org_responses())
        responses[f"{runs}?created={created}&per_page=100"] = {"workflow_runs": [
            {"id": 7, "run_attempt": 1, "name": "build", "status": "completed",
             "conclusion": "success", "created_at": "2026-03-01T00:00:00Z",
             "repository": {"id": 501, "full_name": f"{ORG}/{REPO}"},
             "actor": {"id": 3, "login": "octocat", "type": "User"}}]}
        responses[f"{runs}/7/attempts/1/jobs?per_page=100"] = {"jobs": [
            {"id": 8, "run_id": 7, "run_attempt": 1, "name": "test", "status": "completed",
             "labels": ["ubuntu-latest"]}]}
        _t, _b, records, _s, final = drive(connection, responses)
        self.assertTrue(any(str(item.get("identity", {}).get("object_id", "")).startswith("run:")
                            for item in records))
        jobs = next(item for item in records if item["record_type"] == "operation_report"
                    and item["provenance"]["operation"] == "github.run_jobs")
        self.assertEqual(jobs["status"], "COMPLETE")
        self.assertEqual(final.status, "COMPLETE")
        # One run is one entity, keyed by repository and attempt, with its repository kept.
        run_records = [item for item in records if str(item.get("identity", {}).get("object_id", "")).startswith("run:")]
        self.assertEqual({item["identity"]["object_id"] for item in run_records}, {f"run:{ORG}/{REPO}:7:1"})
        self.assertFalse([o for item in run_records for o in item["omissions"]])
        self.assertTrue(all(record_values(item)["full_name"] == f"{ORG}/{REPO}" for item in run_records))


class ActionsRunWindowTests(unittest.TestCase):
    def test_actions_run_days_sets_its_own_run_window(self):
        def run_paths(options):
            transport, _b, _r, _s, _f = drive(spec(options=options), org_responses())
            return [path for _method, path in transport.calls if "/actions/runs?" in path]

        own = run_paths({"include_actions": True, "actions_run_days": 3})
        self.assertTrue(own)
        self.assertTrue(all("created=2026-03-02..2026-03-05" in path for path in own), own)
        # Unset, runs keep following the audit window (180 days by default).
        audit = run_paths({"include_actions": True})
        self.assertTrue(audit)
        self.assertTrue(all("created=2025-09-06..2026-03-05" in path for path in audit), audit)


class RunTimeLimitTests(unittest.TestCase):
    def test_run_time_limit_stops_after_the_pages_already_read(self):
        from datetime import timedelta

        connection = spec(options={"sources": ["org_sso", "org_fgpat"], "run_time_limit_minutes": 5})
        clock = [NOW]

        def check():
            # Each request moves the clock three minutes: the second read crosses five minutes.
            clock[0] += timedelta(minutes=3)

        transport = FakeTransport(org_responses(), check=check)
        pages = list(adapter.collect_pages(connection, secrets=SECRETS, checkpoint={}, check=lambda: None,
                                           transport=transport, broker=FakeBroker(), now=lambda: clock[0]))
        final = pages[-1]
        self.assertEqual((final.status, final.reasons), ("PARTIAL", ["TIME_BUDGET_EXCEEDED"]))
        self.assertEqual(len(transport.calls), 2)
        state = final.checkpoint
        self.assertEqual({item["kind"]: item["status"] for item in state["tasks"].values()},
                         {"app": "complete", "org_sso": "complete", "org_fgpat": "complete",
                          "org_fgpat_repositories": "pending"})
        records = [row.model_dump() for page in pages for row in page.records]
        self.assertTrue(any(row.get("identity", {}).get("object_id", "").startswith("fgpat:") for row in records))

    def test_run_time_limit_does_not_touch_a_run_with_nothing_left_to_read(self):
        connection = spec(options={"sources": ["org_sso"], "run_time_limit_minutes": 1})
        _t, _b, _r, state, final = drive(connection, org_responses())
        self.assertEqual(final.status, "COMPLETE")
        from datetime import timedelta

        later = adapter.collect_pages(connection, secrets=SECRETS, checkpoint={**state, "status": "COMPLETE"},
                                      check=lambda: None, transport=FakeTransport(org_responses()),
                                      broker=FakeBroker(), now=lambda: NOW + timedelta(minutes=2),
                                      read_records=lambda: iter(()))
        self.assertEqual(list(later)[-1].status, "COMPLETE")


class EnterpriseModeTests(unittest.TestCase):
    def responses(self, connection, **kwargs):
        window = adapter._window(connection, NOW.isoformat())
        return enterprise_responses(window=window, **kwargs), window

    def test_the_inventory_separates_credentials_from_issuer_principals(self):
        connection = enterprise_spec()
        responses, _w = self.responses(connection)
        _t, _b, records, _s, final = drive(connection, responses, enterprise=ENTERPRISE)
        kinds = {item["identity"]["object_id"]: item["identity"]["kind"] for item in records
                 if item["record_type"] == "entity_observation"}
        self.assertEqual(kinds["inventory:export:classic_pat:export-1:row:1"], "credential")
        self.assertEqual(kinds["inventory:export:github_app_installation:export-1:row:2"], "principal")
        self.assertEqual(final.status, "PARTIAL")
        self.assertIn("GITHUB_INVENTORY_METADATA_INCOMPLETE", final.reasons)

    def test_inventory_identity_uses_credential_id_or_fingerprint(self):
        # inventory_id "can differ for the same credential between responses"; the
        # documented per-type credential_id and the SSH fingerprint do not.
        from .fake import inventory_row

        connection = enterprise_spec()
        path = f"/enterprises/{ENTERPRISE}/credentials/exports"

        def inventory_ids(rows):
            responses, _w = self.responses(connection)
            responses[path] = (rows, {})
            _t, _b, records, _s, _f = drive(connection, responses, enterprise=ENTERPRISE)
            return sorted(item["identity"]["object_id"] for item in records
                          if item["record_type"] == "entity_observation"
                          and item["identity"]["kind"] != "context"
                          and item["provenance"]["operation"] == "github.inventory")

        first = inventory_ids([
            inventory_row("a1", credential_type="classic_pat", credential_id=5),
            inventory_row("a2", credential_type="fine_grained_pat", credential_id=5),
            inventory_row("a3", credential_type="ssh_key", fingerprint="SHA256:" + "b" * 43 + "="),
            inventory_row("a4", credential_type="github_app_installation"),
            inventory_row("a5", credential_type="classic_pat")])
        self.assertEqual(first, ["inventory:classic_pat:id:5", "inventory:export:classic_pat:export-1:row:5",
                                 "inventory:export:github_app_installation:export-1:row:4", "inventory:fine_grained_pat:id:5",
                                 "inventory:ssh_key:fingerprint:SHA256:" + "b" * 43])
        # The same credentials under new inventory_ids keep their identity.
        again = inventory_ids([
            inventory_row("z1", credential_type="classic_pat", credential_id=5),
            inventory_row("z3", credential_type="ssh_key", fingerprint="SHA256:" + "b" * 43)])
        self.assertEqual(again, ["inventory:classic_pat:id:5",
                                 "inventory:ssh_key:fingerprint:SHA256:" + "b" * 43])

    def test_the_inventory_completeness_headers_survive_as_warnings(self):
        connection = enterprise_spec()
        responses, _w = self.responses(connection)
        _t, _b, records, _s, _f = drive(connection, responses, enterprise=ENTERPRISE)
        snapshot = adapter.native_snapshots(records)["enterprise"]
        self.assertIn("truncated:true", snapshot["warnings"])
        self.assertTrue(snapshot["generated_at"].startswith("2026-03-02"))
        self.assertFalse(snapshot["inventory_complete"])

    def test_every_organization_the_enterprise_lists_is_collected(self):
        connection = enterprise_spec()
        responses, _w = self.responses(connection, orgs=(ORG, OTHER_ORG))
        _t, _b, records, _s, _f = drive(connection, responses, enterprise=ENTERPRISE)
        snapshot = adapter.native_snapshots(records)["organizations"]
        self.assertEqual(sorted(snapshot), sorted([ORG, OTHER_ORG]))

    def test_audit_entries_become_events_only_for_credential_actions(self):
        connection = enterprise_spec(capabilities=["inventory", "audit"],
                                     options={"include_audit_events": True})
        window = adapter._window(connection, NOW.isoformat())
        responses = enterprise_responses(window=window)
        from urllib.parse import urlencode
        phrase = urlencode({"include": "web", "order": "asc",
                            "phrase": "created:" + window[0] + ".." + window[1]})
        responses[f"/enterprises/{ENTERPRISE}/audit-log?{phrase}&per_page=100"] = [
            audit_row(), audit_row(action="repo.create", _document_id="doc-2")]
        _t, _b, records, _s, _f = drive(connection, responses, enterprise=ENTERPRISE)
        events = [item for item in records if item["record_type"] == "provider_event"]
        self.assertEqual([item["event_type"] for item in events],
                         ["personal_access_token.access_granted"])
        self.assertEqual(events[0]["target"]["object_id"], "credential" and f"token:{ORG}:41")
        self.assertEqual(events[0]["purpose"], "usage")

    def test_audit_scope_organization_skips_the_enterprise_audit(self):
        connection = enterprise_spec(capabilities=["inventory", "audit"],
                                     options={"include_audit_events": True, "audit_scope": "organization"})
        responses, _w = self.responses(connection)
        transport, _b, _r, state, _f = drive(connection, responses, enterprise=ENTERPRISE)
        kinds = {item["kind"] for item in state["tasks"].values()}
        self.assertNotIn("audit", kinds)
        self.assertIn("org_audit", kinds)
        self.assertFalse([path for _m, path in transport.calls if path.startswith(f"/enterprises/{ENTERPRISE}/audit-log")])

    def test_audit_scope_enterprise_never_reads_organization_audits(self):
        connection = enterprise_spec(capabilities=["inventory", "audit"],
                                     options={"include_audit_events": True, "audit_scope": "enterprise"})
        responses, _w = self.responses(connection)
        transport, _b, _r, state, _f = drive(connection, responses, enterprise=ENTERPRISE)
        kinds = {item["kind"] for item in state["tasks"].values()}
        self.assertIn("audit", kinds)
        self.assertNotIn("org_audit", kinds)
        self.assertFalse([path for _m, path in transport.calls if path.startswith("/orgs/") and "/audit-log" in path])

    def test_enterprise_only_reads_no_organization(self):
        connection = enterprise_spec(options={"enterprise_only": True})
        responses, _w = self.responses(connection)
        transport, _b, _r, state, final = drive(connection, responses, enterprise=ENTERPRISE)
        self.assertEqual({item["kind"] for item in state["tasks"].values()}, {"app", "inventory"})
        self.assertFalse([path for _m, path in transport.calls
                          if path.startswith("/orgs/") or "installable_organizations" in path])
        self.assertIsNotNone(final)

    def audited(self, **spec_changes):
        connection = enterprise_spec(capabilities=["inventory", "audit"],
                                     options={"include_audit_events": True}, **spec_changes)
        responses, window = self.responses(connection)
        from urllib.parse import urlencode
        phrase = urlencode({"include": "web", "order": "asc",
                            "phrase": "created:" + window[0] + ".." + window[1]})
        return connection, responses, f"/enterprises/{ENTERPRISE}/audit-log?{phrase}&per_page=100"

    def test_enterprise_audit_token_is_the_only_bearer_of_the_audit_log(self):
        connection, responses, _audit = self.audited()
        transport, _b, _r, _s, _f = drive(connection, responses, enterprise=ENTERPRISE)
        audit_calls = [bearer for path, bearer in transport.bearers if path.startswith(f"/enterprises/{ENTERPRISE}/audit-log")]
        self.assertEqual(audit_calls, [AUDIT_TOKEN])
        self.assertTrue(all(bearer != AUDIT_TOKEN for path, bearer in transport.bearers
                            if not path.startswith(f"/enterprises/{ENTERPRISE}/audit-log")))

    def test_enterprise_audit_token_missing_skips_the_read_with_a_reason_and_falls_back(self):
        connection, responses, _audit = self.audited(
            secret_refs={"app_id": "vault://github/app-id", "private_key": "vault://github/private-key"})
        transport, _b, records, _state, final = drive(connection, responses, enterprise=ENTERPRISE,
                                                     secrets={**SECRETS, "audit_token": AUDIT_TOKEN})
        self.assertFalse([path for _m, path in transport.calls if path.startswith(f"/enterprises/{ENTERPRISE}/audit-log")])
        report = next(item for item in records if item["record_type"] == "operation_report"
                      and item["provenance"]["operation"] == "github.audit")
        self.assertEqual((report["status"], report["reasons"]), ("FAILED", ["GITHUB_ENTERPRISE_AUDIT_TOKEN_REQUIRED"]))
        self.assertTrue([path for _m, path in transport.calls if path.startswith(f"/orgs/{ORG}/audit-log")])
        self.assertEqual(final.status, "PARTIAL")

    def test_enterprise_audit_token_unavailable_fails_only_the_audit_reads(self):
        # The PAT is configured, but the worker could not resolve it (e.g. after a sealing-key change).
        connection, responses, _audit = self.audited()
        self.assertIn("audit_token", connection.secret_refs)
        transport, _b, records, _state, final = drive(connection, responses, enterprise=ENTERPRISE, secrets=SECRETS)
        self.assertFalse([path for _m, path in transport.calls if path.startswith(f"/enterprises/{ENTERPRISE}/audit-log")])
        report = next(item for item in records if item["record_type"] == "operation_report"
                      and item["provenance"]["operation"] == "github.audit")
        self.assertEqual((report["status"], report["reasons"]), ("FAILED", ["GITHUB_ENTERPRISE_AUDIT_TOKEN_UNAVAILABLE"]))
        self.assertTrue([path for _m, path in transport.calls if path.startswith(f"/orgs/{ORG}/audit-log")])
        self.assertEqual(final.status, "PARTIAL")

    def test_enterprise_audit_token_rejection_fails_only_its_task(self):
        connection, responses, audit = self.audited()
        transport, _b, records, _s, final = drive(connection, responses, enterprise=ENTERPRISE,
                                                  failures={audit: "github_http_401"})
        report = next(item for item in records if item["record_type"] == "operation_report"
                      and item["provenance"]["operation"] == "github.audit")
        self.assertEqual(report["reasons"], ["GITHUB_ENTERPRISE_AUDIT_TOKEN_REJECTED"])
        self.assertNotIn("COLLECTION_STOPPED", final.reasons)
        self.assertTrue([path for _m, path in transport.calls if path.startswith(f"/orgs/{ORG}/audit-log")])

    def test_enterprise_audit_token_that_is_not_a_classic_pat_is_never_sent(self):
        connection, responses, _audit = self.audited()
        transport, _b, records, _s, _f = drive(connection, responses, enterprise=ENTERPRISE,
                                               secrets={**SECRETS, "audit_token": "github_pat_" + "a" * 60})
        self.assertFalse([path for _m, path in transport.calls if path.startswith(f"/enterprises/{ENTERPRISE}/audit-log")])
        report = next(item for item in records if item["record_type"] == "operation_report"
                      and item["provenance"]["operation"] == "github.audit")
        self.assertEqual(report["reasons"], ["GITHUB_ENTERPRISE_AUDIT_TOKEN_INVALID"])

    def test_a_completed_enterprise_audit_covers_the_organization_audits(self):
        connection = enterprise_spec(capabilities=["inventory", "audit"],
                                     options={"include_audit_events": True})
        window = adapter._window(connection, NOW.isoformat())
        responses = enterprise_responses(window=window)
        from urllib.parse import urlencode
        phrase = urlencode({"include": "web", "order": "asc",
                            "phrase": "created:" + window[0] + ".." + window[1]})
        responses[f"/enterprises/{ENTERPRISE}/audit-log?{phrase}&per_page=100"] = [audit_row()]
        _t, _b, records, state, _f = drive(connection, responses, enterprise=ENTERPRISE)
        statuses = {item["kind"]: item["status"] for item in state["tasks"].values()}
        self.assertEqual(statuses["org_audit"], "covered_by_enterprise")
        covered = [item for item in records if item["record_type"] == "operation_report"
                   and item["provenance"]["operation"] == "github.org_audit"]
        self.assertEqual([item["status"] for item in covered], ["NOT_REQUESTED"])


class RestartTests(unittest.TestCase):
    def test_a_restart_reads_only_what_is_left_and_produces_the_same_records(self):
        whole, _b, full, _s, final = drive(spec(), org_responses())
        first, _b, part, state, _f = drive(spec(), org_responses(), stop_after=4)
        rest, _b, resumed, _s, resumed_final = drive(spec(), org_responses(), checkpoint=state,
                                                     committed=part)
        self.assertEqual(sorted(map(key, full)), sorted(map(key, resumed)))
        self.assertEqual(final.status, resumed_final.status)
        self.assertEqual(first.requests + rest.requests, whole.requests)

    def test_a_finished_run_requests_nothing_when_resumed(self):
        _t, _b, committed, state, _f = drive(spec(), org_responses())
        transport, _b, resumed, _s, final = drive(spec(), org_responses(), checkpoint=state,
                                                  committed=committed)
        self.assertEqual(transport.calls, [])
        self.assertEqual(len(resumed), len(committed))
        self.assertEqual(final.status, "COMPLETE")

    def test_a_changed_connection_refuses_the_old_checkpoint(self):
        _t, _b, committed, state, _f = drive(spec(), org_responses(), stop_after=2)
        with self.assertRaises(ValueError) as caught:
            drive(spec(options={"sources": ["org_sso"]}), org_responses(), checkpoint=state,
                  committed=committed)
        self.assertEqual(str(caught.exception), "GITHUB_CHECKPOINT_MISMATCH")

    def test_a_checkpoint_without_its_committed_records_is_refused(self):
        _t, _b, _c, state, _f = drive(spec(), org_responses(), stop_after=2)
        pages = adapter.collect_pages(spec(), secrets=SECRETS, checkpoint=state,
                                      check=lambda: None, transport=FakeTransport({}),
                                      broker=FakeBroker())
        with self.assertRaises(ValueError) as caught:
            next(pages)
        self.assertEqual(str(caught.exception), "GITHUB_RECORD_REPLAY_REQUIRED")

    def test_cancellation_stops_before_the_next_request(self):
        state = {"count": 0}

        def check():
            state["count"] += 1
            if state["count"] > 3:
                raise KeyboardInterrupt("cancelled")

        with self.assertRaises(KeyboardInterrupt):
            drive(spec(), org_responses(), check=check)

    def test_a_rate_limited_read_waits_with_its_delay_and_keeps_its_cursor(self):
        _t, _b, _r, state, final = drive(
            spec(), org_responses(),
            failures={f"/orgs/{ORG}/credential-authorizations?per_page=100":
                      "github_rate_limited"})
        self.assertEqual(final.status, "WAITING")
        self.assertEqual(final.reasons, ["GITHUB_RATE_LIMITED"])
        self.assertEqual(final.retry_after_seconds, 120)
        self.assertEqual(state["tasks"][next(
            item_id for item_id, item in state["tasks"].items()
            if item["kind"] == "org_sso")]["status"], "pending")

    def test_a_rejected_credential_stops_the_run_rather_than_hammering_it(self):
        responses = org_responses()
        failures = {path: "github_http_401" for path in responses}
        _t, _b, _r, _s, final = drive(spec(), responses, failures=failures)
        self.assertEqual(final.status, "PARTIAL")
        self.assertIn("COLLECTION_STOPPED", final.reasons)

    def test_the_record_budget_stops_the_run_as_partial(self):
        _t, _b, records, _s, final = drive(spec(max_records=3), org_responses())
        self.assertEqual(final.status, "PARTIAL")
        self.assertIn("RECORD_BUDGET_EXCEEDED", final.reasons)
        self.assertLessEqual(len(records), 3)


class ContractTests(unittest.TestCase):
    def test_every_emitted_record_passes_the_shared_scope_check(self):
        connection = spec(capabilities=["inventory", "public_keys", "policy", "relations"])
        _t, _b, records, _s, _f = drive(connection, org_responses())
        from cremore.coverage.metadata_models import RECORD_ADAPTER

        for item in records:
            parsed = RECORD_ADAPTER.validate_python(item)
            self.assertTrue(in_metadata_scope(connection, parsed), item)
            self.assertTrue(adapter.validate_record(connection, parsed))

    def test_a_relation_names_the_owner_and_the_repository_it_can_reach(self):
        connection = spec(capabilities=["inventory", "public_keys", "policy", "relations"])
        _t, _b, records, _s, _f = drive(connection, org_responses())
        relations = [item for item in records if item["record_type"] == "relation"]
        self.assertIn(("owns", "principal:octocat"),
                      {(item["relation"], item["subject"]["object_id"]) for item in relations})
        self.assertIn("can_access", {item["relation"] for item in relations})

    def test_a_record_from_another_origin_or_scope_is_refused(self):
        connection = spec()
        _t, _b, records, _s, _f = drive(connection, org_responses())
        from cremore.coverage.metadata_models import RECORD_ADAPTER

        item = RECORD_ADAPTER.validate_python(next(
            row for row in records if row["record_type"] == "entity_observation"
            and row["identity"]["object_id"].startswith("fgpat:")))
        self.assertTrue(shared_validate(connection, item))
        moved = item.model_copy(deep=True)
        moved.identity.origin = "https://ghes.example.com"
        self.assertFalse(adapter.validate_record(connection, moved))
        elsewhere = item.model_copy(deep=True)
        elsewhere.scope.id = OTHER_ORG
        self.assertFalse(adapter.validate_record(connection, elsewhere))

    def test_the_registry_resolves_this_adapter(self):
        from cremore.coverage.providers import adapter_for

        self.assertIs(adapter_for("github"), adapter)

    def test_machine_record_binds_native_identity_and_endpoint_to_its_scope(self):
        from cremore.coverage.metadata_models import RECORD_ADAPTER

        connection = spec()
        rows = drive(connection, org_responses())[2]
        for row in rows:
            parsed = RECORD_ADAPTER.validate_python(row)
            self.assertTrue(shared_validate(connection, parsed, trusted_discovery=True), row)
            if (row.get("identity", {}).get("object_id", "").startswith((f"fgpat:{ORG}:", f"repository:{ORG}/"))
                    or row["record_type"] == "operation_report"
                    and row["provenance"]["resource_id"].startswith((f"/orgs/{ORG}/", f"/repos/{ORG}/"))):
                self.assertTrue(adapter.validate_machine_record(connection, parsed), row)
        item = RECORD_ADAPTER.validate_python(next(row for row in rows
            if row["record_type"] == "entity_observation" and row["identity"]["object_id"].startswith("fgpat:")))
        foreign = item.model_copy(deep=True)
        foreign.identity.object_id = f"fgpat:{OTHER_ORG}:31"
        self.assertFalse(adapter.validate_machine_record(connection, foreign))
        foreign = item.model_copy(deep=True)
        foreign.provenance.resource_id = f"/orgs/{OTHER_ORG}/personal-access-tokens"
        self.assertFalse(adapter.validate_machine_record(connection, foreign))
        # A second approved organization does not permit relabelling this row's root.
        both = spec(scopes=[{"kind": "organization", "id": ORG}, {"kind": "organization", "id": OTHER_ORG}])
        self.assertFalse(adapter.validate_machine_record(both, foreign))

    def test_machine_global_ids_need_native_scope_evidence(self):
        from cremore_github_provider.metadata.normalization import observation

        for kind, object_id in (("credential", "inventory:personal_access_token:id:7"),
                                ("installation", "installation:7"),
                                ("principal", "principal:synthetic-person"),
                                ("context", "app:7")):
            for connection in (spec(), enterprise_spec()):
                scope = connection.scopes[0]
                with self.subTest(kind=kind, scope=scope.kind):
                    item = observation(connection, scope, kind=kind, object_id=object_id,
                        operation="github.inventory", resource_id="", row={})
                    self.assertFalse(shared_validate(connection, item))
                    self.assertTrue(shared_validate(connection, item, trusted_discovery=True))
                    # Repeating the outer scope as metadata cannot bind a global ID.
                    labelled = observation(connection, scope, kind=kind, object_id=object_id,
                        operation="github.inventory", resource_id="opaque-resource-id",
                        row={"scope": scope.id, "org" if scope.kind == "organization" else "enterprise": scope.id})
                    self.assertFalse(shared_validate(connection, labelled))
                    self.assertTrue(shared_validate(connection, labelled, trusted_discovery=True))
                    bound = item.model_copy(deep=True)
                    segment = "orgs" if scope.kind == "organization" else "enterprises"
                    bound.provenance.resource_id = f"/{segment}/{scope.id}/installations"
                    self.assertFalse(shared_validate(connection, bound))
                    self.assertTrue(shared_validate(connection, bound, trusted_discovery=True))
                    bound.provenance.resource_id = f"/{segment}/other-synthetic-scope/installations"
                    self.assertFalse(shared_validate(connection, bound))

    def test_machine_scoped_native_id_does_not_require_optional_resource_path(self):
        from cremore_github_provider.metadata.normalization import observation

        connection = spec()
        for kind, object_id in (("credential", f"fgpat:{ORG}:7"),
                                ("resource", f"repository:{ORG}/synthetic-repository"),
                                ("vault_item", f"actionsSecret:organization:{ORG}:SYNTHETIC_NAME")):
            with self.subTest(kind=kind):
                item = observation(connection, connection.scopes[0], kind=kind, object_id=object_id,
                    operation="github.org_fgpat", resource_id="", row={})
                self.assertTrue(shared_validate(connection, item))

    def test_machine_relation_requires_both_endpoint_keys_to_bind_scope(self):
        from cremore_github_provider.metadata.normalization import identity, relation

        connection = spec(capabilities=["inventory", "relations"])
        credential = identity(connection, "credential", f"fgpat:{ORG}:7")
        resource = identity(connection, "resource", f"repository:{ORG}/synthetic-repository")
        scoped = relation(connection, connection.scopes[0], credential, resource,
            relation_kind="can_access", match_basis="PROVIDER_EXPLICIT", confidence="EXACT",
            operation="github.org_fgpat")
        self.assertTrue(shared_validate(connection, scoped))
        for attr in ("subject", "target"):
            with self.subTest(endpoint=attr):
                unbound = scoped.model_copy(deep=True)
                setattr(unbound, attr, identity(connection, "principal", "principal:synthetic-person"))
                unbound.provenance.resource_id = f"/orgs/{ORG}/personal-access-tokens"
                self.assertFalse(shared_validate(connection, unbound))
                self.assertTrue(shared_validate(connection, unbound, trusted_discovery=True))

    def test_refused_machine_batch_does_not_update_an_earlier_entity_summary(self):
        import uuid

        from cremore.coverage.errors import CoverageError
        from cremore.coverage.metadata_models import MetadataBatch, metadata_contract
        from cremore.coverage.metadata_store import MetadataStore
        from cremore.db.repository import InMemoryRepository
        from cremore_github_provider.metadata.normalization import observation

        connection = spec()
        store = MetadataStore(InMemoryRepository())
        owner, token = store.create(connection, "synthetic-operator")
        run = store.start(owner["id"], 1, str(uuid.uuid4()), metadata_contract(connection).model_dump(), token=token)
        original = observation(connection, connection.scopes[0], kind="credential", object_id=f"fgpat:{ORG}:7",
            operation="github.org_fgpat", resource_id="", row={"name": "original"})
        store.append(owner["id"], run["id"], MetadataBatch(index=0, items=[original]), token=token)
        before = store.inventory()
        changed = observation(connection, connection.scopes[0], kind="credential", object_id=f"fgpat:{ORG}:7",
            operation="github.org_fgpat", resource_id="", row={"name": "changed"})
        unbound = observation(connection, connection.scopes[0], kind="installation", object_id="installation:7",
            operation="github.org_installations", resource_id=f"/orgs/{ORG}/installations", row={})
        with self.assertRaisesRegex(CoverageError, "METADATA_OUTSIDE_APPROVED_SCOPE"):
            store.append(owner["id"], run["id"], MetadataBatch(index=1, items=[changed, unbound]), token=token)
        self.assertEqual(store.inventory(), before)
        self.assertEqual(len(list(store.iter_records(run["id"]))), 1)

    def test_machine_enterprise_records_cannot_claim_discovered_organization_membership(self):
        from cremore.coverage.metadata_models import RECORD_ADAPTER

        connection = enterprise_spec()
        rows = drive(connection, enterprise_responses(), enterprise=ENTERPRISE)[2]
        roster = RECORD_ADAPTER.validate_python(next(row for row in rows
            if row["record_type"] == "entity_observation" and row["provenance"]["operation"] == "github.organizations"))
        self.assertTrue(adapter.validate_record(connection, roster))
        self.assertFalse(adapter.validate_machine_record(connection, roster))


class SnapshotTests(unittest.TestCase):
    def test_the_organization_view_groups_each_source_the_way_it_was_read(self):
        _t, _b, records, _s, _f = drive(spec(), org_responses())
        snapshot = adapter.native_snapshots(records)["organizations"][ORG]
        self.assertEqual(snapshot["sources"]["org_sso"]["source"],
                         "organization_saml_sso_authorizations")
        self.assertTrue(snapshot["sources"]["org_sso"]["complete"])
        self.assertEqual(len(snapshot["records"]["deploy_keys"]), 1)
        self.assertEqual(len(snapshot["records"]["sso_authorizations"]), 3)

    def test_a_failed_source_keeps_its_reason_in_the_view(self):
        responses = dict(org_responses())
        responses.pop(f"/repos/{ORG}/{REPO}/keys?per_page=100")
        _t, _b, records, _s, _f = drive(spec(), responses)
        snapshot = adapter.native_snapshots(records)["organizations"][ORG]
        self.assertEqual(snapshot["sources"]["repo_deploy_keys"]["error"], "GITHUB_HTTP_404")
        self.assertFalse(snapshot["sources"]["repo_deploy_keys"]["complete"])


if __name__ == "__main__":
    unittest.main()


def test_the_adapter_reraises_the_platform_pause():
    import pytest

    from cremore.coverage.errors import CoverageError

    calls = []

    def check():
        calls.append(1)
        if len(calls) == 2:
            raise CoverageError("METADATA_COLLECTION_PAUSED")

    pages = adapter.collect_pages(spec(options={"sources": ["org_sso", "org_fgpat"]}), secrets=SECRETS, checkpoint={},
                                  check=lambda: None, transport=FakeTransport(org_responses(), check=check),
                                  broker=FakeBroker(), now=lambda: NOW)
    seen = []
    with pytest.raises(CoverageError, match="METADATA_COLLECTION_PAUSED"):
        for page in pages:
            seen.extend(page.records)
    # The read the pause interrupted is not reported as a failure.
    assert not [row for row in seen if row.record_type == "operation_report" and row.status == "FAILED"]
