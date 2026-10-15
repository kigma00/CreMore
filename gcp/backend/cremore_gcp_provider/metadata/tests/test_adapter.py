"""The shared-runtime contract: scope, pages, restart, budgets and evidence."""

from __future__ import annotations

import base64
import hashlib
import hmac
import unittest
from copy import deepcopy
from datetime import UTC, datetime

from cremore.coverage.metadata_models import in_metadata_scope
from cremore.coverage.models import digest
from cremore.coverage.providers import validate_record as shared_validate
from cremore.detection.engine import Engine, EngineConfig
from cremore_gcp_provider.metadata import adapter
from cremore_gcp_provider.metadata.transport import ApiError
from cremore_gcp_provider.metadata.values import crc32c

from .fake import (
    API_KEY_NAME,
    EMAIL,
    KEY_ID,
    OTHER_EMAIL,
    PROJECT,
    REGIONAL_SECRET,
    SECRET,
    FakeTransport,
    drain,
    inventory_responses,
    spec,
)

KEY = b"k" * 32
NOW = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
LOGS = "https://logging.googleapis.com/v2/entries:list"


def value_context():
    engine = Engine(EngineConfig(fingerprint_key=KEY))
    return {"engine": engine, "key_id": hashlib.sha256(KEY).hexdigest(),
            "engine_digest": engine.detection_digest, "policy_digest": "0" * 64}


def collect(connection=None, responses=None, *, committed=None, checkpoint=None, check=None,
            transport=None, **kwargs):
    connection = connection or spec(options={"locations": ["europe-west4"]})
    transport = transport or FakeTransport(responses or inventory_responses(), check=check)
    records = list(committed or [])
    pages = adapter.collect_pages(connection, secrets={}, checkpoint=checkpoint or {},
                                  check=check or (lambda: None), transport=transport, now=NOW,
                                  read_records=(lambda: iter(records)) if checkpoint else None,
                                  **kwargs)
    return transport, pages


def run(connection=None, responses=None, **kwargs):
    transport, pages = collect(connection, responses, **kwargs)
    records, final = drain(pages)
    return transport, [item.model_dump() for item in records], final


def with_evidence():
    data = inventory_responses()
    data[LOGS] = {"entries": [{
        "logName": f"projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Fdata_access",
        "insertId": "e1", "timestamp": "2026-09-21T11:00:00Z",
        "protoPayload": {
            "serviceName": "secretmanager.googleapis.com",
            "methodName": "google.cloud.secretmanager.v1.SecretManagerService"
                          ".AccessSecretVersion",
            "resourceName": SECRET + "/versions/2",
            "authenticationInfo": {"principalEmail": EMAIL}}}]}
    data[f"https://monitoring.googleapis.com/v3/projects/{PROJECT}/timeSeries"] = {"timeSeries": []}
    data[f"https://cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}:getIamPolicy"] = {
        "bindings": [{"role": "roles/secretmanager.secretAccessor",
                      "members": [f"serviceAccount:{EMAIL}"]}]}
    data[f"https://secretmanager.googleapis.com/v1/{SECRET}:getIamPolicy"] = {"bindings": []}
    return data


def with_values():
    data = inventory_responses()
    data[f"https://apikeys.googleapis.com/v2/{API_KEY_NAME}/keyString"] = {
        "keyString": "AIza" + "B" * 35}
    payload = b"ghp_" + b"a" * 36
    data[f"https://secretmanager.googleapis.com/v1/{SECRET}/versions/2:access"] = {
        "name": SECRET + "/versions/2",
        "payload": {"data": base64.b64encode(payload).decode(), "dataCrc32c": str(crc32c(payload))}}
    data["https://secretmanager.europe-west4.rep.googleapis.com/v1/"
         f"{REGIONAL_SECRET}/versions/1:access"] = {
        "name": REGIONAL_SECRET + "/versions/1",
        "payload": {"data": base64.b64encode(b"nothing recognisable").decode()}}
    return data


def clean_responses():
    """The fixture without its deliberately invalid rows, so a run can end COMPLETE."""
    data = inventory_responses()
    for body in data.values():
        if "accounts" in body:
            body["accounts"] = [row for row in body["accounts"] if "@" in row["email"]]
        if "keys" in body:
            body["keys"] = [row for row in body["keys"] if row.get("name", "").startswith("projects/")]
        if "versions" in body:
            body["versions"] = [row for row in body["versions"] if row["state"] != "PENDING"]
    return data


def entities(records, prefix):
    return [row for row in records if row["record_type"] == "entity_observation"
            and row["identity"]["object_id"].startswith(prefix)]


class SpecTests(unittest.TestCase):
    def rejects(self, **overrides):
        with self.assertRaises(ValueError):
            adapter.validate_spec(spec(**overrides))

    def test_only_ambient_credentials_are_accepted(self):
        adapter.validate_spec(spec())
        adapter.validate_spec(spec(auth_type="workload_identity"))
        self.rejects(auth_type="bearer", secret_refs={"token": "vault://gcp/token"})
        self.rejects(secret_refs={"token": "vault://gcp/token"})

    def test_the_origin_edition_and_scope_shape_are_fixed(self):
        self.rejects(origin="https://iam.googleapis.com")
        self.rejects(edition="self_managed")
        self.rejects(scopes=[{"kind": "organization", "id": "123"}])
        self.rejects(scopes=[{"kind": "project", "id": PROJECT},
                             {"kind": "project", "id": "other-project-x"}])
        self.rejects(scopes=[{"kind": "project", "id": "X"}])

    def test_a_principal_pin_is_refused_because_nothing_verifies_it(self):
        self.rejects(principal_pin="collector@example.test")

    def test_a_value_capability_requires_the_vault_capability_that_lists_it(self):
        self.rejects(capabilities=["inventory", "vault_value"], options={"include_values": True})
        self.rejects(capabilities=["inventory", "relations"], options={"sources": ["secret_iam"]})
        adapter.validate_spec(spec(capabilities=["inventory", "vault_metadata", "vault_value"],
                                   options={"include_values": True}))

    def test_a_location_must_be_a_region_and_never_global(self):
        self.rejects(options={"locations": ["global"]})
        self.rejects(options={"locations": ["Europe-West4"]})
        adapter.validate_spec(spec(options={"locations": ["europe-west4", "us-east1"]}))

    def test_an_audit_window_is_bounded_and_audit_events_are_not_supported(self):
        self.rejects(capabilities=["inventory", "vault_metadata", "audit"],
                     options={"include_audit_events": True, "audit_lookback_days": 1})
        self.rejects(options={"audit_lookback_days": 31})


class CollectionTests(unittest.TestCase):
    def test_a_run_separates_issuers_vaults_and_their_versions(self):
        _t, records, final = run()
        kinds = {(item["identity"]["kind"], item["purpose"])
                 for item in records if item["record_type"] == "entity_observation"}
        self.assertEqual(kinds, {("principal", "issuer_inventory"),
                                 ("credential", "issuer_inventory"),
                                 ("vault_item", "vault_metadata"),
                                 ("vault_version", "vault_metadata")})
        self.assertEqual(final.status, "PARTIAL")
        self.assertIn("INVALID_IDENTIFIERS", final.reasons)

    def test_provider_state_is_reported_and_never_a_verification(self):
        _t, records, _ = run()
        disabled = [item for item in records if item["record_type"] == "entity_observation"
                    and item["identity"]["object_id"].startswith("serviceAccount:runner")]
        self.assertEqual(disabled[0]["normalized_state"], "DISABLED")
        self.assertEqual(disabled[0]["state_basis"], "PROVIDER_REPORTED")
        self.assertIsNone(disabled[0]["value_match"])

    def test_a_destroyed_version_is_deleted_state_not_a_missing_object(self):
        _t, records, _ = run()
        destroyed = [item for item in records
                     if item.get("identity", {}).get("object_id", "")
                     .endswith("deploy-token/versions/1")]
        self.assertEqual(destroyed[0]["normalized_state"], "DELETED")
        self.assertEqual(destroyed[0]["provider_state"], "destroyed")

    def test_a_capability_that_is_off_is_reported_as_not_requested(self):
        _t, records, _final = run(spec(capabilities=["inventory"]))
        skipped = {item["provenance"]["operation"] for item in records
                   if item["record_type"] == "operation_report"
                   and item["status"] == "NOT_REQUESTED"}
        self.assertIn("gcp.secret_manager", skipped)
        self.assertIn("gcp.relations_secret_access", skipped)
        self.assertTrue(all(item["identity"]["kind"] != "vault_item" for item in records
                            if item["record_type"] == "entity_observation"))

    def test_a_region_the_operator_asked_for_but_google_does_not_offer_is_partial(self):
        connection = spec(options={"locations": ["europe-west4", "me-central2"]})
        _t, records, final = run(connection)
        report = next(item for item in records
                      if item["provenance"]["operation"] == "gcp.secret_manager_locations")
        self.assertEqual(report["status"], "PARTIAL")
        self.assertIn("REQUESTED_LOCATION_NOT_SUPPORTED", report["reasons"])
        self.assertEqual(final.status, "PARTIAL")

    def test_a_disabled_api_is_recorded_but_does_not_decide_the_listing(self):
        data = clean_responses()
        for service in ("apikeys", "secretmanager"):
            data[f"https://serviceusage.googleapis.com/v1/projects/{PROJECT}/services/"
                 f"{service}.googleapis.com"] = {"state": "DISABLED"}
        _t, records, final = run(spec(capabilities=["inventory"]), data)
        # The state is the service report's fact; it never blocks what the complete lists showed.
        self.assertEqual((final.status, final.reasons), ("COMPLETE", []))
        usage = next(row for row in records if row["provenance"]["operation"] == "gcp.service_usage")
        states = {row["service"]: row["state"] for row in adapter.record_values(usage)["api_states"]}
        self.assertEqual(states["secretmanager.googleapis.com"], "disabled")
        self.assertEqual(len(entities(records, "apiKey:")), 1)

    def test_without_a_requested_region_the_location_list_is_not_read(self):
        url = f"https://secretmanager.googleapis.com/v1/projects/{PROJECT}/locations"
        transport = FakeTransport(clean_responses(), failures={url: "permission_denied"})
        _t, records, final = run(spec(), transport=transport)
        self.assertEqual((final.status, final.reasons), ("COMPLETE", []))
        self.assertNotIn(url, [called for _, called, _ in transport.calls])
        report = next(row for row in records
                      if row["provenance"]["operation"] == "gcp.secret_manager_locations")
        self.assertEqual(report["status"], "NOT_REQUESTED")

    def test_a_key_past_its_valid_before_time_is_expired_not_active(self):
        data = clean_responses()
        for email, until in ((EMAIL, "2020-01-01T00:00:00Z"), (OTHER_EMAIL, "9999-12-31T23:59:59Z")):
            data[f"https://iam.googleapis.com/v1/projects/{PROJECT}/serviceAccounts/{email}/keys"][
                "keys"][0]["validBeforeTime"] = until
        _t, records, _ = run(responses=data)
        states = {row["identity"]["object_id"]: (row["provider_state"], row["normalized_state"], row["state_basis"])
                  for row in entities(records, "serviceAccountKey:")}
        self.assertEqual(states[f"serviceAccountKey:{EMAIL}:{KEY_ID}"], ("expired", "EXPIRED", "PROVIDER_REPORTED"))
        self.assertEqual(states[f"serviceAccountKey:{OTHER_EMAIL}:{KEY_ID}"], ("active", "ACTIVE", "PROVIDER_REPORTED"))

    def test_a_forbidden_list_is_resolved_against_the_service_state(self):
        data = inventory_responses()
        url = f"https://apikeys.googleapis.com/v2/projects/{PROJECT}/locations/global/keys"
        transport = FakeTransport(data, failures={url: "permission_denied_or_api_disabled"})
        _t, records, final = run(transport=transport)
        report = next(item for item in records
                      if item["provenance"]["operation"] == "gcp.api_keys")
        self.assertEqual(report["status"], "PARTIAL")
        self.assertEqual(report["reasons"], ["PERMISSION_DENIED"])
        self.assertEqual(final.status, "PARTIAL")

    def test_relations_keep_observed_use_apart_from_a_policy_that_allows_it(self):
        connection = spec(capabilities=["inventory", "vault_metadata", "relations"],
                          options={"locations": ["europe-west4"], "audit_lookback_days": 1})
        _t, records, final = run(connection, with_evidence())
        by_relation = {}
        for item in records:
            if item["record_type"] == "relation":
                by_relation.setdefault(item["relation"], []).append(item)
        self.assertEqual({item["confidence"] for item in by_relation["used"]}, {"EXACT"})
        self.assertEqual({item["match_basis"] for item in by_relation["can_access"]}, {"POLICY"})
        self.assertEqual({item["confidence"] for item in by_relation["can_access"]}, {"CANDIDATE"})
        self.assertEqual({item["relation"] for item in by_relation["owns"]}, {"owns"})
        self.assertNotIn("REGIONAL_SECRET_RELATIONS_UNSUPPORTED", final.reasons)

    def test_an_empty_log_window_is_never_written_down_as_unused(self):
        data = with_evidence()
        data[LOGS] = {"entries": []}
        connection = spec(capabilities=["inventory", "vault_metadata", "relations"],
                          options={"locations": ["europe-west4"], "audit_lookback_days": 1})
        _t, records, _ = run(connection, data)
        report = next(item for item in records
                      if item["provenance"]["operation"] == "gcp.cloud_logging.secret_access")
        self.assertEqual(report["status"], "COMPLETE")
        self.assertIn("unknown, not unused", str(report["facts"]))
        self.assertFalse(any(item["record_type"] == "relation" and item["relation"] == "used"
                             and item["target"]["kind"] == "vault_item" for item in records))


class ValueTests(unittest.TestCase):
    def connection(self):
        return spec(capabilities=["inventory", "vault_metadata", "vault_value", "issuer_value"],
                    options={"locations": ["europe-west4"], "include_values": True})

    def test_foreign_listed_parents_are_partial_and_never_used_for_followup_reads(self):
        data = with_values()
        foreign_key = API_KEY_NAME.replace("419699000000", "419699000001")
        foreign_secret = SECRET.replace(PROJECT, "other-project")
        data[f"https://apikeys.googleapis.com/v2/projects/{PROJECT}/locations/global/keys"]["keys"][0]["name"] = foreign_key
        data[f"https://secretmanager.googleapis.com/v1/projects/{PROJECT}/secrets"]["secrets"][0]["name"] = foreign_secret
        transport, records, final = run(self.connection(), data, value_context=value_context())
        assert final.status == "PARTIAL" and "INVALID_IDENTIFIERS" in final.reasons
        assert not any(foreign_key in url or foreign_secret in url for _, url, _ in transport.calls)
        assert not any(row.get("value_match") and foreign_key in str(row) for row in records)

    def test_value_read_boundary_rechecks_parents_from_replayed_records(self):
        from cremore_gcp_provider.metadata.collector import Collector

        connection = self.connection()
        transport = FakeTransport(inventory_responses())
        current = adapter._Run(connection, {}, adapter._config_hash(connection), NOW)
        foreign_key = API_KEY_NAME.replace("419699000000", "419699000001")
        foreign_version = SECRET.replace(PROJECT, "other-project") + "/versions/1"
        listed = {name: adapter._listed_item({"project_id": PROJECT, "resource_name": name, "state": "ENABLED"})
                  for name in (foreign_key, foreign_version)}
        context = {"spec": connection, "run": current, "scope": connection.scopes[0], "project": PROJECT,
                   "transport": transport, "collector": Collector(PROJECT, transport), "value_context": value_context(),
                   "api_keys": [("", foreign_key)], "listed": listed}
        records = [r for page, _ in adapter._phase_values(context, {}) for r in page]
        assert len(records) == 1 and records[0].status == "PARTIAL"
        assert records[0].reasons == ["PROJECT_SCOPE_UNVERIFIED"]
        assert not any(url.endswith((":access", "/keyString")) for _, url, _ in transport.calls)

    def test_alias_resolution_denied_preserves_exact_project_reads_and_reports_partial(self):
        data = with_values()
        del data[f"https://cloudresourcemanager.googleapis.com/v3/projects/{PROJECT}"]
        transport, records, final = run(self.connection(), data, value_context=value_context())
        assert final.status == "PARTIAL"
        assert any(url.endswith(f"{SECRET}/versions/2:access") for _, url, _ in transport.calls)
        assert not any(url.endswith("/keyString") for _, url, _ in transport.calls)
        assert any(row.get("value_match") for row in records)

    def test_a_value_becomes_a_fingerprint_and_the_bytes_are_not_stored(self):
        _t, records, _ = run(self.connection(), with_values(),
                                     value_context=value_context())
        matches = {item["identity"]["object_id"]: item["value_match"] for item in records
                   if item.get("value_match")}
        github = matches["secretVersion:global:deploy-token/versions/2"]
        self.assertEqual((github["evidence"], github["credential_type"]), ("VALUE", "GITHUB_TOKEN"))
        self.assertEqual(len(github["fingerprint"]), 64)
        serialized = str(records)
        self.assertNotIn("ghp_" + "a" * 36, serialized)
        self.assertNotIn("AIza" + "B" * 35, serialized)

    def test_binary_empty_and_unclassified_payloads_get_only_a_private_hmac(self):
        url = f"https://secretmanager.googleapis.com/v1/{SECRET}/versions/2:access"
        for payload in (b"\x00\xffbinary-private", b"", b"short", b"x" * 65536):
            with self.subTest(size=len(payload)):
                data = with_values()
                data[url]["payload"] = {"data": base64.b64encode(payload).decode()}
                _t, records, _ = run(self.connection(), data, value_context=value_context())
                values = [row for row in records if row.get("payload_digest")
                          and row["provenance"]["resource_id"] == SECRET + "/versions/2"]
                self.assertTrue(values)
                expected = hmac.new(KEY, b"cremore/gcp-payload/v1\x00" + payload, hashlib.sha256).hexdigest()
                self.assertTrue(all(row["payload_digest"] == {
                    "scheme": "cremore-gcp-payload-v1/hmac-sha256", "key_id": hashlib.sha256(KEY).hexdigest(),
                    "fingerprint": expected} for row in values))
                self.assertTrue(all(row["value_match"]["evidence"] == "UNRESOLVED" for row in values))
                self.assertNotIn(expected, str(adapter.native_snapshots(records)))
                if payload:
                    self.assertNotIn(base64.b64encode(payload).decode(), str(records))

    def test_the_reference_always_names_the_connection_scope(self):
        _t, records, _ = run(self.connection(), with_values(),
                                     value_context=value_context())
        for item in records:
            if item.get("value_match"):
                self.assertTrue(item["value_match"]["reference"].startswith(
                    f"projects/{PROJECT}/"), item["value_match"]["reference"])

    def test_an_unreadable_value_is_unresolved_with_its_reason(self):
        data = with_values()
        url = f"https://apikeys.googleapis.com/v2/{API_KEY_NAME}/keyString"
        transport = FakeTransport(data, failures={url: "permission_denied_or_api_disabled"})
        _t, records, _final = run(self.connection(), transport=transport,
                                  value_context=value_context())
        match = [item["value_match"] for item in records
                 if item.get("value_match") and item["identity"]["object_id"].startswith("apiKey:")]
        self.assertEqual(match[0]["evidence"], "UNRESOLVED")
        self.assertEqual(match[0]["reason"], "PERMISSION_DENIED_OR_API_DISABLED")
        self.assertIsNone(match[0]["fingerprint"])
        self.assertTrue(all(row.get("payload_digest") is None for row in records
                            if row.get("value_match") and row["identity"]["object_id"].startswith("apiKey:")))
        report = next(item for item in records
                      if item["provenance"]["operation"] == "gcp.value_access")
        self.assertEqual(report["value_access"], "PARTIAL")
        self.assertEqual(report["value_contract"]["key_id"], hashlib.sha256(KEY).hexdigest())

    def test_only_google_refusing_a_deleted_key_is_its_own_fact_not_a_value_gap(self):
        # Google does not say whether a deleted (restorable) key's string can be read: its 400/404 stays on that key.
        url = f"https://apikeys.googleapis.com/v2/{API_KEY_NAME}/keyString"
        keys = f"https://apikeys.googleapis.com/v2/projects/{PROJECT}/locations/global/keys"
        for deleted, failure, answer, access in (
                (True, "http_400", None, "COMPLETE"), (True, "http_404", None, "COMPLETE"),
                (False, "http_400", None, "PARTIAL"),  # a live key's refusal is a gap
                (True, "permission_denied_or_api_disabled", None, "PARTIAL"),
                (True, None, {"keyString": ""}, "PARTIAL")):  # a malformed answer: invalid_key_string
            data = with_values()
            if deleted:
                data[keys]["keys"][0]["deleteTime"] = "2026-09-01T00:00:00Z"
            if answer is not None:
                data[url] = answer
            transport = FakeTransport(data, failures={url: failure} if failure else {})
            _t, records, _final = run(self.connection(), transport=transport, value_context=value_context())
            code = failure or "invalid_key_string"
            key = next(item["value_match"] for item in records
                       if item.get("value_match") and item["identity"]["object_id"].startswith("apiKey:"))
            self.assertEqual((key["evidence"], key["reason"]), ("UNRESOLVED", code.upper()))
            report = next(item for item in records if item["provenance"]["operation"] == "gcp.value_access")
            self.assertEqual(report["value_access"], access, (deleted, code))
            counts = adapter.record_values(report).get("error_counts") or []
            self.assertEqual({row["code"] for row in counts},
                             {"deleted_api_key_unread"} if access == "COMPLETE" else {code})

    def test_a_deleted_key_outside_the_verified_project_is_still_a_value_gap(self):
        from unittest import mock

        from cremore_gcp_provider.metadata.collector import Collector

        data = with_values()
        data[f"https://apikeys.googleapis.com/v2/projects/{PROJECT}/locations/global/keys"]["keys"][0][
            "deleteTime"] = "2026-09-01T00:00:00Z"
        real, asked = Collector.project_resource, set()

        def bound(collector, name):
            # Listed in the project, then not verified again when its value is to be read.
            if "/locations/global/keys/" in name and name in asked:
                return False
            asked.add(name)
            return real(collector, name)

        with mock.patch.object(Collector, "project_resource", bound):
            transport, records, _final = run(self.connection(), data, value_context=value_context())
        self.assertFalse(any(url.endswith("/keyString") for _method, url, _params in transport.calls))
        report = next(item for item in records if item["provenance"]["operation"] == "gcp.value_access")
        self.assertEqual(report["value_access"], "PARTIAL")
        self.assertIn("PROJECT_SCOPE_UNVERIFIED", report["reasons"])

    def test_a_destroyed_version_is_never_asked_for_its_payload(self):
        transport, _records, _ = run(self.connection(), with_values(),
                                     value_context=value_context())
        asked = [url for _method, url, _params in transport.calls if url.endswith(":access")]
        self.assertTrue(all("/versions/1:access" not in url or "europe-west4" in url
                            for url in asked), asked)

    def test_a_run_that_wants_values_without_an_engine_refuses_to_start(self):
        with self.assertRaises(ValueError):
            drain(collect(self.connection(), with_values())[1])

    def test_a_value_read_keeps_the_listed_metadata_and_state(self):
        data = with_values()
        data[f"https://apikeys.googleapis.com/v2/projects/{PROJECT}/locations/global/keys"]["keys"][0][
            "deleteTime"] = "2026-09-01T00:00:00Z"
        _t, records, _ = run(self.connection(), data, value_context=value_context())
        rows = entities(records, "")
        read = [row for row in rows if row["value_match"]]
        self.assertEqual({row["identity"]["object_id"].split(":")[0] for row in read}, {"apiKey", "secretVersion"})
        for row in read:
            # Committed later in the run, the read becomes the entity's current observation.
            [listed] = [other for other in rows if not other["value_match"]
                        and other["identity"] == row["identity"]]
            self.assertEqual((row["facts"], row["normalized_state"]), (listed["facts"], listed["normalized_state"]))
        key = next(row for row in read if row["identity"]["object_id"].startswith("apiKey:"))
        self.assertEqual(key["normalized_state"], "DELETED")
        self.assertEqual(adapter.record_values(key)["display_name"], "browser key")

    def test_a_resumed_value_phase_reads_each_listed_object_once(self):
        connection = self.connection()
        first, pages = collect(connection, with_values(), value_context=value_context())
        committed, checkpoint = [], None
        for page in pages:
            committed.extend(item.model_dump() for item in page.records)
            if page.checkpoint["phase"] == "values" and page.checkpoint["cursor"]:
                checkpoint = page.checkpoint
                pages.close()
                break
        second, rest = collect(connection, with_values(), committed=committed, checkpoint=checkpoint,
                               value_context=value_context())
        records, _final = drain(rest)
        reads = [url for transport in (first, second) for _, url, _ in transport.calls
                 if url.endswith(("/keyString", ":access"))]
        self.assertEqual(len(reads), 3)
        self.assertEqual(len(set(reads)), 3)
        report = next(row for row in records if row.record_type == "operation_report"
                      and row.provenance.operation == "gcp.value_access")
        self.assertEqual((report.received_records, report.value_access), (3, "COMPLETE"))


class RestartTests(unittest.TestCase):
    def drive(self, connection, responses, *, stop_after=None, checkpoint=None, committed=None,
              check=None):
        committed = list(committed or [])
        transport = FakeTransport(responses, check=check)
        pages = adapter.collect_pages(
            connection, secrets={}, checkpoint=checkpoint or {}, check=check or (lambda: None),
            transport=transport, now=NOW,
            read_records=(lambda: iter(committed)) if checkpoint is not None else None)
        state, final = checkpoint or {}, None
        for seen, page in enumerate(pages, start=1):
            committed.extend(item.model_dump() for item in page.records)
            state = page.checkpoint
            if page.status is not None:
                final = page
            if stop_after is not None and seen >= stop_after:
                pages.close()
                break
        return transport, committed, state, final

    def test_a_restart_replays_nothing_and_produces_the_same_records(self):
        connection = spec(options={"locations": ["europe-west4"]})
        whole, full_records, _state, final = self.drive(connection, inventory_responses())
        partial, committed, state, _ = self.drive(connection, inventory_responses(), stop_after=5)
        rest, resumed, _state, resumed_final = self.drive(
            connection, inventory_responses(), checkpoint=state, committed=committed)

        def key(item):
            return (item["record_type"], item.get("identity", {}).get("object_id"),
                    item["provenance"]["operation"], item["provenance"]["resource_id"])

        self.assertEqual(sorted(map(key, full_records)), sorted(map(key, resumed)))
        self.assertEqual(final.status, resumed_final.status)
        self.assertEqual(partial.requests + rest.requests, whole.requests)

    def test_a_completed_run_re_reads_nothing_when_it_is_resumed(self):
        connection = spec(options={"locations": ["europe-west4"]})
        _transport, committed, state, _ = self.drive(connection, inventory_responses())
        transport, resumed, _state, final = self.drive(
            connection, inventory_responses(), checkpoint=state, committed=committed)
        self.assertEqual(transport.calls, [])
        self.assertEqual(len(resumed), len(committed))
        self.assertEqual(final.status, "PARTIAL")

    def test_a_changed_connection_refuses_the_old_checkpoint(self):
        connection = spec(options={"locations": ["europe-west4"]})
        _transport, committed, state, _ = self.drive(connection, inventory_responses(),
                                                     stop_after=3)
        changed = spec(options={"locations": ["us-east1"]})
        with self.assertRaises(ValueError) as caught:
            self.drive(changed, inventory_responses(), checkpoint=state, committed=committed)
        self.assertEqual(str(caught.exception), "GCP_CHECKPOINT_MISMATCH")

    def test_a_checkpoint_from_before_raw_storage_retirement_needs_a_new_run(self):
        connection = spec()
        _transport, committed, state, _ = self.drive(connection, inventory_responses(), stop_after=3)
        legacy = connection.model_dump()
        legacy["options"]["store_values"] = False
        state["config_hash"] = digest(legacy)
        with self.assertRaisesRegex(ValueError, "GCP_CHECKPOINT_MISMATCH"):
            self.drive(connection, inventory_responses(), checkpoint=state, committed=committed)
        _transport, _records, _state, final = self.drive(connection, inventory_responses())
        self.assertIsNotNone(final)

    def test_a_checkpoint_without_the_committed_records_is_refused(self):
        connection = spec(options={"locations": ["europe-west4"]})
        _transport, _committed, state, _ = self.drive(connection, inventory_responses(),
                                                      stop_after=3)
        pages = adapter.collect_pages(connection, secrets={}, checkpoint=state,
                                      check=lambda: None, transport=FakeTransport({}), now=NOW)
        with self.assertRaises(ValueError) as caught:
            next(pages)
        self.assertEqual(str(caught.exception), "GCP_RECORD_REPLAY_REQUIRED")

    def test_cancellation_stops_before_the_next_request(self):
        state = {"count": 0}

        def check():
            state["count"] += 1
            if state["count"] > 4:
                raise KeyboardInterrupt("cancelled")

        with self.assertRaises(KeyboardInterrupt):
            self.drive(spec(), inventory_responses(), check=check)

    def test_a_rate_limited_provider_yields_a_waiting_page_with_its_delay(self):
        url = f"https://iam.googleapis.com/v1/projects/{PROJECT}/serviceAccounts"

        class Limited(FakeTransport):
            def get(self, target, params=None):
                if target == url:
                    raise ApiError("rate_limited", retry_after=120)
                return super().get(target, params)

        transport = Limited(inventory_responses())
        _t, _records, final = run(transport=transport)
        self.assertEqual(final.status, "WAITING")
        self.assertEqual(final.reasons, ["RATE_LIMITED"])
        self.assertEqual(final.retry_after_seconds, 120)
        self.assertIsNone(final.principal_id)

    def test_the_record_budget_stops_the_run_as_partial(self):
        connection = spec(max_records=3, options={"locations": ["europe-west4"]})
        _t, records, final = run(connection)
        self.assertEqual(final.status, "PARTIAL")
        self.assertIn("RECORD_BUDGET_EXCEEDED", final.reasons)
        self.assertLessEqual(len(records), 3)


class ContractTests(unittest.TestCase):
    def test_every_emitted_record_passes_the_shared_scope_check(self):
        connection = spec(capabilities=["inventory", "vault_metadata", "relations"],
                          options={"locations": ["europe-west4"], "audit_lookback_days": 1})
        _t, pages = collect(connection, with_evidence())
        for page in pages:
            for item in page.records:
                self.assertTrue(in_metadata_scope(connection, item), item.model_dump())
                self.assertTrue(adapter.validate_record(connection, item))

    def test_a_record_from_another_project_or_origin_is_refused(self):
        connection = spec()
        _t, pages = collect(connection)
        item = next(record for page in pages for record in page.records
                    if record.record_type == "entity_observation")
        other = item.model_copy(deep=True)
        other.identity.object_id = "serviceAccount:collector@other-project.iam.gserviceaccount.com"
        self.assertTrue(adapter.validate_record(connection, other))
        other.identity.origin = "https://iam.googleapis.com"
        self.assertFalse(adapter.validate_record(connection, other))
        moved = item.model_copy(deep=True)
        moved.scope.id = "another-project-id"
        self.assertFalse(adapter.validate_record(connection, moved))

    def test_a_machine_submission_must_name_this_project_in_its_provenance(self):
        connection = spec()
        _t, pages = collect(connection)
        item = next(record for page in pages for record in page.records
                    if record.record_type == "entity_observation")
        self.assertTrue(shared_validate(connection, item))
        forged = item.model_copy(deep=True)
        forged.provenance.resource_id = "projects/someone-elses-project/serviceAccounts/x"
        self.assertFalse(shared_validate(connection, forged))

    def test_the_gcp_adapter_is_the_one_the_registry_resolves(self):
        from cremore.coverage.providers import adapter_for

        self.assertIs(adapter_for("gcp"), adapter)


class SnapshotTests(unittest.TestCase):
    def connection(self):
        return spec(capabilities=["inventory", "vault_metadata", "relations"],
                    options={"locations": ["europe-west4"], "audit_lookback_days": 1})

    def test_the_native_inventory_is_rebuilt_from_the_records_alone(self):
        _t, records, _ = run(self.connection(), with_evidence())
        snapshot = adapter.native_snapshots(records)
        inventory = snapshot["inventory"]
        self.assertEqual(inventory["schema_version"], "0.3")
        self.assertEqual(inventory["project_id"], PROJECT)
        self.assertEqual(inventory["api_states"]["iam.googleapis.com"]["state"], "enabled")
        sources = {item["source"] for item in inventory["items"]}
        self.assertEqual(sources, {"gcp_iam_service_accounts", "gcp_iam_service_account_keys",
                                   "gcp_api_keys", "gcp_secret_manager"})
        # One fixture row has no usable email, so the source is honestly partial.
        self.assertEqual(inventory["coverage"]["service_accounts"]["status"], "partial")
        self.assertEqual(inventory["coverage"]["service_accounts"]["invalid_identifiers"], 1)
        self.assertEqual(inventory["coverage"]["service_account_keys"]["error_counts"],
                         {"invalid_key_identifier": 2})

    def test_each_secret_keeps_its_own_version_coverage(self):
        _t, records, _ = run(self.connection(), with_evidence())
        coverage = adapter.native_snapshots(records)["inventory"]["coverage"]
        self.assertIn("secret_versions:" + SECRET, coverage)
        self.assertIn("secret_versions:" + REGIONAL_SECRET, coverage)

    def test_a_relation_carries_the_status_of_its_own_coverage_path(self):
        _t, records, _ = run(self.connection(), with_evidence())
        edges = adapter.native_snapshots(records)["relations"]
        observed = [edge for edge in edges["relations"]
                    if edge["relation"] == "secret_access_observed"]
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["collection_status"],
                         edges["coverage"]["secret_access_logs"]["status"])
        self.assertEqual(edges["secret_index"][SECRET]["status"], "observed_access")
        self.assertEqual(edges["secret_index"][SECRET]["missing_logs_mean"], "unknown_not_unused")

    def test_a_disappearance_is_an_event_only_where_the_source_listed_completely(self):
        _t, before, _ = run(self.connection(), with_evidence())
        data = with_evidence()
        data["https://secretmanager.europe-west4.rep.googleapis.com/v1/projects/"
             f"{PROJECT}/locations/europe-west4/secrets"] = {"secrets": []}
        _t, after, _ = run(self.connection(), data)
        diff = adapter.compare_records(after, before)
        events = {(event["event_type"], event["source_id"]) for event in diff["events"]}
        self.assertIn(("no_longer_listed", REGIONAL_SECRET), events)
        self.assertEqual([row["reason"] for row in diff["absence_not_evaluated"]],
                         ["source_not_completely_listed"])

    def test_a_new_value_is_a_collection_event_and_a_changed_one_is_not_the_same(self):
        connection = spec(capabilities=["inventory", "vault_metadata", "vault_value"],
                          options={"locations": ["europe-west4"], "include_values": True})
        _t, before, _ = run(connection.model_copy(
            update={"options": connection.options.model_copy(update={"include_values": False})}),
            with_values())
        _t, after, _ = run(connection, with_values(), value_context=value_context())
        events = {(event["event_type"], event["source_id"])
                  for event in adapter.compare_records(after, before)["events"]}
        self.assertIn(("value_collected", SECRET + "/versions/2"), events)

    def test_missing_or_incomparable_value_evidence_is_not_a_changed_value(self):
        connection = spec(capabilities=["inventory", "vault_metadata", "vault_value"],
                          options={"include_values": True})
        _t, before, _ = run(connection, with_values(), value_context=value_context())
        url = f"https://secretmanager.googleapis.com/v1/{SECRET}/versions/2:access"
        denied = FakeTransport(with_values(), failures={url: "permission_denied_or_api_disabled"})
        _t, after, _ = run(connection, transport=denied, value_context=value_context())
        diff = adapter.compare_records(after, before)
        self.assertNotIn("value_changed", [e["event_type"] for e in diff["events"]])
        self.assertIn({"source_id": SECRET + "/versions/2", "reason": "value_unavailable"},
                      diff["value_not_evaluated"])
        changed = deepcopy(before)
        for row in changed:
            if (row.get("value_match") or {}).get("evidence") == "VALUE":
                row["value_match"].update(key_id="1" * 64, fingerprint="2" * 64)
            if row.get("payload_digest"):
                row["payload_digest"].update(key_id="1" * 64, fingerprint="2" * 64)
        diff = adapter.compare_records(changed, before)
        self.assertNotIn("value_changed", [e["event_type"] for e in diff["events"]])
        self.assertTrue(all(row["reason"] == "value_contract_changed" for row in diff["value_not_evaluated"]))

    def test_value_comparison_keeps_every_fingerprint_and_ignores_order(self):
        connection = spec(capabilities=["inventory", "vault_metadata", "vault_value"],
                          options={"include_values": True})
        _t, records, _ = run(connection, with_values(), value_context=value_context())
        for row in records:
            row.pop("payload_digest", None)  # Historical records compared detected credentials only.
        first = next(row for row in records if (row.get("value_match") or {}).get("evidence") == "VALUE")
        second = deepcopy(first)
        second["value_match"]["fingerprint"] = "b" * 64
        before = [*records, second]
        after = [row for row in records if row is not first] + [second, first]
        self.assertNotIn("value_changed", [e["event_type"] for e in adapter.compare_records(after, before)["events"]])
        after[-1] = deepcopy(first)
        after[-1]["value_match"]["fingerprint"] = "c" * 64
        self.assertIn("value_changed", [e["event_type"] for e in adapter.compare_records(after, before)["events"]])

    def test_partial_reads_and_payload_contract_changes_never_prove_value_changes(self):
        connection = spec(capabilities=["inventory", "vault_metadata", "vault_value", "issuer_value"],
                          options={"include_values": True})
        _t, before, _ = run(connection, with_values(), value_context=value_context())
        data = with_values()
        data[f"https://secretmanager.googleapis.com/v1/{SECRET}/versions/2:access"]["payload"] = {
            "data": base64.b64encode(b"changed-unclassified").decode()}
        denied = FakeTransport(data, failures={f"https://apikeys.googleapis.com/v2/{API_KEY_NAME}/keyString": "http_403"})
        _t, partial, _ = run(connection, transport=denied, value_context=value_context())
        compared = adapter.compare_records(partial, before)
        self.assertNotIn("value_changed", [event["event_type"] for event in compared["events"]])
        self.assertIn({"source_id": SECRET + "/versions/2", "reason": "value_collection_incomplete"},
                      compared["value_not_evaluated"])
        _t, changed, _ = run(connection, data, value_context=value_context())
        self.assertIn("value_changed", [event["event_type"] for event in adapter.compare_records(changed, before)["events"]])
        for field, value in (("key_id", "1" * 64), ("scheme", "future-payload-hmac")):
            incomparable = deepcopy(changed)
            for row in incomparable:
                if row.get("payload_digest"):
                    row["payload_digest"][field] = value
            result = adapter.compare_records(incomparable, before)
            self.assertNotIn("value_changed", [event["event_type"] for event in result["events"]])
            self.assertTrue(all(row["reason"] == "value_contract_changed" for row in result["value_not_evaluated"]))

    def test_an_empty_project_retains_its_identity_from_coverage(self):
        _t, records, _ = run(spec(capabilities=["inventory"]))
        reports = [row for row in records if row["record_type"] == "operation_report"]
        self.assertEqual(adapter.native_snapshots(reports)["inventory"]["project_id"], PROJECT)

    def test_a_key_identifier_match_is_answered_from_committed_records(self):
        _t, records, _ = run()
        result = adapter.link_service_account_key(records, {
            "type": "service_account", "client_email": EMAIL,
            "private_key_id": "0123456789abcdef0123456789abcdef01234567"})
        self.assertEqual(result["status"], "identifier_match")
        self.assertEqual(result["validity"], "unverified")


if __name__ == "__main__":
    unittest.main()
