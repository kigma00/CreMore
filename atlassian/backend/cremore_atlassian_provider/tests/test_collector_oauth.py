"""OAuth contracts, identity uncertainty and private output over synthetic data."""

import json
import unittest

from cremore_atlassian_provider.metadata.collector import safe_summary
from cremore_atlassian_provider.metadata.http import FetchResult
from cremore_atlassian_provider.metadata.metadata import normalize

from .test_collector import NOW, ORG, PII, SECRET, FakeClient, page, run, token

SERVICE = "service-account-oauth-clients"
GENERAL = "org-oauth-clients"


def service(identifier="client-1", **changes):
    sample = {
        "clientId": identifier,
        "clientName": "synthetic OAuth",
        "createdAt": NOW,
        "expiresAt": None,
        "scopes": ["read:jira-user"],
        "serviceAccount": {
            "id": "service-1",
            "name": "synthetic service",
            "orgId": ORG,
            "email": PII,
        },
        "createdBy": {"id": "human-1", "name": "synthetic creator", "email": None},
        "clientRevokerId": "revoker-1",
        "clientRevocationTime": None,
    }
    sample.update(changes)
    return sample


def general(identifier="client-1", **changes):
    sample = {
        "clientId": identifier,
        "name": "synthetic OAuth",
        "status": "ACTIVE",
        "createdAt": 0,
        "updatedAt": 1234,
    }
    sample.update(changes)
    return sample


class OAuthTests(unittest.TestCase):
    def test_observed_service_shape_on_both_endpoints_merges_identity_and_keeps_provenance(self):
        sample = service(disabled=False, tokenEndpointAuthMethod=None)
        result = run(
            FakeClient(
                {SERVICE: [FetchResult(200, [sample], 1)], GENERAL: [FetchResult(200, [sample], 1)]}
            ),
            [SERVICE, GENERAL],
        )
        self.assertEqual(
            result["counts"],
            {
                "observations": 2,
                "identities": 1,
                "unambiguous_credentials": 1,
                "conflicted_identities": 0,
            },
        )
        self.assertEqual(result["identity_link_candidates"], [])
        self.assertEqual(result["warning_counts"], {})
        self.assertEqual(result["run_status"], "unverified")
        entry = result["inventory"][0]
        self.assertEqual(entry["kind"], "service_account_oauth_client")
        self.assertEqual(entry["sources"], [SERVICE, GENERAL])
        self.assertEqual(entry["principal_kind"], "service_account")
        self.assertEqual([o["source"] for o in entry["observations"]], [SERVICE, GENERAL])
        for item in entry["observations"]:
            self.assertEqual(item["record_contract"], "service_account_oauth_client")
            self.assertEqual(item["fields"]["createdAt"]["normalized_utc"], NOW)
            self.assertEqual(item["fields"]["disabled"], {"state": "present", "value": False})
            self.assertNotIn("status", item["fields"])

    def test_variant_conflict_retains_both_versions_and_unknown_principal(self):
        changed = service(serviceAccount={"id": "other-service", "name": "different"})
        result = run(
            FakeClient(
                {
                    SERVICE: [FetchResult(200, [service()], 1)],
                    GENERAL: [FetchResult(200, [changed], 1)],
                }
            ),
            [SERVICE, GENERAL],
        )
        entry = result["inventory"][0]
        self.assertEqual(result["run_status"], "partial")
        self.assertEqual(result["counts"]["unambiguous_credentials"], 0)
        self.assertIn("serviceAccount.id", entry["conflict_fields"])
        self.assertEqual(entry["principal_kind"], "unknown")
        self.assertEqual(len(entry["observations"]), 2)

    def test_documented_envelope_is_not_reinterpreted_as_observed_array(self):
        result = run(FakeClient({GENERAL: [page([service()])]}), [GENERAL])
        item = result["inventory"][0]["observations"][0]
        self.assertEqual(item["record_contract"], "org_oauth_client")
        self.assertIn("invalid_type:createdAt", item["warnings"])
        self.assertNotIn("serviceAccount.id", item["fields"])

    def test_array_contract_selection_never_guesses_from_timestamp_type(self):
        sample = general(createdAt=NOW)
        result = run(FakeClient({GENERAL: [FetchResult(200, [sample], 1)]}), [GENERAL])
        item = result["inventory"][0]["observations"][0]
        self.assertEqual(item["record_contract"], "org_oauth_client")
        self.assertIn("invalid_type:createdAt", item["warnings"])
        sample = service(createdAt=0)
        result = run(FakeClient({GENERAL: [FetchResult(200, [sample], 1)]}), [GENERAL])
        item = result["inventory"][0]["observations"][0]
        self.assertEqual(item["record_contract"], "service_account_oauth_client")
        self.assertIn("invalid_type:createdAt", item["warnings"])

    def test_mixed_record_contracts_stay_separate_and_ambiguous_markers_warn(self):
        result = run(
            FakeClient({GENERAL: [FetchResult(200, [service(), general()], 1)]}), [GENERAL]
        )
        self.assertEqual(result["counts"]["identities"], 2)
        self.assertEqual(len(result["identity_link_candidates"]), 1)
        sample = service(name="ambiguous", status="ACTIVE")
        result = run(FakeClient({GENERAL: [FetchResult(200, [sample], 1)]}), [GENERAL])
        self.assertIn("ambiguous_oauth_record_contract", result["warning_counts"])
        self.assertEqual(result["inventory"][0]["kind"], "org_oauth_client")

    def test_array_variant_applies_service_parent_validation_org_warning_and_secret_filter(self):
        sample = service(createdBy={}, clientSecret=SECRET)
        sample["serviceAccount"]["orgId"] = "different-org"
        sample["serviceAccount"]["secret"] = SECRET
        result = run(FakeClient({GENERAL: [FetchResult(200, [sample], 1)]}), [GENERAL])
        self.assertIn("required_missing:createdBy.id", result["warning_counts"])
        self.assertIn("queried_org_mismatch:serviceAccount.orgId", result["warning_counts"])
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn(PII, json.dumps(safe_summary(result)))

    def test_observed_extra_fields_preserve_boolean_null_without_status_inference(self):
        for value in (True, False):
            item = normalize(SERVICE, service(disabled=value, tokenEndpointAuthMethod=None), NOW)
            self.assertEqual(item["fields"]["disabled"], {"state": "present", "value": value})
            self.assertEqual(item["fields"]["tokenEndpointAuthMethod"], {"state": "null"})
            self.assertNotIn("status", item["fields"])
        for value in (0, 1, "false", []):
            item = normalize(SERVICE, service(disabled=value, tokenEndpointAuthMethod=SECRET), NOW)
            self.assertEqual(item["fields"]["disabled"]["state"], "invalid_type")
            self.assertEqual(item["fields"]["tokenEndpointAuthMethod"]["state"], "invalid_type")
            self.assertNotIn(SECRET, json.dumps(item))

    def test_service_subject_creator_and_revoker_stay_separate_without_invented_status(self):
        result = run(FakeClient({SERVICE: [FetchResult(200, [service()], 1)]}), [SERVICE])
        entry = result["inventory"][0]
        item = entry["observations"][0]
        self.assertEqual(result["run_status"], "complete")
        self.assertEqual(entry["principal_kind"], "service_account")
        self.assertEqual(item["fields"]["serviceAccount.id"]["value"], "service-1")
        self.assertEqual(item["fields"]["createdBy.id"]["value"], "human-1")
        self.assertEqual(item["fields"]["clientRevokerId"]["value"], "revoker-1")
        self.assertNotIn("status", item["fields"])
        self.assertNotIn("lastActiveAt", item["fields"])
        self.assertEqual(item["fields"]["expiresAt"]["state"], "null")
        self.assertEqual(item["warnings"], [])

    def test_optional_creator_missing_null_and_malformed_are_distinct(self):
        absent = service()
        del absent["createdBy"]
        for sample, expected in (
            (absent, "missing"),
            (service(createdBy=None), "null"),
            (service(createdBy=SECRET), "invalid_type"),
        ):
            with self.subTest(state=expected):
                item = normalize(SERVICE, sample, NOW)
                self.assertEqual(item["parent_states"]["createdBy"], expected)
                self.assertEqual(
                    item["warnings"],
                    ["parent_invalid_type:createdBy"] if expected == "invalid_type" else [],
                )
                self.assertNotIn(SECRET, json.dumps(item))
        item = normalize(SERVICE, service(createdBy={}), NOW)
        self.assertEqual(
            set(item["warnings"]),
            {"required_missing:createdBy.id", "required_missing:createdBy.name"},
        )

    def test_missing_subject_retains_client_but_does_not_assert_principal(self):
        for subject in (None, {}, "malformed"):
            result = run(
                FakeClient({SERVICE: [FetchResult(200, [service(serviceAccount=subject)], 1)]}),
                [SERVICE],
            )
            self.assertEqual(result["inventory"][0]["principal_kind"], "unknown")
            self.assertIn("required_missing:serviceAccount.id", result["warning_counts"])
            self.assertEqual(result["counts"]["identities"], 1)

    def test_optional_nullable_token_user_fields_and_organization_mismatch(self):
        sample = service()
        sample["serviceAccount"].update(
            {"appType": None, "userStatus": "active", "orgId": "different-org"}
        )
        result = run(FakeClient({SERVICE: [FetchResult(200, [sample], 1)]}), [SERVICE])
        fields = result["inventory"][0]["observations"][0]["fields"]
        self.assertEqual(fields["serviceAccount.appType"]["state"], "null")
        self.assertEqual(fields["serviceAccount.userStatus"]["value"], "active")
        self.assertIn("queried_org_mismatch:serviceAccount.orgId", result["warning_counts"])

    def test_org_epoch_milliseconds_keep_raw_and_do_not_invent_owner_or_expiry(self):
        item = normalize(GENERAL, general(), NOW)
        self.assertEqual(
            item["fields"]["createdAt"],
            {"state": "present", "value": 0, "normalized_utc": "1970-01-01T00:00:00+00:00"},
        )
        self.assertEqual(
            item["fields"]["updatedAt"]["normalized_utc"], "1970-01-01T00:00:01.234000+00:00"
        )
        self.assertEqual(item["derived"], {})
        self.assertEqual(item["parent_states"], {})
        for field in ("expiresAt", "scopes", "user.id", "serviceAccount.id", "lastActiveAt"):
            self.assertNotIn(field, item["fields"])
        negative = normalize(GENERAL, general(createdAt=-1), NOW)
        self.assertEqual(
            negative["fields"]["createdAt"]["normalized_utc"], "1969-12-31T23:59:59.999000+00:00"
        )

    def test_epoch_rejects_bool_float_and_string_without_guessing_units(self):
        for value in (True, False, "0", 1.5, []):
            with self.subTest(value=value):
                item = normalize(GENERAL, general(createdAt=value), NOW)
                self.assertEqual(item["fields"]["createdAt"], {"state": "invalid_type"})
                self.assertIn("invalid_type:createdAt", item["warnings"])
        item = normalize(GENERAL, general(createdAt=10**30), NOW)
        self.assertEqual(item["fields"]["createdAt"]["value"], 10**30)
        self.assertIn("invalid_timestamp:createdAt", item["warnings"])
        item = normalize(GENERAL, general(createdAt=None), NOW)
        self.assertEqual(item["fields"]["createdAt"], {"state": "null"})

    def test_service_iso_expiry_and_revocation_do_not_synthesize_missing_values(self):
        item = normalize(
            SERVICE,
            service(
                createdAt="2026-09-19T21:00:00+09:00",
                expiresAt="2026-09-18T00:00:00Z",
                clientRevocationTime="2026-09-19T12:00:00",
            ),
            NOW,
        )
        self.assertEqual(item["fields"]["createdAt"]["normalized_utc"], NOW)
        self.assertTrue(item["derived"]["expired_at_observation"])
        self.assertIn("invalid_timestamp:clientRevocationTime", item["warnings"])
        self.assertNotIn("status", item["fields"])

    def test_unknown_status_and_missing_required_metadata_are_preserved(self):
        for status in ("ACTIVE", "REVOKED", "EXPIRED", "FUTURE"):
            item = normalize(GENERAL, general(status=status), NOW)
            self.assertEqual(item["fields"]["status"]["value"], status)
            self.assertEqual("unknown_status:status" in item["warnings"], status == "FUTURE")
        item = normalize(GENERAL, {"clientId": "client"}, NOW)
        self.assertEqual(
            set(item["warnings"]), {"required_missing:name", "required_missing:status"}
        )

    def test_unknown_secret_fields_never_enter_inventory_or_summary(self):
        sample = service(clientSecret=SECRET, access_token=SECRET, refresh_token=SECRET)
        sample["serviceAccount"]["secret"] = SECRET
        sample["createdBy"]["private_key"] = SECRET
        result = run(FakeClient({SERVICE: [FetchResult(200, [sample], 1)]}), [SERVICE])
        self.assertNotIn(SECRET, json.dumps(result))
        for private in (PII, ORG, "client-1", "human-1"):
            self.assertNotIn(private, json.dumps(safe_summary(result)))

    def test_client_id_required_and_never_falls_back_to_id_or_name(self):
        records = [
            {"id": "token", "name": "label"},
            {},
            {"clientId": None},
            {"clientId": True},
            {"clientId": " "},
            {"clientId": "x\ny"},
            service(),
        ]
        result = run(FakeClient({SERVICE: [FetchResult(200, records, 1)]}), [SERVICE])
        self.assertEqual(result["counts"]["identities"], 1)
        self.assertEqual(result["collections"][SERVICE]["invalid_records"], 6)
        self.assertEqual(result["run_status"], "partial")

    def test_same_client_id_is_a_candidate_not_a_merge_or_definite_double_count(self):
        result = run(
            FakeClient({SERVICE: [FetchResult(200, [service()], 1)], GENERAL: [page([general()])]}),
            [SERVICE, GENERAL],
        )
        self.assertEqual(
            result["counts"],
            {
                "observations": 2,
                "identities": 2,
                "unambiguous_credentials": 0,
                "conflicted_identities": 0,
            },
        )
        self.assertEqual(result["run_status"], "unverified")
        self.assertEqual(
            result["identity_link_candidates"],
            [
                {
                    "state": "unverified",
                    "basis": "same_client_id",
                    "provider_id": "client-1",
                    "kinds": ["service_account_oauth_client", "org_oauth_client"],
                }
            ],
        )
        self.assertEqual(safe_summary(result)["candidate_link_count"], 1)
        self.assertNotIn("client-1", json.dumps(safe_summary(result)))

    def test_same_string_token_id_and_oauth_id_remain_separate(self):
        result = run(
            FakeClient(
                {"org-api-tokens": [page([token("client-1")])], GENERAL: [page([general()])]}
            ),
            ["org-api-tokens", GENERAL],
        )
        self.assertEqual(result["counts"]["identities"], 2)
        self.assertEqual(result["identity_link_candidates"], [])

    def test_documented_cursor_pages_and_service_empty_array_complete(self):
        client = FakeClient(
            {
                GENERAL: [page([general()], "next"), page([general("client-2")])],
                SERVICE: [FetchResult(200, [], 1)],
            }
        )
        result = run(client, [GENERAL, SERVICE])
        self.assertEqual(result["run_status"], "complete")
        self.assertEqual(
            client.queries,
            [
                (GENERAL, {"pageSize": 20}),
                (GENERAL, {"pageSize": 20, "cursor": "next"}),
                (SERVICE, {}),
            ],
        )

    def test_supported_array_preserves_observations_but_not_pagination_completion(self):
        for records in ([], [general()], [general(), general()]):
            result = run(FakeClient({GENERAL: [FetchResult(200, records, 1)]}), [GENERAL])
            self.assertEqual(result["run_status"], "unverified")
            self.assertEqual(result["counts"]["observations"], len(records))
            report = result["collections"][GENERAL]
            self.assertEqual(
                (report["coverage_basis"], report["reason"]),
                ("support_confirmed_array", "pagination_contract_unverified"),
            )
            self.assertEqual(report["requests"], 1)

    def test_array_variant_after_cursor_page_stops_without_inventing_next(self):
        result = run(
            FakeClient(
                {GENERAL: [page([general()], "more"), FetchResult(200, [general("client-2")], 1)]}
            ),
            [GENERAL],
        )
        self.assertEqual(result["run_status"], "unverified")
        self.assertEqual(result["counts"]["observations"], 2)
        self.assertEqual(result["collections"][GENERAL]["pages"], 2)

    def test_array_invalid_records_limits_and_http_failure_remain_partial(self):
        cases = [
            ([FetchResult(200, [general(), {}], 1)], {}, "invalid_records"),
            (
                [FetchResult(200, [general(), general("two")], 1)],
                {"max_records": 1},
                "record_limit",
            ),
            (
                [page([general()], "more"), FetchResult(403, attempts=1, reason="http_403")],
                {},
                "http_403",
            ),
        ]
        for pages, limits, reason in cases:
            with self.subTest(reason=reason):
                result = run(FakeClient({GENERAL: pages}, **limits), [GENERAL])
                self.assertEqual(result["run_status"], "partial")
                self.assertEqual(result["collections"][GENERAL]["reason"], reason)
                self.assertEqual(result["counts"]["identities"], 1)

    def test_conflicting_service_subjects_do_not_acquire_creator_as_owner(self):
        changed = service(serviceAccount={"id": "other-service", "name": "other"})
        result = run(FakeClient({SERVICE: [FetchResult(200, [service(), changed], 1)]}), [SERVICE])
        entry = result["inventory"][0]
        self.assertEqual(entry["principal_kind"], "unknown")
        self.assertIn("serviceAccount.id", entry["conflict_fields"])
        self.assertEqual(result["run_status"], "partial")


if __name__ == "__main__":
    unittest.main()
