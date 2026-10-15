"""End-to-end collection contracts over synthetic transport and metadata."""

import json
import unittest
from unittest.mock import Mock

from cremore_atlassian_provider.metadata.collector import collect, safe_summary
from cremore_atlassian_provider.metadata.http import CloudClient, FetchResult, Limits
from cremore_atlassian_provider.metadata.metadata import normalize

ORG = "00000000-0000-0000-0000-000000000001"
NOW = "2026-09-19T12:00:00+00:00"
SECRET = "SYNTHETIC_UNKNOWN_SECRET"
PII = "synthetic-private@example.invalid"


def token(identifier="token-1", **changes):
    data = {
        "id": identifier,
        "label": "lab",
        "status": "ALLOWED",
        "createdAt": "2026-09-19T09:00:00Z",
        "expiresAt": "2026-10-19T09:00:00Z",
        "lastActiveAt": None,
        "user": {"id": "service-1", "orgId": ORG, "name": "lab-service", "email": PII},
        "scopes": ["read:jira-user"],
    }
    data.update(changes)
    return data


def page(records, cursor=None):
    return FetchResult(200, {"data": records, "links": {"next": cursor}}, 1)


class FakeClient:
    def snapshot(self, body):
        from cremore_atlassian_provider.metadata.snapshot import metadata_snapshot

        return metadata_snapshot(body, sensitive_values=(SECRET,))

    def __init__(self, pages, **limits):
        self.org_id, self.limits, self.queries = ORG, Limits(**limits), []
        self.pages = {source: iter(items) for source, items in pages.items()}

    def fetch(self, source, query):
        self.queries.append((source, dict(query)))
        result = next(self.pages[source])
        if isinstance(result, Exception):
            raise result
        return result


def run(client, sources=None):
    return collect(client, sources, now=lambda: NOW)


class CollectorTests(unittest.TestCase):
    def test_three_source_lab_inventory_counts_token_once_keeps_both_origins(self):
        key = {
            "id": "key-1",
            "label": "admin",
            "createdAt": NOW,
            "expiresAt": NOW,
            "lastActiveAt": NOW,
            "createdBy": {"id": "human-1", "name": "human", "email": PII},
        }
        sample = token()
        client = FakeClient(
            {
                "admin-api-keys": [page([key])],
                "org-api-tokens": [page([sample])],
                "service-account-api-tokens": [FetchResult(200, [sample], 1)],
            }
        )
        result = run(client)
        self.assertEqual(result["run_status"], "complete")
        self.assertFalse(result["inventory_complete"])
        self.assertEqual(
            result["counts"],
            {
                "observations": 3,
                "identities": 2,
                "unambiguous_credentials": 2,
                "conflicted_identities": 0,
            },
        )
        entry = result["inventory"][1]
        self.assertEqual(entry["principal_kind"], "service_account")
        self.assertEqual(entry["sources"], ["org-api-tokens", "service-account-api-tokens"])
        self.assertEqual(len(entry["observations"]), 2)
        self.assertEqual(result["warning_counts"], {"required_missing:keyType": 1})
        self.assertNotIn(PII, json.dumps(safe_summary(result)))

    def test_cursor_pages_keep_parameters_empty_middle_page_and_original_values(self):
        client = FakeClient(
            {
                "org-api-tokens": [
                    page([token()], "opaque+/="),
                    page([], "third"),
                    page([token("token-2")]),
                ]
            }
        )
        result = run(client, ["org-api-tokens"])
        self.assertEqual(result["run_status"], "complete")
        self.assertEqual(result["counts"]["identities"], 2)
        self.assertEqual(
            [q for _, q in client.queries],
            [
                {"pageSize": 20},
                {"pageSize": 20, "cursor": "opaque+/="},
                {"pageSize": 20, "cursor": "third"},
            ],
        )
        self.assertEqual(result["collections"]["admin-api-keys"]["coverage"], "not_requested")

    def test_source_failure_does_not_erase_other_records_or_assert_human_owner(self):
        client = FakeClient(
            {
                "org-api-tokens": [page([token()])],
                "service-account-api-tokens": [FetchResult(404, attempts=1, reason="http_404")],
            }
        )
        result = run(client, ["org-api-tokens", "service-account-api-tokens"])
        self.assertEqual(result["run_status"], "partial")
        self.assertEqual(result["inventory"][0]["principal_kind"], "unknown")
        self.assertEqual(result["counts"]["identities"], 1)
        self.assertEqual(result["collections"]["service-account-api-tokens"]["coverage"], "failed")

    def test_midstream_retry_exhaustion_keeps_data_and_attempt_count(self):
        client = FakeClient(
            {
                "org-api-tokens": [
                    page([token()], "next"),
                    FetchResult(429, attempts=3, reason="http_429"),
                ]
            }
        )
        result = run(client, ["org-api-tokens"])
        report = result["collections"]["org-api-tokens"]
        self.assertEqual(
            (report["coverage"], report["requests"], report["pages"]), ("partial", 4, 1)
        )
        self.assertEqual(result["counts"]["identities"], 1)

    def test_limits_cycles_and_missing_next_never_claim_completion(self):
        cases = [
            ([page([token()], "more")], {"max_pages": 1}, "page_limit"),
            ([page([token(), token("two")])], {"max_records": 1}, "record_limit"),
            ([page([token()], "more")], {"max_records": 1}, "record_limit"),
            ([page([], "same"), page([], "same")], {}, "repeated_cursor"),
            (
                [FetchResult(200, {"data": [token()]}, 1)],
                {},
                "missing_pagination_contract",
            ),
            ([page([token()], {"secret": SECRET})], {}, "invalid_cursor"),
        ]
        for pages, limits, reason in cases:
            with self.subTest(reason=reason):
                result = run(FakeClient({"org-api-tokens": pages}, **limits), ["org-api-tokens"])
                self.assertEqual(result["collections"]["org-api-tokens"]["reason"], reason)
                self.assertEqual(result["run_status"], "partial")
                self.assertNotIn(SECRET, json.dumps(result))

    def test_a_last_page_without_a_next_cursor_is_complete(self):
        # API Access: "If there are more results ... a `next` cursor is included in the response links."
        result = run(FakeClient({"org-api-tokens": [FetchResult(200, {"data": [token()], "links": {}}, 1)]}),
                     ["org-api-tokens"])
        self.assertEqual(result["collections"]["org-api-tokens"]["coverage"], "complete")
        self.assertEqual(result["run_status"], "complete")

    def test_exact_terminal_limits_and_empty_documented_results_can_complete(self):
        for records in ([], [token()]):
            with self.subTest(count=len(records)):
                result = run(
                    FakeClient({"org-api-tokens": [page(records)]}, max_pages=1, max_records=1),
                    ["org-api-tokens"],
                )
                self.assertEqual(result["run_status"], "complete")
        result = run(
            FakeClient({"service-account-api-tokens": [FetchResult(200, [], 1)]}),
            ["service-account-api-tokens"],
        )
        self.assertEqual(
            result["collections"]["service-account-api-tokens"]["coverage_basis"],
            "documented_array",
        )

    def test_invalid_records_are_counted_and_raw_unknown_fields_are_not_saved(self):
        sample = token(secret=SECRET)
        sample["user"]["clientSecret"] = SECRET
        records = [sample, {}, {"id": None}, {"id": True}, {"id": " "}, SECRET]
        result = run(FakeClient({"org-api-tokens": [page(records)]}), ["org-api-tokens"])
        self.assertEqual(result["collections"]["org-api-tokens"]["invalid_records"], 5)
        self.assertEqual(result["run_status"], "partial")
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn(PII, json.dumps(safe_summary(result)))

    def test_conflicting_subjects_and_metadata_retain_versions_and_no_forced_owner(self):
        first, second = token(), token(label="changed")
        second["user"]["id"] = "other-subject"
        result = run(
            FakeClient(
                {
                    "org-api-tokens": [page([first])],
                    "service-account-api-tokens": [FetchResult(200, [second], 1)],
                }
            ),
            ["org-api-tokens", "service-account-api-tokens"],
        )
        entry = result["inventory"][0]
        self.assertEqual(entry["conflict_fields"], ["label", "user.id"])
        self.assertEqual(entry["principal_kind"], "unknown")
        self.assertEqual(len(entry["observations"]), 2)
        self.assertEqual(result["counts"]["unambiguous_credentials"], 0)
        self.assertEqual(result["run_status"], "partial")

    def test_same_id_of_key_and_token_does_not_merge(self):
        result = run(
            FakeClient(
                {
                    "admin-api-keys": [page([{"id": "same"}])],
                    "org-api-tokens": [page([token("same")])],
                }
            ),
            ["admin-api-keys", "org-api-tokens"],
        )
        self.assertEqual(result["counts"]["identities"], 2)

    def test_duplicate_ids_within_source_are_retained_and_unverified(self):
        result = run(FakeClient({"org-api-tokens": [page([token(), token()])]}), ["org-api-tokens"])
        self.assertEqual(result["run_status"], "unverified")
        self.assertEqual(result["collections"]["org-api-tokens"]["duplicate_observations"], 1)
        self.assertEqual(len(result["inventory"][0]["observations"]), 2)

    def test_wrong_shapes_and_exception_text_are_failed_without_leaks(self):
        for payload in (FetchResult(200, [], 1), RuntimeError(SECRET)):
            with self.subTest(payload=type(payload).__name__):
                result = run(FakeClient({"org-api-tokens": [payload]}), ["org-api-tokens"])
                self.assertEqual(result["run_status"], "failed")
                self.assertNotIn(SECRET, json.dumps(result))

    def test_unexpected_transport_failure_still_counts_attempted_request(self):
        opener = Mock()
        opener.open.side_effect = RuntimeError(SECRET)
        client = CloudClient(ORG, "SYNTHETIC_AUTH", opener=opener)
        result = run(client, ["org-api-tokens"])
        report = result["collections"]["org-api-tokens"]
        self.assertEqual(
            (report["coverage"], report["reason"], report["requests"]),
            ("failed", "fetch_exception", 1),
        )
        self.assertNotIn(SECRET, json.dumps(result))

    def test_null_missing_invalid_parent_and_empty_scope_remain_distinct(self):
        for parent, expected in ((None, "null"), (SECRET, "invalid_type"), ({}, "present")):
            item = normalize("org-api-tokens", token(user=parent, scopes=[]), NOW)
            self.assertEqual(item["parent_states"]["user"], expected)
            self.assertEqual(item["fields"]["user.id"]["state"], "missing")
            self.assertEqual(item["fields"]["lastActiveAt"]["state"], "null")
            self.assertEqual(item["fields"]["scopes"], {"state": "present", "value": []})
            self.assertNotIn(SECRET, json.dumps(item))
        sample = token(scopes=[{"secret": SECRET}])
        del sample["user"]
        item = normalize("org-api-tokens", sample, NOW)
        self.assertEqual(item["parent_states"]["user"], "missing")
        self.assertEqual(item["fields"]["scopes"]["state"], "invalid_type")
        self.assertNotIn(SECRET, json.dumps(item))

    def test_times_expiry_and_unknown_status_do_not_overwrite_provider_fields(self):
        sample = token(createdAt="2026-09-19T21:00:00+09:00", expiresAt="2026-09-18T00:00:00Z")
        item = normalize("org-api-tokens", sample, NOW)
        self.assertEqual(item["fields"]["createdAt"]["normalized_utc"], NOW)
        self.assertTrue(item["derived"]["expired_at_observation"])
        self.assertEqual(item["fields"]["status"]["value"], "ALLOWED")
        item = normalize(
            "org-api-tokens",
            token(createdAt="2026-09-19T12:00:00", expiresAt=True, status="NEW_STATUS"),
            NOW,
        )
        self.assertIn("invalid_timestamp:createdAt", item["warnings"])
        self.assertIn("unknown_status:status", item["warnings"])
        self.assertEqual(item["fields"]["expiresAt"]["state"], "invalid_type")
        self.assertIsNone(item["derived"]["expired_at_observation"])
        self.assertEqual(
            normalize("org-api-tokens", token(status="EXPIRED"), NOW)["fields"]["status"]["value"],
            "EXPIRED",
        )

    def test_scope_order_does_not_create_false_identity_conflict(self):
        first, second = token(scopes=["scope-a", "scope-b"]), token(scopes=["scope-b", "scope-a"])
        result = run(
            FakeClient(
                {
                    "org-api-tokens": [page([first])],
                    "service-account-api-tokens": [FetchResult(200, [second], 1)],
                }
            ),
            ["org-api-tokens", "service-account-api-tokens"],
        )
        self.assertEqual(result["inventory"][0]["conflict_fields"], [])
        self.assertEqual(
            result["inventory"][0]["observations"][1]["fields"]["scopes"]["value"],
            ["scope-b", "scope-a"],
        )

    def test_selection_validation_precedes_transport(self):
        for sources in ([], ["org-api-tokens", "org-api-tokens"], ["unknown"]):
            client = FakeClient({})
            with self.assertRaises(ValueError):
                run(client, sources)
            self.assertEqual(client.queries, [])

    def test_source_org_and_scope_inconsistencies_are_preserved_as_warnings(self):
        sample = token(scopes=[])
        sample["user"]["orgId"] = "different-organization"
        result = run(
            FakeClient({"service-account-api-tokens": [FetchResult(200, [sample], 1)]}),
            ["service-account-api-tokens"],
        )
        item = result["inventory"][0]["observations"][0]
        self.assertIn("empty_service_account_scopes", item["warnings"])
        self.assertIn("queried_org_mismatch:user.orgId", item["warnings"])
        self.assertEqual(item["fields"]["user.orgId"]["value"], "different-organization")
        self.assertEqual(result["queried_org_id"], ORG)


if __name__ == "__main__":
    unittest.main()
