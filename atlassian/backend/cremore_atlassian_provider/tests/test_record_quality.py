"""Collection completeness must account for ambiguous saved list records."""

import json
import unittest
from copy import deepcopy

from cremore_atlassian_provider.metadata.bitbucket import (
    OPERATIONS,
    collect_bitbucket,
    safe_summary,
)
from cremore_atlassian_provider.metadata.compare import compare_snapshots
from cremore_atlassian_provider.metadata.discovery import (
    collect_discovery,
    collect_operation,
    discovery_summary,
)
from cremore_atlassian_provider.metadata.http import FetchResult
from cremore_atlassian_provider.metadata.identities import RecordQuality, record_identity
from cremore_atlassian_provider.metadata.read_operations import READ_OPERATIONS

from .test_bitbucket import Client as BitbucketClient
from .test_bitbucket import empty as bitbucket_empty
from .test_compare import events, snapshot
from .test_discovery import SECRET, Client, empty_baseline, ok


class QualityTests(unittest.TestCase):
    def test_duplicate_ids_across_different_pages_keep_all_records_and_mark_unverified(self):
        bodies = [
            {"data": [{"id": "private-id", "label": "first"}], "links": {"next": "next"}},
            {
                "data": [{"id": "private-id", "label": "second"}, {"id": "other"}],
                "links": {"next": None},
            },
        ]
        client = Client({"admin-api-keys": [ok(body) for body in bodies]})
        report = collect_operation(client, "admin-api-keys")
        self.assertEqual(
            (report["coverage"], report["reason"]), ("unverified", "duplicate_record_identities")
        )
        self.assertEqual(report["saved_records"], 3)
        self.assertEqual([p["metadata"] for p in report["pages"]], bodies)
        self.assertEqual(
            report["record_quality"],
            {
                "assessed_records": 3,
                "identified_records": 3,
                "unique_identities": 2,
                "duplicate_records": 1,
                "invalid_records": 0,
                "unidentified_records": 0,
                "identity_not_configured_records": 0,
            },
        )
        self.assertNotIn("private-id", json.dumps(report["record_quality"]))

    def test_valid_size_does_not_hide_duplicate_runner_ids(self):
        body = {"values": [{"uuid": "same"}, {"uuid": "same"}], "size": 2}
        report = collect_operation(
            BitbucketClient({"workspace-runners": [ok(body)]}),
            "workspace-runners",
            specs=OPERATIONS,
        )
        self.assertEqual(
            (report["coverage"], report["reason"]), ("unverified", "duplicate_record_identities")
        )
        self.assertEqual(report["saved_records"], 2)

    def test_bad_rows_and_missing_ids_are_preserved_but_not_counted_as_identified(self):
        rows = [
            None,
            False,
            "unexpected",
            {"name": "unknown"},
            {"id": True},
            {"id": ""},
            {"id": " "},
            {"id": -1},
            {"id": "line\nbreak"},
            {"id": 0},
        ]
        report = collect_operation(
            Client({"service-account-api-tokens": [ok(rows)]}), "service-account-api-tokens"
        )
        self.assertEqual(
            (report["coverage"], report["reason"]), ("unverified", "unidentifiable_records")
        )
        self.assertEqual(report["pages"][0]["metadata"], rows)
        self.assertEqual(report["record_quality"]["invalid_records"], 3)
        self.assertEqual(report["record_quality"]["unidentified_records"], 6)
        self.assertEqual(report["record_quality"]["unique_identities"], 1)

    def test_quality_assesses_sanitized_ids_without_leaking_authentication(self):
        report = collect_operation(
            Client({"service-account-api-tokens": [ok([{"id": SECRET}])]}),
            "service-account-api-tokens",
        )
        self.assertEqual(report["coverage"], "unverified")
        self.assertEqual(report["record_quality"]["unidentified_records"], 1)
        self.assertNotIn(SECRET, json.dumps(report))

    def test_fetch_failure_keeps_primary_reason_and_duplicate_quality(self):
        client = Client(
            {
                "admin-api-keys": [
                    ok({"data": [{"id": "same"}, {"id": "same"}], "links": {"next": "next"}}),
                    FetchResult(403, attempts=1, reason="http_403"),
                ]
            }
        )
        report = collect_operation(client, "admin-api-keys")
        self.assertEqual((report["coverage"], report["reason"]), ("partial", "http_403"))
        self.assertEqual(report["record_quality"]["duplicate_records"], 1)

    def test_empty_list_and_count_are_not_marked_unverified_by_quality(self):
        reports = [
            collect_operation(
                Client({"service-account-api-tokens": [ok([])]}), "service-account-api-tokens"
            ),
            collect_operation(Client({"admin-api-key-count": [ok(4)]}), "admin-api-key-count"),
        ]
        for report in reports:
            self.assertEqual(report["coverage"], "complete")
            self.assertEqual(report["record_quality"]["assessed_records"], 0)

    def test_identity_state_does_not_cross_target_boundaries(self):
        for user in ("one", "two"):
            report = collect_operation(
                Client({"user-api-tokens": [ok([{"id": "shared"}])]}),
                "user-api-tokens",
                identifier=user,
            )
            self.assertEqual(report["coverage"], "complete")
            self.assertEqual(report["record_quality"]["duplicate_records"], 0)

    def test_unknown_list_identity_is_reported_without_dropping_metadata(self):
        spec = {"future-list": {"shape": "array"}}
        report = collect_operation(
            Client({"future-list": [ok([{"provider_field": 1}])]}), "future-list", specs=spec
        )
        self.assertEqual(
            (report["coverage"], report["reason"]), ("unverified", "record_identity_not_configured")
        )
        self.assertEqual(report["record_quality"]["identity_not_configured_records"], 1)
        self.assertEqual(report["pages"][0]["metadata"], [{"provider_field": 1}])

    def test_all_known_list_operations_have_identity_contracts(self):
        for specs in (READ_OPERATIONS, OPERATIONS):
            for op, spec in specs.items():
                if spec["shape"] in (
                    "array",
                    "data",
                    "array_or_data",
                    "items",
                    "values",
                    "jwks",
                    "public_key_bundle",
                ):
                    with self.subTest(operation=op):
                        self.assertTrue(spec.get("identity_fields"))

    def test_quality_in_cloud_summary_has_counts_only(self):
        pages = empty_baseline()
        pages["admin-api-keys"] = [
            ok({"data": [{"id": "private-id"}, {"id": "private-id"}], "links": {"next": None}})
        ]
        result = collect_discovery(Client(pages))
        summary = discovery_summary(result)
        self.assertEqual(
            summary["operations"]["admin-api-keys"]["record_quality"]["duplicate_records"], 1
        )
        self.assertNotIn("private-id", json.dumps(summary))

    def test_quality_in_bitbucket_summary_controls_run_status_without_values(self):
        pages = bitbucket_empty()
        pages["workspace-members"] = [
            ok({"values": [{"user": {"uuid": "person-1"}}, {"user": {"uuid": "person-1"}}]})
        ]
        pages["user-profile"] = [ok({})]
        pages["user-ssh-keys"] = [ok({"values": []})]
        pages["user-gpg-keys"] = [ok({"values": []})]
        result = collect_bitbucket(BitbucketClient(pages))
        summary = safe_summary(result)
        self.assertEqual(result["run_status"], "unverified")
        self.assertEqual(
            summary["operations"]["workspace-members"]["record_quality"]["duplicate_records"], 1
        )
        self.assertNotIn("person-1", json.dumps(summary))

    def test_quality_does_not_merge_integer_and_string_ids_or_modify_input(self):
        rows = [{"id": 1}, {"id": "1"}]
        original = deepcopy(rows)
        quality = RecordQuality(("id",))
        quality.observe(rows)
        self.assertEqual(quality.counts["unique_identities"], 2)
        self.assertIsNone(quality.reason())
        self.assertEqual(rows, original)

    def test_nested_ids_and_fallback_keep_field_provenance(self):
        self.assertEqual(
            record_identity({"user": {"uuid": "member"}}, ("user.uuid",)),
            {"field": "user.uuid", "value": "member"},
        )
        self.assertEqual(
            record_identity({"id": "account"}, ("atlassianId", "id")),
            {"field": "id", "value": "account"},
        )

    def test_record_limit_keeps_primary_partial_reason_and_counts_only_saved_rows(self):
        report = collect_operation(
            Client(
                {
                    "service-account-api-tokens": [
                        ok([{"id": "same"}, {"id": "same"}, {"id": "lost"}])
                    ]
                },
                max_records=2,
            ),
            "service-account-api-tokens",
        )
        self.assertEqual((report["coverage"], report["reason"]), ("partial", "record_limit"))
        self.assertEqual(report["record_quality"]["assessed_records"], 2)
        self.assertEqual(report["record_quality"]["duplicate_records"], 1)


class GpgIdentityTests(unittest.TestCase):
    def test_user_and_workspace_gpg_use_fingerprint_for_collection_and_comparison(self):
        for op in ("user-gpg-keys", "workspace-gpg-key"):
            with self.subTest(operation=op):
                rows = [{"fingerprint": "PUBLIC-FINGERPRINT", "expires_on": None}]
                report = collect_operation(
                    BitbucketClient({op: [ok({"values": rows})]}), op, specs=OPERATIONS
                )
                self.assertEqual(report["coverage"], "complete")
                self.assertEqual(report["record_quality"]["unique_identities"], 1)
                before = snapshot(
                    [report], environment="bitbucket_cloud", kind="bitbucket_metadata_discovery"
                )
                after = snapshot(
                    [deepcopy(report)],
                    day=21,
                    environment="bitbucket_cloud",
                    kind="bitbucket_metadata_discovery",
                )
                after["collections"][0]["pages"][0]["metadata"]["values"][0]["expires_on"] = (
                    "2026-10-01"
                )
                result = compare_snapshots(before, after)
                self.assertEqual(result["counts"]["metadata_changed"], 1)
                self.assertEqual(events(result)[0]["identity"]["field"], "fingerprint")
                self.assertEqual(events(result)[0]["changed_paths"], ["/expires_on"])

    def test_gpg_key_id_does_not_replace_missing_full_fingerprint(self):
        report = collect_operation(
            BitbucketClient({"user-gpg-keys": [ok({"values": [{"key_id": "short-key"}]})]}),
            "user-gpg-keys",
            specs=OPERATIONS,
        )
        self.assertEqual(
            (report["coverage"], report["reason"]), ("unverified", "unidentifiable_records")
        )


if __name__ == "__main__":
    unittest.main()
