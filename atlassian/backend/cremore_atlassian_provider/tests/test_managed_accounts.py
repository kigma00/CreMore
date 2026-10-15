"""Managed-account reads, connection isolation, and documented reason metadata."""

import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from cremore_atlassian_provider.metadata.discovery import collect_accounts, discovery_summary
from cremore_atlassian_provider.metadata.http import CloudClient, FetchResult, Limits
from cremore_atlassian_provider.metadata.read_operations import (
    ACCOUNT_DETAIL_OPERATIONS,
    MANAGEMENT_REASON_CODES,
)
from cremore_atlassian_provider.metadata.snapshot import REDACTED, metadata_snapshot

from . import posix_native_io
from . import test_collector_cli as cli_helpers
from . import test_discovery as helpers


def details():
    return {
        operation: [helpers.ok([] if operation == "user-api-tokens" else {})]
        for operation in ACCOUNT_DETAIL_OPERATIONS
    }


class AccountCollectionTests(unittest.TestCase):
    def test_only_managed_account_ids_are_deduplicated_and_bounded(self):
        pages = details()
        pages["managed-accounts"] = [
            helpers.ok(
                {
                    "data": [
                        {"account_id": "person-b", "createdBy": {"id": "outside-user"}},
                        {"account_id": "person-a"},
                        {"account_id": "person-a"},
                        {"account_id": "../invalid"},
                        {"name": "missing-id"},
                        None,
                    ],
                    "links": {},
                }
            )
        ]
        client = helpers.Client(pages)
        result = collect_accounts(client, max_targets=1)
        self.assertEqual(result["target_discovery"]["user_ids"], ["person-a"])
        self.assertEqual(result["targets_omitted_by_limit"]["user_ids"], 1)
        self.assertEqual(result["target_discovery"]["invalid_identifiers"], 3)
        self.assertEqual(result["run_status"], "unverified")
        self.assertEqual([call[1]["identifier"] for call in client.calls[1:]], ["person-a"] * 3)
        for private in ("person-a", "person-b", "outside-user", helpers.ORG):
            self.assertNotIn(private, json.dumps(discovery_summary(result)))

    def test_empty_listing_and_denied_listing_are_distinct_without_followups(self):
        for response, expected in (
            (helpers.ok({"data": [], "links": {}}), "unverified"),
            (FetchResult(403, attempts=1, reason="http_403"), "failed"),
        ):
            with self.subTest(expected=expected):
                client = helpers.Client({"managed-accounts": [response]})
                result = collect_accounts(client)
                self.assertEqual(len(client.calls), 1)
                self.assertEqual(result["run_status"], expected)
                self.assertEqual(
                    result["not_requested_no_observed_targets"], list(ACCOUNT_DETAIL_OPERATIONS)
                )

    def test_partial_listing_keeps_observed_accounts_and_reports_failure(self):
        pages = details()
        pages["managed-accounts"] = [
            helpers.ok({"data": [{"account_id": "person"}], "links": {"next": "?cursor=next"}}),
            FetchResult(403, attempts=1, reason="http_403"),
        ]
        result = collect_accounts(helpers.Client(pages))
        self.assertEqual(result["run_status"], "partial")
        self.assertEqual(result["collections"][0]["saved_records"], 1)
        self.assertEqual(len(result["collections"]), 4)
        self.assertFalse(result["inventory_complete"])

    def test_global_request_budget_applies_to_all_account_detail_reads(self):
        opener = Mock()
        opener.open.side_effect = [
            helpers.Response({"data": [{"account_id": "person"}], "links": {}}),
            helpers.Response({"profile.read": {"allowed": True}}),
        ]
        client = CloudClient(
            helpers.ORG, helpers.SECRET, Limits(max_requests=2, retries=0), opener=opener
        )
        result = collect_accounts(client)
        self.assertEqual(opener.open.call_count, 2)
        self.assertEqual(discovery_summary(result)["request_count"], 2)
        self.assertEqual(result["run_status"], "partial")
        self.assertEqual([r["reason"] for r in result["collections"][2:]], ["request_limit"] * 2)

    def test_invalid_target_limit_does_not_request(self):
        for limit in (0, 501, True):
            client = helpers.Client({})
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                collect_accounts(client, max_targets=limit)
            self.assertEqual(client.calls, [])


class AccountCliTests(unittest.TestCase):
    @posix_native_io
    def test_separate_profile_runs_only_four_gets_and_saves_private_metadata(self):
        runner = cli_helpers.CliTests()
        account_key = "SYNTHETIC_ACCOUNT_CONNECTION"
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            runner.connection(directory)
            config = directory / "connection-lab-accounts.json"
            config.write_text(json.dumps({"org_id": helpers.ORG, "api_key": account_key}))
            config.chmod(0o600)
            response = cli_helpers.Response
            code, output, opener = runner.invoke(
                directory,
                [
                    response(
                        {"data": [{"account_id": "person", "email": cli_helpers.PII}], "links": {}}
                    ),
                    response({"profile.read": {"allowed": True}}),
                    response(
                        {
                            "account": {
                                "account_id": "person",
                                "email": cli_helpers.PII,
                                "secret": account_key,
                            }
                        }
                    ),
                    response(
                        [
                            {
                                "id": "token-id",
                                "createdBy": "person",
                                "disabledStatus": False,
                                "products": ["jira"],
                                "future": {"nullable": None},
                            }
                        ]
                    ),
                ],
                ["--profile", "lab-accounts", "--accounts"],
            )
            self.assertEqual(code, 0)
            summary = json.loads(output)
            self.assertEqual(summary["report_type"], "managed_account_metadata_discovery")
            self.assertEqual(summary["request_count"], 4)
            self.assertEqual(
                set(summary["operations"]), {"managed-accounts", *ACCOUNT_DETAIL_OPERATIONS}
            )
            for call in opener.open.call_args_list:
                request = call.args[0]
                self.assertEqual(request.get_method(), "GET")
                self.assertEqual(request.get_header("Authorization"), "Bearer " + account_key)
                self.assertNotIn("/admin/api-access/", request.full_url)
            for private in (cli_helpers.PII, "token-id", account_key, cli_helpers.KEY, helpers.ORG):
                self.assertNotIn(private, output)
            path = next(directory.glob("inventory-*.json"))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            artifact = path.read_text()
            self.assertNotIn(account_key, artifact)
            self.assertIn(cli_helpers.PII, artifact)
            result = json.loads(artifact)
            token = result["collections"][-1]["pages"][0]["metadata"][0]
            self.assertEqual(token["future"], {"nullable": None})
            self.assertIs(token["disabledStatus"], False)
            self.assertEqual(result["connection_profile"], "lab-accounts")

    def test_missing_explicit_profile_or_conflicting_modes_make_no_requests(self):
        runner = cli_helpers.CliTests()
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            runner.connection(directory)
            for args in (
                ["--accounts"],
                ["--profile", "absent", "--accounts"],
                ["--profile", "lab", "--accounts", "--discovery"],
                ["--profile", "lab", "--accounts", "--sources", "org-api-tokens"],
            ):
                with self.subTest(args=args):
                    code, _, opener = runner.invoke(directory, [], args)
                    self.assertEqual(code, 2)
                    opener.open.assert_not_called()
            self.assertEqual(list(directory.glob("inventory-*.json")), [])


class ManagementReasonTests(unittest.TestCase):
    def test_only_documented_reason_codes_survive_and_auth_redaction_wins(self):
        client = CloudClient(helpers.ORG, helpers.SECRET)
        for reason in MANAGEMENT_REASON_CODES:
            body = {"profile.read": {"allowed": False, "reason": {"key": reason}}}
            saved, stats = client.snapshot(body)
            self.assertEqual(saved, body)
            self.assertEqual(sum(stats.values()), 0)
        body = {
            "reason": {"key": "UNDOCUMENTED_VALUE"},
            "key": "managedAccount",
            "other": {"key": "myselfOnly"},
        }
        saved, stats = client.snapshot(body)
        self.assertEqual(stats["secret_fields_omitted"], 3)
        self.assertEqual(saved["reason"]["key"], REDACTED)
        saved, _ = metadata_snapshot({"reason": {"key": "managedAccount"}})
        self.assertEqual(saved["reason"]["key"], REDACTED)
        client = CloudClient(helpers.ORG, "managedAccount")
        saved, stats = client.snapshot({"reason": {"key": "managedAccount"}})
        self.assertEqual(saved["reason"]["key"], REDACTED)
        self.assertEqual(stats["sensitive_values_omitted"], 1)


if __name__ == "__main__":
    unittest.main()
