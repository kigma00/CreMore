"""Runner credentials are read as metadata within the selected workspace."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from cremore_atlassian_provider.metadata.bitbucket import (
    BRANCH_OPERATIONS,
    CORE_OPERATIONS,
    OPERATIONS,
    RUNNER_OPERATIONS,
    BitbucketClient,
    collect_bitbucket,
    main,
    safe_summary,
)
from cremore_atlassian_provider.metadata.discovery import collect_operation
from cremore_atlassian_provider.metadata.http import FetchResult, Limits
from cremore_atlassian_provider.metadata.qa.bitbucket_connection import save_connection

from . import posix_native_io
from .test_bitbucket import SECRET, Client, ok, with_user
from .test_discovery import Response


def runner(identifier):
    return {
        "uuid": identifier,
        "name": "private runner name",
        "labels": ["self.hosted"],
        "state": {"status": "UNREGISTERED"},
        "future": {"nullable": None},
        "oauth_client": {
            "id": "private-client-id",
            "audience": "runner",
            "token_endpoint": "https://example.invalid/no-request",
            "secret": "SYNTHETIC_RUNNER_SECRET",
        },
    }


class RunnerTests(unittest.TestCase):
    def test_missing_next_with_uncollected_size_is_partial_and_preserves_metadata(self):
        report = collect_operation(
            Client({"workspace-runners": [ok({"values": [runner("one")], "size": 2})]}),
            "workspace-runners",
            specs=OPERATIONS,
        )
        self.assertEqual(
            (report["coverage"], report["reason"]), ("partial", "pagination_size_mismatch")
        )
        self.assertEqual((report["saved_records"], report["requests"]), (1, 1))
        self.assertEqual(report["pages"][0]["metadata"]["size"], 2)

    def test_invalid_or_changing_sizes_do_not_claim_complete(self):
        for size in (True, -1, "2", None):
            with self.subTest(size=size):
                report = collect_operation(
                    Client({"workspace-runners": [ok({"values": [], "size": size})]}),
                    "workspace-runners",
                    specs=OPERATIONS,
                )
                self.assertEqual(
                    (report["coverage"], report["reason"]),
                    ("unverified", "invalid_pagination_size"),
                )
        client = Client(
            {
                "workspace-runners": [
                    ok({"values": [runner("one")], "size": 2, "next": "?page=2"}),
                    ok({"values": [runner("two")], "size": 3}),
                ]
            }
        )
        report = collect_operation(client, "workspace-runners", specs=OPERATIONS)
        self.assertEqual(
            (report["coverage"], report["reason"]), ("partial", "pagination_size_changed")
        )
        self.assertEqual(report["saved_records"], 2)

    def test_consistent_or_absent_optional_size_completes_without_extra_requests(self):
        cases = [
            ([{"values": [], "size": 0}], 0),
            ([{"values": [runner("one")]}], 1),
            (
                [
                    {"values": [runner("one")], "size": 2, "next": "?page=2"},
                    {"values": [runner("two")]},
                ],
                2,
            ),
        ]
        for pages, count in cases:
            with self.subTest(count=count):
                report = collect_operation(
                    Client({"workspace-runners": [ok(p) for p in pages]}),
                    "workspace-runners",
                    specs=OPERATIONS,
                )
                self.assertEqual(
                    (report["coverage"], report["saved_records"], report["requests"]),
                    ("complete", count, len(pages)),
                )
        report = collect_operation(
            Client({"workspace-runners": [ok({"values": [runner("one")], "size": 0})]}),
            "workspace-runners",
            specs=OPERATIONS,
        )
        self.assertEqual(
            (report["coverage"], report["reason"]), ("partial", "pagination_size_mismatch")
        )

    def test_internal_next_link_stays_partial_with_explicit_reason_and_no_second_request(self):
        # Observed public Runner API response shape, with synthetic identifiers.
        nxt = "https://api.bitbucket.org/internal/workspaces/%7Bsynthetic-workspace%7D/pipelines-config/runners?page=2&pagelen=1"
        opener = Mock()
        opener.open.return_value = Response(
            {"values": [runner("one")], "page": 1, "pagelen": 1, "size": 2, "next": nxt}
        )
        report = collect_operation(
            BitbucketClient("lab", SECRET, page_size=1, opener=opener),
            "workspace-runners",
            specs=OPERATIONS,
        )
        self.assertEqual(
            (report["coverage"], report["reason"]),
            ("partial", "pagination_target_outside_resource"),
        )
        self.assertEqual(
            (report["requests"], report["saved_records"], report["last_http_status"]), (1, 1, 200)
        )
        self.assertEqual(report["pages"][0]["metadata"]["next"], nxt)
        self.assertNotIn("SYNTHETIC_RUNNER_SECRET", json.dumps(report))
        self.assertEqual(opener.open.call_count, 1)

    def test_real_transport_follows_next_and_reads_both_scopes_without_other_operations(self):
        first, second = runner("{workspace-one}"), runner("{workspace-two}")
        third = runner("{repo-one}")
        next_url = (
            "https://api.bitbucket.org/2.0/workspaces/lab/pipelines-config/runners?pagelen=1&page=2"
        )
        opener = Mock()
        opener.open.side_effect = [
            Response(body)
            for body in (
                {"values": [{"slug": "repo", "uuid": "repo-id"}]},
                {"values": [first], "next": next_url},
                {"values": [second]},
                first,
                second,
                {"values": [third]},
                third,
            )
        ]
        result = collect_bitbucket(
            BitbucketClient("lab", SECRET, page_size=1, opener=opener), runners_only=True
        )
        summary = safe_summary(result)
        self.assertEqual((result["run_status"], summary["request_count"]), ("complete", 7))
        self.assertEqual(summary["not_requested_operations"], [])
        self.assertEqual(set(summary["operations"]), set(RUNNER_OPERATIONS) | {"repositories"})
        self.assertEqual(
            set(summary["not_requested_by_mode"]),
            (set(CORE_OPERATIONS) - {"repositories"}) | set(BRANCH_OPERATIONS),
        )
        reqs = [call.args[0] for call in opener.open.call_args_list]
        self.assertTrue(
            all(
                req.get_method() == "GET" and req.get_header("Authorization") == "Bearer " + SECRET
                for req in reqs
            )
        )
        self.assertEqual(reqs[2].full_url, next_url)
        self.assertEqual(parse_qs(urlsplit(reqs[0].full_url).query), {"pagelen": ["1"]})
        self.assertTrue(
            reqs[3].full_url.endswith(
                "/workspaces/lab/pipelines-config/runners/%7Bworkspace-one%7D"
            )
        )
        self.assertTrue(
            reqs[6].full_url.endswith(
                "/repositories/lab/repo/pipelines-config/runners/%7Brepo-one%7D"
            )
        )
        text = json.dumps(result)
        self.assertNotIn("SYNTHETIC_RUNNER_SECRET", text)
        self.assertIn("private-client-id", text)
        self.assertIn("nullable", text)
        for private in ("private runner name", "private-client-id", "workspace-one", SECRET):
            self.assertNotIn(private, json.dumps(summary))

    def test_detail_budget_is_shared_and_bad_identifiers_are_never_requested(self):
        client = Client(
            {
                "workspace-runners": [
                    ok({"values": [runner("w1"), runner("w1"), runner("../bad"), runner("w2")]})
                ],
                "repositories": [ok({"values": [{"slug": "repo"}, {"slug": "omitted"}]})],
                "workspace-runner-detail": [ok(runner("w1"))],
                "repository-runners": [ok({"values": [runner("r1")]})],
            }
        )
        result = collect_bitbucket(client, max_targets=1, runners_only=True)
        self.assertEqual(result["run_status"], "unverified")
        self.assertEqual(result["runner_details_omitted_by_limit"], 2)
        self.assertEqual(result["key_details_omitted_by_limit"], 0)
        self.assertEqual(result["invalid_identifiers"], 1)
        self.assertEqual(result["targets_omitted_by_limit"]["repositories"], 1)
        self.assertNotIn("repository-runner-detail", [op for op, _ in client.calls])

    def test_scope_denial_is_failed_not_empty_and_core_mode_does_not_request_runners(self):
        result = collect_bitbucket(
            Client(
                {
                    "workspace-runners": [FetchResult(403, attempts=1, reason="http_403")],
                    "repositories": [ok({"values": []})],
                }
            ),
            runners_only=True,
        )
        self.assertEqual(result["run_status"], "partial")
        failed = next(r for r in result["collections"] if r["operation"] == "workspace-runners")
        self.assertEqual(failed["coverage"], "failed")
        self.assertEqual(failed["pages"], [])
        core = Client(with_user())
        result = collect_bitbucket(core)
        self.assertFalse(set(RUNNER_OPERATIONS) & {op for op, _ in core.calls})
        self.assertEqual(
            set(result["not_requested_by_mode"]), set(RUNNER_OPERATIONS + BRANCH_OPERATIONS)
        )

    def test_request_budget_and_invalid_inputs_never_broaden_requests(self):
        opener = Mock()
        opener.open.return_value = Response({"values": [runner("one")]})
        client = BitbucketClient("lab", SECRET, Limits(max_requests=1), opener=opener)
        result = collect_bitbucket(client, runners_only=True)
        self.assertEqual(result["run_status"], "partial")
        self.assertEqual(opener.open.call_count, 1)
        for invalid in (0, 101, True, "1", 1.5):
            with self.assertRaises(ValueError):
                BitbucketClient("lab", SECRET, page_size=invalid, opener=opener)
        for op, identifier in [
            ("workspace-runner-detail", "../outside"),
            ("repository-runner-detail", ("repo", "../outside")),
        ]:
            with self.assertRaises(ValueError):
                client.read_metadata(op, identifier=identifier)
        with self.assertRaises(ValueError):
            client.read_metadata(
                "workspace-runners",
                next_url="https://api.bitbucket.org/2.0/workspaces/other/pipelines-config/runners?page=2",
            )
        with self.assertRaises(ValueError):
            collect_bitbucket(client, runners_only="yes")
        self.assertEqual(opener.open.call_count, 1)

    @posix_native_io
    def test_cli_uses_separate_profile_and_private_output_and_validates_limits(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            directory.chmod(0o700)
            save_connection(directory, "runners", "lab", SECRET)
            opener = Mock()
            opener.open.side_effect = [
                Response({"values": []}),
                Response({"values": [runner("one")]}),
                Response(runner("one")),
            ]
            out = io.StringIO()
            with (
                patch(
                    "cremore_atlassian_provider.metadata.http.urllib.request.build_opener",
                    return_value=opener,
                ),
                redirect_stdout(out),
            ):
                code = main(
                    ["--profile", "runners", "--runners-only", "--page-size", "1"],
                    directory=directory,
                )
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.getvalue())["collection_mode"], "runners")
            self.assertNotIn("private-client-id", out.getvalue())
            path = next(directory.glob("inventory-*.json"))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            saved = json.loads(path.read_text())
            self.assertEqual(saved["limits"]["page_size"], 1)
            self.assertEqual(saved["connection_profile"], "runners")
            self.assertNotIn("SYNTHETIC_RUNNER_SECRET", path.read_text())
            for value in ("0", "101"):
                with (
                    patch(
                        "cremore_atlassian_provider.metadata.http.urllib.request.build_opener"
                    ) as forbidden,
                    redirect_stderr(io.StringIO()),
                ):
                    with self.assertRaises(SystemExit) as error:
                        main(["--profile", "runners", "--page-size", value], directory=directory)
                    self.assertEqual(error.exception.code, 2)
                    forbidden.assert_not_called()


if __name__ == "__main__":
    unittest.main()
