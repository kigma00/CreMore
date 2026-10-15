"""Branch rules are context metadata, not an inventory of every access token."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from cremore_atlassian_provider.metadata.bitbucket import (
    BRANCH_OPERATIONS,
    BitbucketClient,
    collect_bitbucket,
    main,
    safe_summary,
)
from cremore_atlassian_provider.metadata.qa.bitbucket_connection import save_connection

from . import posix_native_io
from .test_bitbucket import SECRET
from .test_discovery import Response


def rule(identifier):
    return {
        "type": "branchrestriction",
        "id": identifier,
        "kind": "push",
        "pattern": "lab/*",
        "users": [],
        "groups": [],
        "future": {"nullable": None},
        "access_tokens": [
            {
                "id": "synthetic-token-id",
                "name": "synthetic name",
                "secret": "SYNTHETIC_TOKEN_SECRET",
            }
        ],
    }


class BranchRestrictionTests(unittest.TestCase):
    def test_paginated_rules_and_observed_details_preserve_metadata_and_exclude_secret(self):
        first, second = rule(1), rule(2)
        nxt = "https://api.bitbucket.org/2.0/repositories/lab/repo/branch-restrictions?pagelen=1&page=2"
        opener = Mock()
        opener.open.side_effect = [
            Response(b)
            for b in (
                {"values": [{"slug": "repo", "uuid": "repo-id"}]},
                {"values": [first], "size": 2, "next": nxt},
                {"values": [second], "size": 2},
                first,
                second,
            )
        ]
        result = collect_bitbucket(
            BitbucketClient("lab", SECRET, page_size=1, opener=opener),
            branch_restrictions_only=True,
        )
        summary = safe_summary(result)
        self.assertEqual((result["run_status"], summary["request_count"]), ("complete", 5))
        self.assertEqual(summary["collection_mode"], "branch_restrictions")
        self.assertEqual(set(summary["operations"]), {"repositories"} | set(BRANCH_OPERATIONS))
        requests = [c.args[0] for c in opener.open.call_args_list]
        self.assertEqual(requests[2].full_url, nxt)
        self.assertTrue(requests[-1].full_url.endswith("/repo/branch-restrictions/2"))
        self.assertTrue(all(r.get_method() == "GET" and r.data is None for r in requests))
        self.assertIn("synthetic-token-id", json.dumps(result))
        self.assertNotIn("SYNTHETIC_TOKEN_SECRET", json.dumps(result))
        self.assertNotIn("synthetic-token-id", json.dumps(summary))
        self.assertIn("resource-access-tokens", result["public_listing_contract_unverified"])

    def test_empty_rules_are_success_not_positive_token_evidence(self):
        opener = Mock()
        opener.open.side_effect = [
            Response({"values": [{"slug": "repo", "uuid": "repo-id"}]}),
            Response({"values": [], "size": 0}),
        ]
        result = collect_bitbucket(
            BitbucketClient("lab", SECRET, opener=opener), branch_restrictions_only=True
        )
        self.assertEqual(result["run_status"], "complete")
        self.assertIn("repository-branch-restriction-detail", result["not_requested_operations"])
        self.assertFalse(result["inventory_complete"])
        self.assertEqual(opener.open.call_count, 2)

    def test_detail_budget_and_identifiers_and_conflicting_modes(self):
        opener = Mock()
        opener.open.side_effect = [
            Response({"values": [{"slug": "repo"}]}),
            Response({"values": [rule(1), rule(1), rule("../bad"), rule(2)]}),
            Response(rule(1)),
        ]
        client = BitbucketClient("lab", SECRET, opener=opener)
        result = collect_bitbucket(client, max_targets=1, branch_restrictions_only=True)
        self.assertEqual(result["run_status"], "unverified")
        self.assertEqual(
            (result["invalid_identifiers"], result["key_details_omitted_by_limit"]), (1, 1)
        )
        self.assertEqual(opener.open.call_count, 3)
        for kwargs in (
            {"branch_restrictions_only": "yes"},
            {"branch_restrictions_only": True, "runners_only": True},
        ):
            with self.assertRaises(ValueError):
                collect_bitbucket(client, **kwargs)
        self.assertEqual(opener.open.call_count, 3)

    @posix_native_io
    def test_cli_explicit_mode_and_output(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            directory.chmod(0o700)
            save_connection(directory, "lab", "lab", SECRET)
            opener = Mock()
            opener.open.return_value = Response({"values": []})
            out = io.StringIO()
            with (
                patch(
                    "cremore_atlassian_provider.metadata.http.urllib.request.build_opener",
                    return_value=opener,
                ),
                redirect_stdout(out),
            ):
                code = main(["--profile", "lab", "--branch-restrictions-only"], directory=directory)
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.getvalue())["collection_mode"], "branch_restrictions")
            self.assertEqual(next(directory.glob("inventory-*.json")).stat().st_mode & 0o777, 0o600)
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(
                    ["--profile", "lab", "--runners-only", "--branch-restrictions-only"],
                    directory=directory,
                )
