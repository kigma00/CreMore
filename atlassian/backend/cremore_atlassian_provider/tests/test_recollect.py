"""Explicit failed-read recovery without saved URL replay or scope changes."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from copy import deepcopy
from pathlib import Path
from unittest.mock import Mock, patch

from cremore_atlassian_provider.metadata import recollect
from cremore_atlassian_provider.metadata.bitbucket import BitbucketClient
from cremore_atlassian_provider.metadata.http import Limits

from . import posix_native_io
from .test_collector_cli import KEY, ORG, Response
from .test_compare import collection, snapshot
from .test_jobs import factory, page


def source(*reports, bitbucket=False, mode="core"):
    value = snapshot(list(reports))
    value["queried_org_id"] = ORG
    if bitbucket:
        value.update(
            report_type="bitbucket_metadata_discovery",
            environment="bitbucket_cloud",
            workspace="lab",
            collection_mode=mode,
        )
    return value


def failed(operation="admin-api-keys", target=None, coverage="failed"):
    result = collection([], operation=operation, coverage=coverage, target=target)
    result["pages"] = []
    return result


class RecollectionTests(unittest.TestCase):
    def test_plan_defaults_to_failed_partial_and_explicitly_opts_into_unverified(self):
        value = source(
            failed(),
            failed("org-api-tokens", coverage="partial"),
            failed("org-oauth-clients", coverage="unverified"),
            collection([]),
        )
        before = deepcopy(value)
        plan = recollect.build_plan(value)
        self.assertEqual(plan["selected_count"], 2)
        self.assertEqual(recollect.build_plan(value, include_unverified=True)["selected_count"], 3)
        self.assertEqual(
            recollect.build_plan(value, operations=["org-api-tokens"])["selected_count"], 1
        )
        self.assertEqual(value, before)

    @posix_native_io
    def test_saved_links_and_cursor_are_never_used_for_new_requests(self):
        report = failed(coverage="partial")
        report["pages"] = [
            {
                "metadata": {
                    "data": [{"id": "old"}],
                    "links": {"next": "https://example.invalid/OLD_CURSOR"},
                }
            }
        ]
        value = source(report)
        plan = recollect.build_plan(value)
        self.assertNotIn("OLD_CURSOR", json.dumps(plan))
        clients = []
        with tempfile.TemporaryDirectory() as tmp:
            result, filename = recollect.execute_plan(
                plan,
                Path(tmp),
                Limits(retries=0),
                input_sha256="digest",
                client_factory=factory([[Response(page())]], clients),
            )
            self.assertEqual(result["run_status"], "complete")
            self.assertEqual(result["input_sha256"], "digest")
            url = clients[0]._opener.open.call_args.args[0].full_url
            self.assertNotIn("OLD_CURSOR", url)
            self.assertNotIn("cursor=", url)
            self.assertEqual(json.loads((Path(tmp) / filename).read_text()), result)
            self.assertFalse(result["inventory_complete"])

    def test_invalid_target_write_method_duplicate_and_over_limit_plan_rejected(self):
        cases = [
            source(failed("user-profile", target="../outside")),
            source(dict(failed(), method="DELETE")),
            source(failed("delete-key")),
            source(failed(), failed()),
        ]
        for value in cases:
            with self.subTest(value=value), self.assertRaises((ValueError, KeyError)):
                recollect.build_plan(value)
        with self.assertRaises(ValueError):
            recollect.build_plan(source(failed(), failed("org-api-tokens")), max_tasks=1)

    def test_source_mode_rejects_unrelated_reads(self):
        value = source(failed("admin-api-keys"))
        value["report_type"] = "managed_account_metadata_discovery"
        with self.assertRaises(ValueError):
            recollect.build_plan(value)
        with self.assertRaises(ValueError):
            recollect.build_plan(
                source(failed("user-ssh-keys", target="user"), bitbucket=True, mode="runners")
            )

    @posix_native_io
    def test_count_post_retains_only_validated_account_ids(self):
        report = dict(
            failed("service-account-token-counts"),
            method="POST",
            requested_account_ids=["account-a"],
        )
        plan = recollect.build_plan(source(report))
        clients = []
        body = {
            "validServiceAccountIds": [{"serviceAccountId": "account-a", "credentialsCount": 1}],
            "invalidServiceAccountIds": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            recollect.execute_plan(
                plan, Path(tmp), client_factory=factory([[Response(body)]], clients)
            )
        request = clients[0]._opener.open.call_args.args[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(json.loads(request.data), ["account-a"])
        for bad in (None, [], ["same", "same"], ["../bad"]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                recollect.build_plan(source(dict(report, requested_account_ids=bad)))

    @posix_native_io
    def test_repository_runner_refreshes_uuid_mapping_then_follows_fresh_next(self):
        plan = recollect.build_plan(
            source(failed("repository-runners", target="repo"), bitbucket=True, mode="runners")
        )
        self.assertEqual(
            [task["operation"] for task in plan["tasks"]], ["repositories", "repository-runners"]
        )
        workspace = "{00000000-0000-0000-0000-000000000001}"
        repository = "{00000000-0000-0000-0000-000000000002}"
        nxt = (
            "https://api.bitbucket.org/internal/repositories/"
            + workspace
            + "/"
            + repository
            + "/pipelines-config/runners?page=2"
        )
        opener = Mock()
        opener.open.side_effect = [
            Response(
                {
                    "values": [
                        {
                            "slug": "repo",
                            "uuid": repository,
                            "workspace": {"slug": "lab", "uuid": workspace},
                        }
                    ]
                }
            ),
            Response({"values": [{"uuid": "runner-one"}], "size": 2, "next": nxt}),
            Response({"values": [{"uuid": "runner-two"}], "size": 2}),
        ]

        def create(job, directory, limits):
            return BitbucketClient("lab", KEY, limits, opener=opener)

        with tempfile.TemporaryDirectory() as tmp:
            result, _ = recollect.execute_plan(plan, Path(tmp), client_factory=create)
        self.assertEqual((result["run_status"], result["requests"]), ("complete", 3))
        self.assertEqual(opener.open.call_args_list[-1].args[0].full_url, nxt)
        self.assertEqual(result["collections"][-1]["saved_records"], 2)

    def test_selected_repository_read_is_a_single_fresh_prerequisite(self):
        plan = recollect.build_plan(
            source(
                failed("repository-runners", target="repo"),
                failed("repositories"),
                bitbucket=True,
                mode="runners",
            )
        )
        self.assertEqual(
            [task["operation"] for task in plan["tasks"]], ["repositories", "repository-runners"]
        )
        self.assertEqual(plan["prerequisite_count"], 0)

    def test_both_runner_lists_share_repository_prerequisite_without_extra_scope(self):
        plan = recollect.build_plan(
            source(
                failed("workspace-runners"),
                failed("repository-runners", target="repo"),
                bitbucket=True,
                mode="runners",
            )
        )
        self.assertEqual(
            [task["operation"] for task in plan["tasks"]],
            ["repositories", "workspace-runners", "repository-runners"],
        )
        self.assertEqual(plan["prerequisite_count"], 1)

    @posix_native_io
    def test_request_budget_applies_to_all_selected_reads(self):
        plan = recollect.build_plan(source(failed(), failed("org-api-tokens")))
        clients = []
        with tempfile.TemporaryDirectory() as tmp:
            result, _ = recollect.execute_plan(
                plan,
                Path(tmp),
                Limits(max_requests=1, retries=0),
                client_factory=factory([[Response(page())]], clients),
            )
        self.assertEqual(result["requests"], 1)
        self.assertEqual(result["collections"][1]["reason"], "request_limit")
        self.assertEqual(result["run_status"], "partial")

    @posix_native_io
    def test_next_recollection_selects_only_still_failed_reads(self):
        plan = recollect.build_plan(source(failed(), failed("org-api-tokens")))
        with tempfile.TemporaryDirectory() as tmp:
            result, _ = recollect.execute_plan(
                plan,
                Path(tmp),
                Limits(retries=0),
                client_factory=factory([[Response(page()), Response({}, 403)]]),
            )
            next_plan = recollect.build_plan(result)
        self.assertEqual(next_plan["selected_count"], 1)
        self.assertEqual(next_plan["tasks"][0]["operation"], "org-api-tokens")

    @posix_native_io
    def test_interruption_preserves_completed_results_and_can_plan_pending_tasks(self):
        plan = recollect.build_plan(
            source(failed(), failed("org-api-tokens"), failed("service-accounts"))
        )
        with tempfile.TemporaryDirectory() as tmp:
            result, _ = recollect.execute_plan(
                plan, Path(tmp), client_factory=factory([[Response(page()), KeyboardInterrupt()]])
            )
            self.assertEqual(result["run_status"], "interrupted")
            self.assertEqual(len(result["collections"]), 1)
            next_plan = recollect.build_plan(result)
            self.assertEqual(
                {task["operation"] for task in next_plan["tasks"]},
                {"org-api-tokens", "service-accounts"},
            )
            initial = next(
                value
                for file in Path(tmp).glob("recollection-*")
                for value in [json.loads(file.read_text())]
                if value.get("report_type") == "metadata_recollection"
                and not value["collections"]
                and not value.get("collection_refs")
            )
            self.assertEqual(recollect.build_plan(initial)["selected_count"], 3)

    @posix_native_io
    def test_inconsistent_checkpoint_task_link_is_rejected(self):
        plan = recollect.build_plan(source(failed()))
        with tempfile.TemporaryDirectory() as tmp:
            result, _ = recollect.execute_plan(
                plan, Path(tmp), client_factory=factory([[Response(page())]])
            )
        result["collections"][0]["operation"] = "org-api-tokens"
        with self.assertRaises(ValueError):
            recollect.build_plan(result)

    @posix_native_io
    def test_legacy_inventory_source_creates_separate_broad_recollection_report(self):
        value = source()
        value.pop("report_type")
        value["schema_version"] = 3
        value["collections"] = {"admin-api-keys": {"coverage": "failed"}}
        plan = recollect.build_plan(value)
        with tempfile.TemporaryDirectory() as tmp:
            result, _ = recollect.execute_plan(
                plan, Path(tmp), client_factory=factory([[Response(page())]])
            )
        self.assertEqual(result["report_type"], "metadata_recollection")
        self.assertEqual(result["source_scope"]["report_type"], "inventory")
        self.assertIsInstance(result["collections"], list)

    @posix_native_io
    def test_cli_dry_run_and_no_failures_do_not_load_auth_or_write_results(self):
        for report, option in ((failed(), ["--dry-run"]), (collection([]), [])):
            with tempfile.TemporaryDirectory() as tmp:
                file = Path(tmp) / "source.json"
                file.write_text(json.dumps(source(report)))
                out = io.StringIO()
                with patch.object(recollect, "create_client") as create, redirect_stdout(out):
                    code = recollect.main(["--input", str(file)] + option, directory=Path(tmp))
                self.assertEqual(code, 0)
                create.assert_not_called()
                self.assertNotIn(ORG, out.getvalue())
                self.assertEqual(len(list(Path(tmp).iterdir())), 1)

    @posix_native_io
    def test_cli_success_keeps_original_file_and_safe_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            file = directory / "source.json"
            file.write_text(json.dumps(source(failed())))
            original = file.read_bytes()
            out = io.StringIO()
            with (
                patch.object(recollect, "create_client", side_effect=factory([[Response(page())]])),
                redirect_stdout(out),
            ):
                code = recollect.main(["--input", str(file)], directory=directory)
            self.assertEqual(code, 0)
            self.assertEqual(file.read_bytes(), original)
            for private in (ORG, KEY, "private-person@example.invalid"):
                self.assertNotIn(private, out.getvalue())
            self.assertTrue(json.loads(out.getvalue())["output_file"].startswith("recollection-"))

    @posix_native_io
    def test_reference_checkpoints_resume_without_copying_response_bodies(self):
        plan = recollect.build_plan(source(failed(), failed("org-api-tokens")))
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            large = page()
            large["data"][0]["future_metadata"] = "x" * 20000
            result, _ = recollect.execute_plan(
                plan, directory, client_factory=factory([[Response(large), KeyboardInterrupt()]])
            )
            checkpoint = next(
                value
                for file in directory.glob("recollection-*.json")
                for value in [json.loads(file.read_text())]
                if value.get("checkpoint_kind") == "references" and value["collection_refs"]
            )
            self.assertLess(len(json.dumps(checkpoint)), 10000)
            self.assertNotIn("future_metadata", json.dumps(checkpoint))
            resumed = recollect.build_plan(checkpoint, directory=directory)
            self.assertEqual([task["operation"] for task in resumed["tasks"]], ["org-api-tokens"])
            self.assertEqual(
                result["collections"][0]["pages"][0]["metadata"]["data"][0]["future_metadata"],
                "x" * 20000,
            )

    @posix_native_io
    def test_modified_or_outside_reference_is_rejected_before_planning_requests(self):
        plan = recollect.build_plan(source(failed(), failed("org-api-tokens")))
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            recollect.execute_plan(
                plan, directory, client_factory=factory([[Response(page()), KeyboardInterrupt()]])
            )
            checkpoint = next(
                value
                for file in directory.glob("recollection-*.json")
                for value in [json.loads(file.read_text())]
                if value.get("checkpoint_kind") == "references" and value["collection_refs"]
            )
            invalid = deepcopy(checkpoint)
            invalid["collection_refs"][0]["file"] = "../connection-lab.json"
            with self.assertRaises(ValueError):
                recollect.build_plan(invalid, directory=directory)
            (directory / checkpoint["collection_refs"][0]["file"]).write_text("{}")
            with self.assertRaises(ValueError):
                recollect.build_plan(checkpoint, directory=directory)

    @posix_native_io
    def test_cross_run_part_is_rejected_even_with_updated_hash(self):
        plan = recollect.build_plan(source(failed(), failed("org-api-tokens")))
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            recollect.execute_plan(
                plan, directory, client_factory=factory([[Response(page()), KeyboardInterrupt()]])
            )
            checkpoint = next(
                value
                for file in directory.glob("recollection-*.json")
                for value in [json.loads(file.read_text())]
                if value.get("checkpoint_kind") == "references" and value["collection_refs"]
            )
            reference = checkpoint["collection_refs"][0]
            file = directory / reference["file"]
            part = json.loads(file.read_text())
            part["run_id"] = "other-run"
            file.write_text(json.dumps(part))
            reference["sha256"] = recollect.output_digest(directory, file.name)
            with self.assertRaises(ValueError):
                recollect.build_plan(checkpoint, directory=directory)


if __name__ == "__main__":
    unittest.main()
