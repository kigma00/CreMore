"""Observation changes, coverage boundaries and the offline/private CLI contract."""

import io
import json
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from cremore_atlassian_provider.metadata import compare
from cremore_atlassian_provider.metadata.metadata import group_inventory, normalize
from cremore_atlassian_provider.metadata.storage import save_private

from . import posix_native_io


def collection(rows, *, operation="org-api-tokens", coverage="complete", target=None, shape="data"):
    body = rows if shape == "array" else {shape: rows}
    result = {
        "operation": operation,
        "coverage": coverage,
        "pages": [{"http_status": 200, "metadata": body, "redactions": {"truncated_nodes": 0}}],
    }
    if target is not None:
        result["target_id"] = target
    return result


def snapshot(reports, *, day=20, environment="cloud", kind="metadata_discovery"):
    result = {
        "schema_version": 1,
        "provider": "atlassian",
        "environment": environment,
        "report_type": kind,
        "connection_profile": "lab",
        "started_at": f"2026-09-{day:02d}T00:00:00Z",
        "finished_at": f"2026-09-{day:02d}T00:01:00Z",
        "collections": reports,
    }
    if environment == "bitbucket_cloud":
        result.update(workspace="synthetic-workspace", collection_mode="core")
    else:
        result["queried_org_id"] = "synthetic-org"
    return result


def pair(before, after, **kwargs):
    return compare.compare_snapshots(snapshot(before, **kwargs), snapshot(after, day=21, **kwargs))


def events(result):
    return [event for source in result["sources"] for event in source["events"]]


class ComparisonTests(unittest.TestCase):
    def test_new_changed_missing_and_unchanged_keep_source_evidence_without_values(self):
        before = [{"id": "changed", "label": "private-old"}, {"id": "missing"}, {"id": "same"}]
        after = [{"id": "same"}, {"id": "changed", "label": "private-new"}, {"id": "new"}]
        result = pair([collection(before)], [collection(after)])
        self.assertEqual(
            result["counts"],
            {
                "first_observed": 1,
                "metadata_changed": 1,
                "not_observed": 1,
                "observation_unknown": 0,
                "metadata_unknown": 0,
                "unchanged_observations": 1,
                "sources": 1,
                "limited_sources": 0,
            },
        )
        change = next(
            event for event in events(result) if event["change_type"] == "metadata_changed"
        )
        self.assertEqual(change["changed_paths"], ["/label"])
        self.assertEqual(change["before_refs"], ["/collections/0/pages/0/metadata/data/0"])
        self.assertEqual(change["after_refs"], ["/collections/0/pages/0/metadata/data/1"])
        self.assertNotIn("private-", json.dumps(result))
        self.assertFalse(result["inventory_complete"])

    def test_no_absence_claim_on_partial_failed_unverified_or_unrequested_source(self):
        for coverage in ("partial", "failed", "unverified", "not_requested"):
            with self.subTest(coverage=coverage):
                result = pair([collection([{"id": "old"}])], [collection([], coverage=coverage)])
                self.assertEqual(events(result)[0]["change_type"], "observation_unknown")
                self.assertEqual(result["comparison_status"], "limited")

    def test_entire_missing_target_is_unknown_not_removed(self):
        previous = collection(
            [{"id": "token"}], operation="user-api-tokens", target="user-a", shape="array"
        )
        result = pair([previous], [])
        self.assertEqual(events(result)[0]["change_type"], "observation_unknown")
        self.assertEqual(result["sources"][0]["after"]["issues"], ["source_not_observed"])

    def test_missing_baseline_is_first_observed_without_creation_inference(self):
        result = pair([], [collection([{"id": "seen"}])])
        self.assertEqual(events(result)[0]["change_type"], "first_observed")
        self.assertFalse(events(result)[0]["baseline_complete"])

    def test_current_complete_source_can_lose_a_previously_observed_partial_item(self):
        result = pair([collection([{"id": "seen"}], coverage="partial")], [collection([])])
        self.assertEqual(events(result)[0]["change_type"], "not_observed")
        self.assertEqual(result["comparison_status"], "limited")

    def test_partial_source_still_compares_observed_metadata(self):
        result = pair(
            [collection([{"id": "seen", "status": "a"}])],
            [collection([{"id": "seen", "status": "b"}], coverage="partial")],
        )
        self.assertEqual(events(result)[0]["changed_paths"], ["/status"])
        self.assertEqual(result["comparison_status"], "limited")

    def test_unidentified_row_prevents_absence_claims(self):
        for bad_row in ({"label": "no-id"}, {"id": True}, {"id": ""}, {"id": None}, None):
            with self.subTest(row=bad_row):
                result = pair([collection([{"id": "old"}])], [collection([bad_row])])
                self.assertEqual(events(result)[0]["change_type"], "observation_unknown")
                self.assertEqual(result["sources"][0]["after"]["unidentified_records"], 1)

    def test_duplicate_identities_are_ambiguous_even_if_values_equal(self):
        row = {"id": "same"}
        result = pair([collection([row, row, {"id": "old"}])], [collection([row, row])])
        self.assertEqual(result["counts"]["observation_unknown"], 2)
        self.assertEqual(result["counts"]["not_observed"], 0)

    def test_identity_is_namespaced_by_operation_and_target(self):
        before, after = [], []
        for user, status in (("user-a", "a"), ("user-b", "b")):
            before.append(
                collection(
                    [{"id": "same", "status": status}],
                    operation="user-api-tokens",
                    target=user,
                    shape="array",
                )
            )
            after.append(
                collection(
                    [{"id": "same", "status": "b"}],
                    operation="user-api-tokens",
                    target=user,
                    shape="array",
                )
            )
        before.append(collection([{"id": "same"}]))
        after.append(collection([{"id": "same"}]))
        result = pair(before, after)
        self.assertEqual(result["counts"]["metadata_changed"], 1)
        self.assertEqual(result["counts"]["unchanged_observations"], 2)

    def test_page_and_record_order_does_not_change_identity_or_metadata(self):
        before = collection([{"id": "a"}, {"id": "b"}])
        after = collection([{"id": "b"}])
        after["pages"].append(collection([{"id": "a"}])["pages"][0])
        after["pages"][0]["metadata"].update(next="https://example.invalid/opaque", size=2)
        result = pair([before], [after])
        self.assertEqual(events(result), [])
        self.assertEqual(result["counts"]["unchanged_observations"], 2)

    def test_list_array_variant_is_read_but_unverified_coverage_is_preserved(self):
        before = collection(
            [{"clientId": "c"}], operation="org-oauth-clients", shape="array", coverage="unverified"
        )
        after = collection([], operation="org-oauth-clients", shape="array", coverage="unverified")
        result = pair([before], [after])
        self.assertEqual(events(result)[0]["change_type"], "observation_unknown")

    def test_changed_paths_escape_names_and_distinguish_missing_null_and_boolean(self):
        result = pair(
            [collection([{"id": "same", "a/b~": None, "flag": True}])],
            [collection([{"id": "same", "new": None, "flag": 1}])],
        )
        self.assertEqual(events(result)[0]["changed_paths"], ["/a~1b~0", "/flag", "/new"])

    def test_nested_arrays_remain_ordered_without_assuming_a_common_schema(self):
        result = pair(
            [collection([{"id": "same", "scopes": ["a", "b"]}])],
            [collection([{"id": "same", "scopes": ["b", "a"]}])],
        )
        self.assertEqual(events(result)[0]["changed_paths"], ["/scopes/0", "/scopes/1"])

    def test_sensitive_omissions_are_unknown_even_when_markers_are_equal(self):
        marker = {"_cremore_omitted": "sensitive_value"}
        for later in (marker, "synthetic-secret", compare.MISSING):
            with self.subTest(later=later):
                after = {"id": "same"}
                if later is not compare.MISSING:
                    after["secret"] = later
                result = pair(
                    [collection([{"id": "same", "secret": marker}])], [collection([after])]
                )
                self.assertEqual(events(result)[0]["change_type"], "metadata_unknown")
                self.assertEqual(events(result)[0]["unknown_paths"], ["/secret"])
                self.assertNotIn("synthetic-secret", json.dumps(result))

    def test_truncated_tail_does_not_turn_hidden_fields_into_changes(self):
        result = pair(
            [collection([{"id": "same", "detail": {"a": 1, "b": 2}}])],
            [
                collection(
                    [
                        {
                            "id": "same",
                            "detail": {
                                "_cremore_omitted_tail": {"_cremore_omitted": "snapshot_limit"}
                            },
                        }
                    ]
                )
            ],
        )
        self.assertEqual(events(result)[0]["changed_paths"], [])
        self.assertEqual(events(result)[0]["unknown_paths"], ["/detail"])

    def test_truncation_or_missing_pages_prevents_absence_even_if_coverage_says_complete(self):
        candidates = [collection([]), collection([])]
        candidates[0]["pages"][0]["redactions"]["truncated_nodes"] = 1
        candidates[1]["pages"] = []
        for after in candidates:
            result = pair([collection([{"id": "old"}])], [after])
            self.assertEqual(events(result)[0]["change_type"], "observation_unknown")

    def test_unexpected_response_or_error_page_is_not_compared_as_metadata(self):
        bad_shape = collection([])
        bad_shape["pages"][0]["metadata"] = {"error": "not-a-list"}
        bad_status = collection([{"id": "old", "label": "error-response"}])
        bad_status["pages"][0]["http_status"] = 403
        for after in (bad_shape, bad_status):
            result = pair([collection([{"id": "old"}])], [after])
            self.assertEqual(events(result)[0]["change_type"], "observation_unknown")

    def test_count_and_detail_documents_are_source_observations_not_credentials(self):
        before = collection([], operation="admin-api-key-count")
        after = deepcopy(before)
        before["pages"][0]["metadata"], after["pages"][0]["metadata"] = 1, 2
        result = pair([before], [after])
        self.assertEqual(events(result)[0]["identity"], {"source_document": True})
        self.assertEqual(events(result)[0]["changed_paths"], [""])
        self.assertNotIn("credentials", result["counts"])

    def test_bitbucket_numeric_ids_and_composite_target_contexts(self):
        before = collection(
            [{"id": 7, "label": "old"}],
            operation="repository-deploy-keys",
            target="repo",
            shape="values",
        )
        after = collection(
            [{"id": 7, "label": "new"}],
            operation="repository-deploy-keys",
            target="repo",
            shape="values",
        )
        result = pair(
            [before], [after], environment="bitbucket_cloud", kind="bitbucket_metadata_discovery"
        )
        self.assertEqual(events(result)[0]["identity"], {"field": "id", "value": 7})
        self.assertEqual(events(result)[0]["changed_paths"], ["/label"])

    def test_workspace_members_use_user_uuid_and_oidc_keys_use_kid(self):
        for operation, row in (
            ("workspace-members", {"user": {"uuid": "user-a"}}),
            ("workspace-oidc-keys", {"kid": "signing-key", "kty": "RSA"}),
        ):
            shape = "keys" if operation == "workspace-oidc-keys" else "values"
            report = collection([row], operation=operation, shape=shape)
            result = pair(
                [report],
                [deepcopy(report)],
                environment="bitbucket_cloud",
                kind="bitbucket_metadata_discovery",
            )
            self.assertEqual(result["counts"]["unchanged_observations"], 1)

    def test_public_key_bundle_without_stable_ids_is_explicitly_limited(self):
        report = collection([{"key": "PUBLIC KEY"}], operation="workspace-gpg-key", shape="values")
        result = pair(
            [report],
            [deepcopy(report)],
            environment="bitbucket_cloud",
            kind="bitbucket_metadata_discovery",
        )
        self.assertIn("unidentifiable_records", result["sources"][0]["after"]["issues"])
        self.assertEqual(events(result), [])
        self.assertEqual(result["comparison_status"], "limited")

    def test_snapshot_not_mutated(self):
        before, after = snapshot([collection([{"id": "same"}])]), snapshot([collection([])], day=21)
        originals = deepcopy((before, after))
        compare.compare_snapshots(before, after)
        self.assertEqual((before, after), originals)

    def test_saved_record_count_mismatch_cannot_claim_absence(self):
        after = collection([])
        after["saved_records"] = 1
        result = pair([collection([{"id": "old"}])], [after])
        self.assertEqual(events(result)[0]["change_type"], "observation_unknown")
        self.assertIn("saved_record_count_mismatch", result["sources"][0]["after"]["issues"])

    def test_global_fanout_limit_and_run_status_remain_visible(self):
        for field, value in (
            ("run_status", "unverified"),
            ("targets_omitted_by_limit", {"users": 1}),
            ("key_details_omitted_by_limit", 1),
            ("runner_details_omitted_by_limit", 1),
            ("invalid_identifiers", 1),
            ("target_discovery", {"invalid_identifiers": 1}),
        ):
            before, after = snapshot([collection([])]), snapshot([collection([])], day=21)
            after[field] = value
            result = compare.compare_snapshots(before, after)
            self.assertEqual(result["comparison_status"], "limited")
            self.assertTrue(result["input_limits"]["after"])

    def test_empty_snapshots_do_not_claim_complete_comparison(self):
        result = pair([], [])
        self.assertEqual(result["comparison_status"], "limited")

    def test_early_bitbucket_core_snapshot_without_mode_is_supported_conservatively(self):
        reports = []
        for operation in ("current-user", "workspace"):
            report = collection([], operation=operation)
            report["pages"][0]["metadata"] = {"uuid": "synthetic"}
            reports.append(report)
        before = snapshot(
            reports, environment="bitbucket_cloud", kind="bitbucket_metadata_discovery"
        )
        after = snapshot(
            deepcopy(reports),
            day=21,
            environment="bitbucket_cloud",
            kind="bitbucket_metadata_discovery",
        )
        before.pop("collection_mode")
        result = compare.compare_snapshots(before, after)
        self.assertEqual(result["counts"]["unchanged_observations"], 2)
        self.assertEqual(result["scope"]["collection_mode"], "core")
        before["collections"].append(collection([], operation="workspace-runners", shape="values"))
        with self.assertRaises(compare.ComparisonError):
            compare.compare_snapshots(before, after)

    def test_incompatible_bitbucket_workspace_is_rejected(self):
        before = snapshot([], environment="bitbucket_cloud", kind="bitbucket_metadata_discovery")
        after = snapshot(
            [], day=21, environment="bitbucket_cloud", kind="bitbucket_metadata_discovery"
        )
        after["workspace"] = "different-workspace"
        with self.assertRaises(compare.ComparisonError):
            compare.compare_snapshots(before, after)

    def test_tuple_target_namespaces_detail_documents(self):
        reports = []
        for target in (["repo-a", "7"], ["repo-b", "7"]):
            report = collection([], operation="repository-deploy-key-detail", target=target)
            report["pages"][0]["metadata"] = {"id": 7}
            reports.append(report)
        result = pair(
            reports,
            deepcopy(reports),
            environment="bitbucket_cloud",
            kind="bitbucket_metadata_discovery",
        )
        self.assertEqual(result["counts"]["unchanged_observations"], 2)
        self.assertEqual(result["counts"]["sources"], 2)

    def test_incompatible_org_environment_profile_mode_and_schema_are_rejected(self):
        before = snapshot([collection([])])
        for field, value in (
            ("queried_org_id", "another"),
            ("environment", "data_center"),
            ("connection_profile", "another"),
            ("schema_version", 2),
            ("report_type", "managed_account_metadata_discovery"),
            ("schema_version", True),
        ):
            with self.subTest(field=field, value=value):
                after = snapshot([collection([])], day=21)
                after[field] = value
                with self.assertRaises(compare.ComparisonError):
                    compare.compare_snapshots(before, after)
        before = snapshot([], environment="bitbucket_cloud", kind="bitbucket_metadata_discovery")
        after = deepcopy(before)
        after["collection_mode"] = "runners"
        with self.assertRaises(compare.ComparisonError):
            compare.compare_snapshots(before, after)

    def test_bad_time_order_overlap_and_naive_timestamps_are_rejected(self):
        before = snapshot([])
        for start, finish in (
            ("2026-09-19T00:00:00Z", "2026-09-19T01:00:00Z"),
            ("2026-09-20T00:00:30Z", "2026-09-20T01:00:00Z"),
            ("2026-09-21T00:00:00", "2026-09-21T01:00:00Z"),
            ("2026-09-21T02:00:00Z", "2026-09-21T01:00:00Z"),
        ):
            after = snapshot([], day=21)
            after.update(started_at=start, finished_at=finish)
            with self.assertRaises(compare.ComparisonError):
                compare.compare_snapshots(before, after)

    def test_duplicate_source_context_is_rejected(self):
        report = collection([])
        with self.assertRaises(compare.ComparisonError):
            pair([report, deepcopy(report)], [report])

    def test_legacy_inventory_compares_provider_fields_but_not_derived_expiry(self):
        before, after = snapshot({}), snapshot({}, day=21)
        for value in (before, after):
            value.pop("report_type")
            value["schema_version"] = 3
            value["collections"] = {
                name: {"coverage": "complete" if name == "org-api-tokens" else "not_requested"}
                for name in compare.SOURCES
            }
            obs = normalize("org-api-tokens", {"id": "same", "label": "name"}, value["started_at"])
            value["inventory"] = group_inventory([obs])
        after["inventory"][0]["observations"][0]["derived"] = {"expired_at_observation": True}
        result = compare.compare_snapshots(before, after)
        self.assertEqual(result["counts"]["unchanged_observations"], 1)
        self.assertEqual(result["counts"]["sources"], 1)
        after["inventory"][0]["observations"][0]["fields"]["label"]["value"] = "changed"
        result = compare.compare_snapshots(before, after)
        self.assertEqual(events(result)[0]["changed_paths"], ["/fields/label/value"])


class OfflineCliTests(unittest.TestCase):
    def inputs(self, directory, *, limited=False):
        before, after = directory / "before.json", directory / "after.json"
        before.write_text(
            json.dumps(snapshot([collection([{"id": "private-id", "label": "private-name"}])])),
            encoding="utf-8",
        )
        after.write_text(
            json.dumps(
                snapshot([collection([], coverage="partial" if limited else "complete")], day=21)
            ),
            encoding="utf-8",
        )
        return before, after

    def invoke(self, directory, before, after):
        output = io.StringIO()
        with (
            redirect_stdout(output),
            redirect_stderr(output),
            patch(
                "urllib.request.OpenerDirector.open",
                side_effect=AssertionError("Network forbidden"),
            ),
            patch(
                "cremore_atlassian_provider.metadata.qa.probe_cloud.load_connection",
                side_effect=AssertionError("Authentication forbidden"),
            ),
        ):
            try:
                code = compare.main(
                    ["--before", str(before), "--after", str(after)], directory=directory
                )
            except SystemExit as error:
                code = error.code
        return code, output.getvalue()

    @posix_native_io
    def test_cli_runs_without_connection_preserves_inputs_and_writes_private_comparison(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            before, after = self.inputs(directory)
            original = (before.read_bytes(), after.read_bytes())
            code, output = self.invoke(directory, before, after)
            self.assertEqual(code, 0)
            summary = json.loads(output)
            for private in ("synthetic-org", "private-id", "private-name", str(directory)):
                self.assertNotIn(private, output)
            artifact = directory / summary["output_file"]
            self.assertTrue(artifact.name.startswith("comparison-"))
            self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
            result = json.loads(artifact.read_text())
            self.assertEqual(result["input_sha256"]["before"], compare.load_snapshot(before)[1])
            self.assertEqual((before.read_bytes(), after.read_bytes()), original)
            self.assertEqual(list(directory.glob("inventory-*")), [])
            self.assertEqual(list(directory.glob(".*.tmp")), [])

    @posix_native_io
    def test_limited_comparison_saved_with_exit_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            before, after = self.inputs(directory, limited=True)
            code, output = self.invoke(directory, before, after)
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(output)["comparison_status"], "limited")
            self.assertEqual(len(list(directory.glob("comparison-*"))), 1)

    def test_failure_suppresses_input_values_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            before, after = self.inputs(directory)
            after.write_text('{"private-secret": invalid}')
            code, output = self.invoke(directory, before, after)
            self.assertEqual(code, 2)
            self.assertNotIn("private-secret", output)
            self.assertNotIn(str(directory), output)
            self.assertEqual(list(directory.glob("comparison-*")), [])

    def test_nonprivate_output_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            before, after = self.inputs(directory)
            directory.chmod(0o755)
            self.assertEqual(self.invoke(directory, before, after)[0], 2)
            self.assertEqual(list(directory.glob("comparison-*")), [])

    @posix_native_io
    def test_duplicate_json_keys_nan_size_depth_nodes_and_symlinks_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            value = directory / "input.json"
            for text in ('{"a":1,"a":2}', '{"a":NaN}', "[" * 66 + "0" + "]" * 66):
                value.write_text(text)
                with self.assertRaises(ValueError):
                    compare.load_snapshot(value)
            value.write_text("[1,2,3]")
            with patch.object(compare, "MAX_BYTES", 2), self.assertRaises(ValueError):
                compare.load_snapshot(value)
            with patch.object(compare, "MAX_NODES", 2), self.assertRaises(ValueError):
                compare.load_snapshot(value)
            link = directory / "link.json"
            link.symlink_to(value)
            with self.assertRaises(OSError):
                compare.load_snapshot(link)

    def test_storage_prefix_is_fixed_and_cannot_escape_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                save_private(Path(tmp), {}, prefix="../other")
            self.assertEqual(list(Path(tmp).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
