"""Batch isolation, global budgets, durable progress and sample-only diagnostics."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from copy import deepcopy
from pathlib import Path
from unittest.mock import Mock, patch

from cremore_atlassian_provider.metadata import jobs
from cremore_atlassian_provider.metadata.discovery import collect_accounts
from cremore_atlassian_provider.metadata.http import CloudClient, Limits

from . import posix_native_io
from .test_collector_cli import KEY, ORG, Response


def job(name="one", **extra):
    return dict(
        {
            "name": name,
            "mode": "cloud-inventory",
            "profile": "lab",
            "expected_scope": ORG,
            "sources": ["admin-api-keys"],
            "limits": {"retries": 0},
        },
        **extra,
    )


def config(*items, **extra):
    return dict({"schema_version": 1, "jobs": list(items or (job(),))}, **extra)


def page(identifier="key", next_page=None):
    return {
        "data": [{"id": identifier, "label": "private-person@example.invalid"}],
        "links": {"next": next_page},
    }


def factory(responses, clients=None):
    pending = iter(responses)

    def create(item, directory, limits):
        opener = Mock()
        opener.open.side_effect = next(pending)
        client = CloudClient(ORG, KEY, limits, opener=opener)
        if clients is not None:
            clients.append(client)
        return client

    return create


class JobsTests(unittest.TestCase):
    @posix_native_io
    def test_success_has_native_outputs_and_immutable_private_checkpoints(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            value = config(job(), job("two"))
            original = deepcopy(value)
            manifest, filename = jobs.run_jobs(
                value,
                directory,
                client_factory=factory([[Response(page())], [Response(page("second"))]]),
            )
            self.assertEqual((manifest["status"], manifest["requests"]), ("complete", 2))
            self.assertEqual(value, original)
            self.assertEqual(json.loads((directory / filename).read_text()), manifest)
            self.assertGreater(len(list(directory.glob("manifest-*"))), 2)
            for entry in manifest["jobs"]:
                output = directory / entry["output_file"]
                saved = json.loads(output.read_text())
                self.assertEqual(saved["schema_version"], 3)
                self.assertEqual(saved["connection_profile"], "lab")
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                self.assertEqual(jobs.load_snapshot(output)[1], entry["output_sha256"])
            summary = json.dumps(jobs.manifest_summary(manifest, filename))
            for value in (ORG, KEY, "private-person@example.invalid"):
                self.assertNotIn(value, summary)

    def test_invalid_config_is_rejected_before_any_client_or_output(self):
        cases = [
            config(job(), job()),
            config(job(api_token=KEY)),
            config(job(expected_scope="other")),
            config(job(mode="arbitrary-url")),
            config(job(), max_requests=True),
            config(job(), max_seconds=float("nan")),
            config(job(limits={"retries": 10})),
            config(job(profile="../other")),
            config(job(), unexpected="secret"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            for value in cases:
                create = Mock()
                with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                    jobs.run_jobs(value, Path(tmp), client_factory=create)
                create.assert_not_called()
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_profile_scope_mismatch_fails_before_network(self):
        item = jobs.validate_job(job())
        with (
            patch.object(
                jobs, "load_cloud", return_value=("00000000-0000-0000-0000-000000000010", KEY)
            ),
            patch.object(jobs, "CloudClient") as client,
        ):
            with self.assertRaises(ValueError):
                jobs.create_client(item, Path("."), Limits())
            client.assert_not_called()
        item = jobs.validate_job(
            {
                "name": "bitbucket",
                "mode": "bitbucket-core",
                "profile": "lab",
                "expected_scope": "lab",
            }
        )
        with (
            patch.object(jobs, "load_bitbucket", return_value=("other-workspace", KEY)),
            patch.object(jobs, "BitbucketClient") as client,
        ):
            with self.assertRaises(ValueError):
                jobs.create_client(item, Path("."), Limits())
            client.assert_not_called()

    @posix_native_io
    def test_connection_failure_does_not_stop_next_job_or_expose_exception(self):
        good = factory([[Response(page())]])

        def create(item, directory, limits):
            if item["name"] == "one":
                raise ValueError(KEY)
            return good(item, directory, limits)

        with tempfile.TemporaryDirectory() as tmp:
            manifest, _ = jobs.run_jobs(config(job(), job("two")), Path(tmp), client_factory=create)
            self.assertEqual(
                [entry["state"] for entry in manifest["jobs"]], ["configuration_error", "collected"]
            )
            self.assertEqual((manifest["status"], manifest["requests"]), ("partial", 1))
            self.assertNotIn(KEY, json.dumps(manifest))

    @posix_native_io
    def test_shared_request_budget_counts_retries_and_skips_remaining_jobs(self):
        clients = []
        busy = Response({}, 503)
        busy.headers["Retry-After"] = "0"
        with tempfile.TemporaryDirectory() as tmp:
            manifest, _ = jobs.run_jobs(
                config(job(limits={"retries": 1, "max_retry_wait": 0}), job("two"), max_requests=2),
                Path(tmp),
                client_factory=factory([[busy, Response(page())]], clients),
            )
            self.assertEqual(manifest["requests"], 2)
            self.assertEqual(manifest["jobs"][1]["state"], "skipped_budget")
            self.assertEqual(len(clients), 1)
        with tempfile.TemporaryDirectory() as tmp:
            manifest, _ = jobs.run_jobs(
                config(job(), job("two"), max_requests=1),
                Path(tmp),
                client_factory=factory([[Response(page(next_page="next"))]]),
            )
            self.assertEqual(manifest["requests"], 1)
            self.assertEqual(manifest["jobs"][1]["state"], "skipped_budget")
            self.assertEqual(manifest["jobs"][0]["run_status"], "partial")

    @posix_native_io
    def test_interrupt_keeps_previous_output_and_marks_pending_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            manifest, _ = jobs.run_jobs(
                config(job(), job("two"), job("three")),
                directory,
                client_factory=factory([[Response(page())], [KeyboardInterrupt()]]),
            )
            self.assertEqual(manifest["status"], "interrupted")
            self.assertEqual(
                [entry["state"] for entry in manifest["jobs"]],
                ["collected", "interrupted", "skipped_after_interrupt"],
            )
            self.assertEqual(manifest["requests"], 2)
            self.assertTrue((directory / manifest["jobs"][0]["output_file"]).exists())
            checkpoints = [json.loads(path.read_text()) for path in directory.glob("manifest-*")]
            self.assertTrue(
                any(
                    value["jobs"] and value["jobs"][-1]["state"] == "running"
                    for value in checkpoints
                )
            )

    @posix_native_io
    def test_output_failure_stops_future_jobs(self):
        original_save = jobs.save_private

        def save(directory, value, *, prefix="inventory"):
            if prefix == "inventory":
                raise OSError("disk full " + KEY)
            return original_save(directory, value, prefix=prefix)

        create = Mock(wraps=factory([[Response(page())], [Response(page())]]))
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(jobs, "save_private", side_effect=save),
        ):
            with self.assertRaises(OSError):
                jobs.run_jobs(config(job(), job("two")), Path(tmp), client_factory=create)
            self.assertEqual(create.call_count, 1)
            self.assertTrue(list(Path(tmp).glob("manifest-*")))

    @posix_native_io
    def test_deadline_includes_connection_setup(self):
        elapsed = [0]
        good = factory([[Response(page())]])

        def create(item, directory, limits):
            elapsed[0] = 3
            return good(item, directory, limits)

        with tempfile.TemporaryDirectory() as tmp:
            manifest, _ = jobs.run_jobs(
                config(job(), job("two"), max_seconds=2),
                Path(tmp),
                client_factory=create,
                clock=lambda: elapsed[0],
            )
            self.assertEqual(manifest["requests"], 0)
            self.assertEqual(
                [entry["state"] for entry in manifest["jobs"]], ["skipped_budget", "skipped_budget"]
            )

    def test_http_outer_deadline_cannot_extend_client_time(self):
        elapsed = [0]
        opener = Mock()
        client = CloudClient(
            ORG, KEY, Limits(max_seconds=10), opener=opener, clock=lambda: elapsed[0]
        )
        client.restrict_time(2)
        client.restrict_time(100)
        elapsed[0] = 3
        response = client.fetch("admin-api-keys", {"pageSize": 20})
        self.assertEqual(response.reason, "time_limit")
        opener.open.assert_not_called()

    @posix_native_io
    def test_dry_run_loads_no_credentials_and_prints_only_safe_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "jobs.json"
            file.write_text(json.dumps(config(job())))
            out = io.StringIO()
            with patch.object(jobs, "create_client") as create, redirect_stdout(out):
                code = jobs.main(["--config", str(file), "--dry-run"], directory=Path(tmp))
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.getvalue())["status"], "valid_plan")
            self.assertNotIn(ORG, out.getvalue())
            create.assert_not_called()
            self.assertEqual(len(list(Path(tmp).iterdir())), 1)

    @posix_native_io
    def test_cli_connection_error_returns_partial_and_hides_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            file = directory / "jobs.json"
            file.write_text(json.dumps(config(job())))
            out = io.StringIO()
            with (
                patch.object(jobs, "create_client", side_effect=ValueError(KEY)),
                redirect_stdout(out),
            ):
                code = jobs.main(["--config", str(file)], directory=directory)
            self.assertEqual(code, 1)
            self.assertNotIn(KEY, out.getvalue())
            self.assertNotIn(ORG, out.getvalue())


class DiagnosticsTests(unittest.TestCase):
    def test_failure_categories_never_explain_404_as_permissions(self):
        for status, expected in (
            (401, "authentication_rejected"),
            (403, "access_denied"),
            (404, "not_found_or_hidden"),
            (429, "rate_limited"),
            (400, "request_rejected"),
            (503, "provider_error"),
        ):
            self.assertEqual(
                jobs.diagnostic_outcome(
                    {"last_http_status": status, "reason": "http_" + str(status)}
                ),
                expected,
            )

    def test_server_retry_wait_limit_does_not_mean_rate_limit(self):
        self.assertEqual(
            jobs.diagnostic_outcome(
                {"last_http_status": 503, "reason": "retry_wait_exceeds_limit"}
            ),
            "provider_error",
        )

    @posix_native_io
    def test_first_page_is_readable_sample_without_complete_inventory_claim(self):
        clients = []
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            manifest, _ = jobs.run_jobs(
                config(job(limits={"retries": 5})),
                directory,
                diagnose=True,
                client_factory=factory([[Response(page(next_page="next"))]], clients),
            )
            self.assertEqual(manifest["requests"], 1)
            self.assertEqual(clients[0].limits.retries, 0)
            self.assertEqual(clients[0].limits.max_pages, 1)
            result = json.loads((directory / manifest["jobs"][0]["output_file"]).read_text())
            self.assertEqual(result["checks"][0]["outcome"], "readable_sample")
            self.assertFalse(result["inventory_complete"])
            self.assertNotIn("private-person@example.invalid", json.dumps(result))
            self.assertNotIn(KEY, json.dumps(result))
            self.assertEqual(list(directory.glob("inventory-*")), [])

    def test_public_oidc_read_does_not_claim_authentication_was_checked(self):
        report = {
            "collections": [
                {
                    "operation": "workspace-oidc-keys",
                    "last_http_status": 200,
                    "coverage": "complete",
                    "reason": None,
                    "requests": 1,
                    "saved_records": 1,
                }
            ],
            "started_at": "2026-09-21T00:00:00Z",
            "finished_at": "2026-09-21T00:01:00Z",
            "run_status": "complete",
        }
        item = {"mode": "bitbucket-core", "profile": "lab", "expected_scope": "lab"}
        result = jobs.diagnostics(report, item)
        self.assertFalse(result["checks"][0]["authentication_sent"])

    def test_large_managed_account_fanout_obeys_single_request_budget(self):
        opener = Mock()

        def response(request, **kwargs):
            if request.full_url.endswith("/users"):
                return Response(
                    {"data": [{"account_id": f"user-{n:04d}"} for n in range(500)], "links": {}}
                )
            return Response([] if request.full_url.endswith("/api-tokens") else {})

        opener.open.side_effect = response
        client = CloudClient(ORG, KEY, Limits(max_requests=17, retries=0), opener=opener)
        result = collect_accounts(client, max_targets=500)
        self.assertEqual(opener.open.call_count, 17)
        self.assertEqual(len(result["collections"]), 1501)
        self.assertEqual(result["run_status"], "partial")
        self.assertTrue(
            all(report["reason"] == "request_limit" for report in result["collections"][17:])
        )


class ResumeJobsTests(unittest.TestCase):
    @posix_native_io
    def test_resume_skips_verified_complete_output_and_keeps_original_config_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            value = config(job(), job("two"))
            manifest, _ = jobs.run_jobs(
                value, directory, client_factory=factory([[Response(page())], [Response({}, 403)]])
            )
            selected = jobs.resume_jobs(value, manifest, directory)
            self.assertEqual(selected, ["two"])
            resumed, _ = jobs.run_jobs(
                value,
                directory,
                selected_jobs=selected,
                client_factory=factory([[Response(page("second"))]]),
            )
            self.assertEqual(resumed["config_sha256"], manifest["config_sha256"])
            self.assertEqual(resumed["selected_jobs"], ["two"])
            self.assertEqual(jobs.resume_jobs(value, resumed, directory), [])

    @posix_native_io
    def test_resume_detects_missing_modified_or_symlinked_output(self):
        for damage in ("missing", "modified", "symlink"):
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                value = config(job())
                manifest, _ = jobs.run_jobs(
                    value, directory, client_factory=factory([[Response(page())]])
                )
                output = directory / manifest["jobs"][0]["output_file"]
                if damage == "modified":
                    output.write_text("{}")
                else:
                    output.unlink()
                    if damage == "symlink":
                        output.symlink_to(directory / "private-connection.json")
                self.assertEqual(jobs.resume_jobs(value, manifest, directory), ["one"])

    @posix_native_io
    def test_resume_rejects_changed_config_action_or_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            value = config(job())
            manifest, _ = jobs.run_jobs(
                value, directory, client_factory=factory([[Response(page())]])
            )
            with self.assertRaises(ValueError):
                jobs.resume_jobs(config(job(), max_requests=1), manifest, directory)
            with self.assertRaises(ValueError):
                jobs.resume_jobs(value, manifest, directory, diagnose=True)
            manifest["jobs"][0]["expected_scope"] = "wrong"
            with self.assertRaises(ValueError):
                jobs.resume_jobs(value, manifest, directory)

    @posix_native_io
    def test_initial_running_checkpoint_can_select_all_pending_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            value = config(job(), job("two"))
            jobs.run_jobs(
                value, directory, client_factory=factory([[Response(page())], [Response(page())]])
            )
            initial = next(
                json.loads(file.read_text())
                for file in directory.glob("manifest-*")
                if not json.loads(file.read_text())["jobs"]
            )
            self.assertEqual(jobs.resume_jobs(value, initial, directory), ["one", "two"])

    @posix_native_io
    def test_cli_nothing_to_resume_is_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            value = config(job())
            _manifest, filename = jobs.run_jobs(
                value, directory, client_factory=factory([[Response(page())]])
            )
            config_file = directory / "jobs.json"
            config_file.write_text(json.dumps(value))
            count = len(list(directory.iterdir()))
            out = io.StringIO()
            with patch.object(jobs, "create_client") as create, redirect_stdout(out):
                code = jobs.main(
                    ["--config", str(config_file), "--resume-manifest", str(directory / filename)],
                    directory=directory,
                )
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.getvalue())["status"], "nothing_to_resume")
            create.assert_not_called()
            self.assertEqual(count, len(list(directory.iterdir())))


if __name__ == "__main__":
    unittest.main()
