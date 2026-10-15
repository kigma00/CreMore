"""Versioned output contracts and recovery from transient test artifacts."""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from cremore_atlassian_provider.metadata.jobs import resume_jobs
from cremore_atlassian_provider.metadata.recollect import build_plan

from . import posix_native_io
from .output_samples import AUTH, generate, job

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:
    Draft202012Validator = None

ROOT = Path(__file__).resolve().parent
PROVIDER = ROOT.parent / "metadata"


class IntegrationHandoffTests(unittest.TestCase):
    def test_package_imports_without_repository_scripts_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copytree(
                PROVIDER,
                Path(tmp) / "atlassian_collector",
                ignore=shutil.ignore_patterns("__pycache__"),
            )
            code = "import atlassian_collector.cli, atlassian_collector.jobs, atlassian_collector.recollect, atlassian_collector.compare"
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "import sys; sys.path.insert(0, " + repr(tmp) + "); " + code,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    @posix_native_io
    def test_collected_artifacts_resume_and_reference_hashes_match(self):
        samples, artifacts = generate()
        self.assertNotIn(AUTH, json.dumps([samples, artifacts]))
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name, value in artifacts.items():
                destination = directory / name
                destination.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
                destination.chmod(0o600)
            manifest = samples["manifest"]
            self.assertEqual(
                resume_jobs(
                    {"schema_version": 1, "jobs": [job("cloud-accounts")]}, manifest, directory
                ),
                [],
            )
            checkpoint = samples["recollection-checkpoint"]
            self.assertEqual(build_plan(checkpoint, directory=directory)["selected_count"], 0)
            for value in [*samples.values(), *artifacts.values()]:
                for reference in value.get("collection_refs", []):
                    self.assertEqual(
                        hashlib.sha256((directory / reference["file"]).read_bytes()).hexdigest(),
                        reference["sha256"],
                    )


@unittest.skipIf(
    Draft202012Validator is None, "Install .[dev] for JSON Schema contract checks"
)
class OutputSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads((ROOT / "contracts/atlassian-outputs.schema.json").read_text())
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema, format_checker=FormatChecker())

    @posix_native_io
    def test_current_collectors_and_generated_artifacts_match_contract(self):
        samples, artifacts = generate()
        values = [*samples.values(), *artifacts.values()]
        for index, value in enumerate(values):
            with self.subTest(index=index, report_type=value.get("report_type", "inventory")):
                self.assertFalse(list(self.validator.iter_errors(value)))

    @posix_native_io
    def test_contract_rejects_missing_state_wrong_version_and_false_completion(self):
        samples, _ = generate()
        cases = []
        for name in (
            "cloud-inventory",
            "cloud-discovery",
            "bitbucket-core",
            "comparison",
            "manifest",
            "diagnostic",
            "recollection",
            "recollection-part",
        ):
            value = deepcopy(samples[name])
            value["schema_version"] = 999
            cases.append(value)
        value = deepcopy(samples["cloud-accounts"])
        del value["collections"][0]["coverage"]
        cases.append(value)
        value = deepcopy(samples["partial"])
        value["collections"][0]["requests"] = -1
        cases.append(value)
        value = deepcopy(samples["manifest"])
        del value["jobs"][0]["output_sha256"]
        cases.append(value)
        value = deepcopy(samples["cloud-inventory"])
        value["inventory_complete"] = True
        cases.append(value)
        value = deepcopy(samples["cloud-accounts"])
        value["finished_at"] = "yesterday"
        cases.append(value)
        for index, value in enumerate(cases):
            with self.subTest(index=index):
                self.assertTrue(list(self.validator.iter_errors(value)))

    def test_job_configuration_schema_matches_mode_and_secret_boundaries(self):
        schema = json.loads((ROOT / "contracts/atlassian-jobs.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        example = {"schema_version": 1, "jobs": [job(mode) for mode in (
            "cloud-inventory", "cloud-discovery", "cloud-accounts", "bitbucket-core", "bitbucket-runners", "bitbucket-branches")]}
        self.assertFalse(list(validator.iter_errors(example)))
        for field, value in (
            ("api_token", "example-secret"),
            ("include_account_reads", "false"),
            ("expected_scope", "../outside"),
        ):
            invalid = deepcopy(example)
            invalid["jobs"][0][field] = value
            with self.subTest(field=field):
                self.assertTrue(list(validator.iter_errors(invalid)))
