"""Private storage and the complete CLI flow using synthetic HTTP responses."""

import io
import json
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from cremore_atlassian_provider.metadata import cli
from cremore_atlassian_provider.metadata.http import CloudClient
from cremore_atlassian_provider.metadata.storage import save_private

from . import posix_native_io

ORG = "00000000-0000-0000-0000-000000000009"
KEY = "SYNTHETIC_CONNECTION_SECRET"
UNKNOWN_SECRET = "SYNTHETIC_RESPONSE_SECRET"
PII = "private-person@example.invalid"


class Response(io.BytesIO):
    def __init__(self, body, status=200):
        super().__init__(json.dumps(body).encode())
        self.code, self.headers = status, {}


class CliTests(unittest.TestCase):
    def connection(self, directory):
        directory.chmod(0o700)
        p = directory / "connection-lab.json"
        p.write_text(json.dumps({"org_id": ORG, "api_key": KEY}))
        p.chmod(0o600)

    def invoke(self, directory, responses, args=None):
        opener, output = Mock(), io.StringIO()
        opener.open.side_effect = responses

        def client(org, key, limits, **kwargs):
            return CloudClient(org, key, limits, opener=opener, **kwargs)

        with (
            patch.object(cli, "CloudClient", side_effect=client),
            redirect_stdout(output),
            redirect_stderr(output),
        ):
            try:
                code = cli.main(args or ["--profile", "lab"], directory=directory)
            except SystemExit as error:
                code = error.code
        return code, output.getvalue(), opener

    @posix_native_io
    def test_three_http_responses_to_private_inventory_and_safe_stdout(self):
        sample = {
            "id": "token-1",
            "label": PII,
            "status": "ALLOWED",
            "createdAt": "2026-09-19T00:00:00Z",
            "expiresAt": "2026-10-19T00:00:00Z",
            "lastActiveAt": None,
            "user": {
                "id": "service-1",
                "orgId": ORG,
                "name": PII,
                "email": PII,
                "secret": UNKNOWN_SECRET,
            },
            "scopes": ["read:jira-user"],
            "clientSecret": UNKNOWN_SECRET,
        }
        key = {
            "id": "key-1",
            "label": PII,
            "createdAt": "2026-09-19T00:00:00Z",
            "expiresAt": "2026-10-19T00:00:00Z",
            "lastActiveAt": None,
            "createdBy": {"id": "human", "name": PII, "email": PII},
        }
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            self.connection(directory)
            code, output, opener = self.invoke(
                directory,
                [
                    Response({"data": [key], "links": {"next": None}}),
                    Response({"data": [sample], "links": {"next": None}}),
                    Response([sample]),
                ],
            )
            self.assertEqual(code, 0)
            summary = json.loads(output)
            self.assertEqual(summary["counts"]["identities"], 2)
            for private in (PII, KEY, UNKNOWN_SECRET, ORG, "token-1"):
                self.assertNotIn(private, output)
            files = list(directory.glob("inventory-*.json"))
            self.assertEqual(len(files), 1)
            self.assertEqual(stat.S_IMODE(files[0].stat().st_mode), 0o600)
            self.assertEqual(files[0].name, Path(summary["output_file"]).name)
            artifact = files[0].read_text()
            self.assertIn(PII, artifact)
            self.assertNotIn(KEY, artifact)
            self.assertNotIn(UNKNOWN_SECRET, artifact)
            self.assertEqual(json.loads(artifact)["connection_profile"], "lab")
            for call in opener.open.call_args_list:
                self.assertIn("/orgs/" + ORG + "/", call.args[0].full_url)
                self.assertEqual(call.args[0].get_header("Authorization"), "Bearer " + KEY)
            self.assertEqual(opener.open.call_count, 3)

    @posix_native_io
    def test_partial_run_is_saved_and_returns_one(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            self.connection(directory)
            code, output, _ = self.invoke(
                directory,
                [
                    Response({"data": [{"id": "key"}], "links": {"next": None}}),
                    Response({"message": UNKNOWN_SECRET}, 403),
                ],
                ["--profile", "lab", "--sources", "admin-api-keys", "org-api-tokens"],
            )
            self.assertEqual(code, 1)
            summary = json.loads(output)
            self.assertEqual(summary["run_status"], "partial")
            self.assertEqual(summary["counts"]["identities"], 1)
            self.assertNotIn(UNKNOWN_SECRET, output)
            self.assertEqual(len(list(directory.glob("inventory-*.json"))), 1)

    @posix_native_io
    def test_oauth_opt_in_uses_fixed_get_paths_and_saves_unverified_array(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            self.connection(directory)
            sample = {
                "clientId": "synthetic-client",
                "name": PII,
                "status": "ACTIVE",
                "createdAt": 0,
                "clientSecret": UNKNOWN_SECRET,
            }
            code, output, opener = self.invoke(
                directory,
                [Response([]), Response([sample])],
                [
                    "--profile",
                    "lab",
                    "--sources",
                    "service-account-oauth-clients",
                    "org-oauth-clients",
                ],
            )
            self.assertEqual(code, 1)
            summary = json.loads(output)
            self.assertEqual(summary["run_status"], "unverified")
            self.assertEqual(summary["schema_version"], 3)
            self.assertEqual(summary["collections"]["admin-api-keys"]["coverage"], "not_requested")
            paths = ["/service-accounts/oauth-clients", "/oauth-clients?pageSize=20"]
            for call, path in zip(opener.open.call_args_list, paths):
                request = call.args[0]
                self.assertEqual(
                    request.full_url,
                    "https://api.atlassian.com/admin/api-access/v1/orgs/" + ORG + path,
                )
                self.assertEqual(request.get_method(), "GET")
            self.assertEqual(opener.open.call_count, 2)
            for private in (KEY, UNKNOWN_SECRET, PII, "synthetic-client"):
                self.assertNotIn(private, output)
            artifact = next(directory.glob("inventory-*.json")).read_text()
            self.assertNotIn(UNKNOWN_SECRET, artifact)
            self.assertNotIn(KEY, artifact)
            self.assertIn('"normalized_utc": "1970-01-01T00:00:00+00:00"', artifact)

    def test_missing_profile_and_invalid_limits_make_no_request(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            self.connection(directory)
            for args in (
                ["--profile", "absent"],
                ["--profile", "lab", "--max-pages", "0"],
                ["--profile", "lab", "--max-seconds", "nan"],
                ["--profile", "lab", "--token-page-size", "1"],
                ["--profile", "lab", "--accounts", "--token-page-size", "1"],
                ["--profile", "lab", "--discovery", "--token-page-size", "0"],
                ["--profile", "lab", "--discovery", "--token-page-size", "1001"],
                ["--profile", "lab", "--sources", "org-api-tokens", "org-api-tokens"],
            ):
                with self.subTest(args=args):
                    code, output, opener = self.invoke(directory, [], args)
                    self.assertEqual(code, 2)
                    opener.open.assert_not_called()
                    self.assertNotIn(KEY, output)
            self.assertEqual(list(directory.glob("inventory-*.json")), [])

    def test_output_error_is_sanitized_and_not_reported_as_complete(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            self.connection(directory)
            with patch.object(cli, "save_private", side_effect=OSError(UNKNOWN_SECRET)):
                code, output, _ = self.invoke(
                    directory,
                    [Response([])],
                    ["--profile", "lab", "--sources", "service-account-api-tokens"],
                )
            self.assertEqual(code, 2)
            self.assertNotIn(UNKNOWN_SECRET, output)
            self.assertNotIn('"run_status": "complete"', output)

    @posix_native_io
    def test_storage_is_atomic_private_and_repeated_runs_do_not_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            directory.chmod(0o700)
            first = save_private(directory, {"metadata": "first"})
            second = save_private(directory, {"metadata": "second"})
            self.assertNotEqual(first, second)
            self.assertEqual(json.loads((directory / first).read_text()), {"metadata": "first"})
            self.assertEqual(stat.S_IMODE((directory / second).stat().st_mode), 0o600)
            self.assertEqual(list(directory.glob(".inventory-*.tmp")), [])
            with self.assertRaises(TypeError):
                save_private(directory, {"invalid": object()})
            self.assertEqual(len(list(directory.iterdir())), 2)

    @posix_native_io
    def test_storage_refuses_symlink_directory_and_existing_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory = root / "private"
            directory.mkdir(mode=0o700)
            link = root / "link"
            link.symlink_to(directory)
            with self.assertRaises(OSError):
                save_private(link, {})
            destination = directory / "inventory-fixed.json"
            destination.write_text("original")
            with (
                patch(
                    "cremore_atlassian_provider.metadata.storage.uuid.uuid4",
                    return_value=Mock(hex="fixed"),
                ),
                self.assertRaises(FileExistsError),
            ):
                save_private(directory, {})
            self.assertEqual(destination.read_text(), "original")
            self.assertEqual(list(directory.glob("*.tmp")), [])
            directory.chmod(0o755)
            with self.assertRaises(ValueError):
                save_private(directory, {})


if __name__ == "__main__":
    unittest.main()
