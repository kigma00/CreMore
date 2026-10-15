"""Keep organization credentials separate without loading any real key."""

import io
import json
import stat
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from cremore_atlassian_provider.metadata.qa import configure_local, probe_cloud
from cremore_atlassian_provider.metadata.qa.connection_profile import connection_filename

from . import posix_native_io

OLD_ORG = "00000000-0000-0000-0000-000000000001"
NEW_ORG = "00000000-0000-0000-0000-000000000002"
OLD_KEY = "SYNTHETIC_OLD_KEY"
NEW_KEY = "SYNTHETIC_NEW_KEY"


class ConnectionProfileTests(unittest.TestCase):
    def make_original(self, root):
        directory = root / ".local"
        directory.mkdir(mode=0o700)
        old = directory / "connection.json"
        old.write_text(json.dumps({"org_id": OLD_ORG, "api_key": OLD_KEY}))
        old.chmod(0o600)
        return directory, old

    def run_setup(self, root, key=NEW_KEY, tty=True):
        output = io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(patch.object(configure_local.Path, "cwd", return_value=root))
            stack.enter_context(
                patch("sys.argv", ["configure_local.py", "--org-id", NEW_ORG, "--profile", "lab"])
            )
            stack.enter_context(patch("sys.stdin.isatty", return_value=tty))
            prompt = stack.enter_context(
                patch.object(configure_local.getpass, "getpass", return_value=key)
            )
            stack.enter_context(redirect_stdout(output))
            stack.enter_context(redirect_stderr(output))
            code = 0
            try:
                configure_local.main()
            except SystemExit as error:
                code = error.code
        return code, output.getvalue(), prompt.call_count

    def test_profile_cannot_escape_private_directory(self):
        self.assertEqual(connection_filename(), "connection.json")
        self.assertEqual(connection_filename("lab"), "connection-lab.json")
        for bad in ("", "../lab", "/lab", "a/b", "a\\b", ".", "Lab", "a\n", "a" * 33, False):
            with self.subTest(profile=repr(bad)), self.assertRaises(ValueError):
                connection_filename(bad)

    @posix_native_io
    def test_saving_named_profile_preserves_original_and_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory, old = self.make_original(root)
            before = old.read_bytes()
            code, output, prompts = self.run_setup(root)
            self.assertEqual((code, prompts), (0, 1))
            self.assertEqual(old.read_bytes(), before)
            self.assertEqual(probe_cloud.load_connection(directory), (OLD_ORG, OLD_KEY))
            self.assertEqual(probe_cloud.load_connection(directory, "lab"), (NEW_ORG, NEW_KEY))
            self.assertEqual(
                stat.S_IMODE((directory / "connection-lab.json").stat().st_mode), 0o600
            )
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            self.assertIn("connection-lab.json", output)
            self.assertNotIn(NEW_KEY, output)
            self.assertNotIn(OLD_KEY, output)

    @posix_native_io
    def test_existing_named_profile_is_not_overwritten_or_prompted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.assertEqual(self.run_setup(root)[0], 0)
            path = root / ".local/connection-lab.json"
            before = path.read_bytes()
            code, _, prompts = self.run_setup(root, key="SYNTHETIC_REPLACEMENT")
            self.assertEqual((code, prompts), (2, 0))
            self.assertEqual(path.read_bytes(), before)

    @posix_native_io
    def test_missing_named_profile_never_falls_back_to_original(self):
        with tempfile.TemporaryDirectory() as temp:
            directory, _ = self.make_original(Path(temp))
            with self.assertRaises(FileNotFoundError):
                probe_cloud.load_connection(directory, "lab")

    @posix_native_io
    def test_symlink_profile_cannot_overwrite_or_load_another_connection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory, old = self.make_original(root)
            before = old.read_bytes()
            (directory / "connection-lab.json").symlink_to(old)
            code, _, prompts = self.run_setup(root)
            self.assertEqual((code, prompts), (2, 0))
            self.assertEqual(old.read_bytes(), before)
            with self.assertRaises(ValueError):
                probe_cloud.load_connection(directory, "lab")

    def test_noninteractive_input_is_refused_before_prompt(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            code, _, prompts = self.run_setup(root, tty=False)
            self.assertEqual((code, prompts), (2, 0))
            self.assertFalse((root / ".local/connection-lab.json").exists())

    def test_control_characters_are_rejected_without_creating_profile(self):
        for suffix in ("\n", "\x00", "\x7f"):
            with self.subTest(suffix=repr(suffix)), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                code, output, _ = self.run_setup(root, key=NEW_KEY + suffix)
                self.assertEqual(code, 2)
                self.assertFalse((root / ".local/connection-lab.json").exists())
                self.assertNotIn(NEW_KEY, output)

    @posix_native_io
    def test_probe_cli_uses_only_selected_organization_and_labels_report(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory, _ = self.make_original(root)
            self.assertEqual(self.run_setup(root)[0], 0)
            output = io.StringIO()
            with (
                patch.object(probe_cloud.Path, "cwd", return_value=root),
                patch("sys.argv", ["probe_cloud.py", "--profile", "lab"]),
                patch.object(
                    probe_cloud, "probe", return_value={"outcome": "documented_shape"}
                ) as request,
                redirect_stdout(output),
            ):
                self.assertEqual(probe_cloud.main(), 0)
            request.assert_called_once_with("admin-api-keys", NEW_ORG, NEW_KEY)
            report = json.loads(output.getvalue())
            self.assertEqual(report["connection_profile"], "lab")
            self.assertNotIn(NEW_KEY, output.getvalue())
            self.assertNotIn(OLD_KEY, output.getvalue())
            files = list(directory.glob("probe-*.json"))
            self.assertEqual(len(files), 1)
            self.assertEqual(stat.S_IMODE(files[0].stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
