"""Write/read compatibility, durable publication and bounded large artifacts."""

import hashlib
import io
import json
import tempfile
import tracemalloc
import unittest
from pathlib import Path
from unittest.mock import patch

from cremore_atlassian_provider.metadata import jsonio, storage
from cremore_atlassian_provider.metadata.compare import load_snapshot

from . import posix_native_io


class ArtifactIOTests(unittest.TestCase):
    @posix_native_io
    def test_large_result_above_old_32_mib_limit_round_trips(self):
        # Individual pages remain smaller than the transport's 1 MiB limit.
        page = {"metadata": {"description": "x" * (512 * 1024)}}
        value = {"pages": [page] * 68}
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            filename = storage.save_private(directory, value)
            self.assertGreater((directory / filename).stat().st_size, 32 * 1024 * 1024)
            restored, digest = load_snapshot(directory / filename)
            self.assertEqual(restored, value)
            self.assertEqual(digest, storage.output_digest(directory, filename))

    def test_utf8_byte_limit_includes_indentation_and_final_newline(self):
        value = {"한국어": ["값", "é"]}
        expected = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()
        out = io.BytesIO()
        self.assertEqual(jsonio.write_json(out, value, max_bytes=len(expected)), len(expected))
        self.assertEqual(out.getvalue(), expected)
        with self.assertRaises(ValueError):
            jsonio.write_json(io.BytesIO(), value, max_bytes=len(expected) - 1)

    def test_wide_array_validation_uses_depth_not_width_memory(self):
        value = [None] * 300000
        tracemalloc.start()
        try:
            jsonio.bounded_json(value)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 1024 * 1024)

    @posix_native_io
    def test_writer_and_reader_enforce_same_structure_limits(self):
        for value, bounds in (
            ([0, 1], {"max_nodes": 2}),
            ([[0]], {"max_depth": 1}),
            ({"value": float("nan")}, {}),
        ):
            with self.subTest(bounds=bounds), tempfile.TemporaryDirectory() as tmp:
                file = Path(tmp) / "input.json"
                file.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    jsonio.load_json(file, **bounds)
                with self.assertRaises(ValueError):
                    jsonio.write_json(io.BytesIO(), value, **bounds)

    @posix_native_io
    def test_oversized_serialization_never_publishes_or_leaves_temporary_file(self):
        original = jsonio.write_json
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            name = storage.save_private(directory, {"previous": True})
            before = (directory / name).read_bytes()

            def bounded_write(handle, value):
                return original(handle, value, max_bytes=128)

            with (
                patch.object(storage, "write_json", side_effect=bounded_write),
                self.assertRaises(ValueError),
            ):
                storage.save_private(directory, {"metadata": "x" * 200})
            self.assertEqual([p.name for p in directory.iterdir()], [name])
            self.assertEqual((directory / name).read_bytes(), before)

    @posix_native_io
    def test_write_fsync_and_link_failures_preserve_existing_output(self):
        for phase in ("write", "file_fsync", "link", "directory_fsync", "interrupt"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                previous = storage.save_private(directory, {"previous": True})
                original = (directory / previous).read_bytes()
                if phase in ("write", "interrupt"):

                    def fail(handle, value, phase=phase):
                        handle.write(b'{"incomplete":')
                        raise KeyboardInterrupt() if phase == "interrupt" else OSError("disk full")

                    mock = patch.object(storage, "write_json", side_effect=fail)
                elif phase == "link":
                    mock = patch.object(
                        storage.os, "link", side_effect=OSError("publication failed")
                    )
                else:
                    side_effect = (
                        OSError("sync failed")
                        if phase == "file_fsync"
                        else [None, OSError("sync failed")]
                    )
                    mock = patch.object(storage.os, "fsync", side_effect=side_effect)
                with mock, self.assertRaises((OSError, KeyboardInterrupt)):
                    storage.save_private(directory, {"new": True})
                self.assertEqual((directory / previous).read_bytes(), original)
                self.assertFalse(list(directory.glob("*.tmp")))
                # If the final directory sync fails, a complete, unclaimed file
                # may exist. No partial JSON or false completion is published.
                for file in directory.glob("*.json"):
                    self.assertIn(jsonio.load_json(file)[0], ({"previous": True}, {"new": True}))

    @posix_native_io
    def test_private_reference_checks_owner_mode_and_hash_of_same_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            name = storage.save_private(
                directory, {"metadata": "sample"}, prefix="recollection-part"
            )
            restored, digest = storage.load_private(directory, name)
            self.assertEqual(restored, {"metadata": "sample"})
            self.assertEqual(digest, hashlib.sha256((directory / name).read_bytes()).hexdigest())
            (directory / name).chmod(0o644)
            with self.assertRaises(ValueError):
                storage.load_private(directory, name)


if __name__ == "__main__":
    unittest.main()
