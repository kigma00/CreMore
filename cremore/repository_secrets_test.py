"""The repository itself must not carry credential-shaped values.

Detector fixtures still need token-shaped input, so tests split each value into
adjacent string pieces ("AKIA..." "...") that join only at run time. This scan
runs the platform's own engine over every tracked file and fails on any finding
above low confidence that is not already marked as a placeholder.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from cremore.detection import DetectorInput, Engine, ResourceRef

ROOT = Path(__file__).resolve().parent.parent


def _repository_files() -> list[Path]:
    if not shutil.which("git") or not (ROOT / ".git").exists():
        pytest.skip("needs a git checkout")
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout
    return [ROOT / name for name in out.decode().split("\0") if name]


def test_no_credential_shaped_values_in_repository():
    engine = Engine()
    found = []
    for path in _repository_files():
        if not path.is_file():
            continue
        data = path.read_bytes()
        if b"\0" in data[:4096]:
            continue
        for d in engine.scan(DetectorInput(data=data, resource=ResourceRef())):
            if d.confidence != "low" and not d.extra_safe_data.get("fp_signal"):
                found.append(f"{path.relative_to(ROOT).as_posix()}:{d.line_number} {d.credential_type}")
    assert not found, "credential-shaped values in the repository:\n" + "\n".join(found)
