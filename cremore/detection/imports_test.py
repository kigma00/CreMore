"""Pure detection helpers import independently of the engine composition root."""

import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("module", [
    "cremore.detection.fingerprint",
    "cremore.detection.models",
    "cremore_aws_provider.detection.session_material",
])
def test_pure_modules_import_first_and_preserve_public_exports(module):
    result = subprocess.run(
        [sys.executable, "-c", """
import importlib
import sys

def no_network(event, args):
    if event in {"socket.connect", "socket.getaddrinfo"}:
        raise AssertionError("Importing a library must not use the network")

sys.addaudithook(no_network)
importlib.import_module(sys.argv[1])
assert "cremore.detection.engine" not in sys.modules
import cremore.detection as detection
assert {"Engine", "EngineConfig"} <= set(dir(detection))
from cremore.detection import Engine, EngineConfig
from cremore.detection.engine import Engine as implementation
from cremore.detection.engine import EngineConfig as configuration
assert Engine is implementation and EngineConfig is configuration
assert detection.Engine is Engine and detection.EngineConfig is EngineConfig
assert all(getattr(detection, name) is not None for name in detection.__all__)
try:
    detection.missing_public_name
except AttributeError:
    pass
else:
    raise AssertionError("Unknown attributes must fail")
""", module],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
