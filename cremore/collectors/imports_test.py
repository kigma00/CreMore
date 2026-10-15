"""Provider collectors remain reusable regardless of import order."""

import subprocess
import sys

import pytest


@pytest.mark.parametrize("first_module", [
    "cremore_aws_provider.collectors.s3",
    "cremore_github_provider.collectors.github",
    "cremore_notion_provider.collectors.notion",
    "cremore.collectors.base",
    "cremore.collectors",
])
def test_collector_imports_and_compatibility_exports(first_module, tmp_path):
    # Full-suite imports can hide cycles. Each entry point needs a fresh process.
    result = subprocess.run(
        [sys.executable, "-B", "-c", """
import importlib
import sys

importlib.import_module(sys.argv[1])
import cremore.collectors as public

exports = {
    "BytesCollector": "cremore.collectors.bytes_source",
    "CollectedObject": "cremore.collectors.base",
    "Collector": "cremore.collectors.base",
    "S3Collector": "cremore_aws_provider.collectors.s3",
    "GitHubCollector": "cremore_github_provider.collectors.github",
    "GitHubOrgCollector": "cremore_github_provider.collectors.github",
    "NotionCollector": "cremore_notion_provider.collectors.notion",
}
assert set(public.__all__) == exports.keys()
assert exports.keys() <= set(dir(public))
if sys.argv[1].startswith("cremore.collectors"):
    assert not any("_provider.collectors." in name for name in sys.modules)

from cremore.collectors import *
for name, module_name in exports.items():
    module = importlib.import_module(module_name)
    assert globals()[name] is getattr(public, name) is getattr(module, name)
    if "_provider." in module_name:
        legacy = "cremore.collectors." + module_name.rsplit(".", 1)[1]
        assert importlib.import_module(legacy) is module
assert not hasattr(public, "UnknownCollector")
""", first_module],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
