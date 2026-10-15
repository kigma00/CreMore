"""Import boundaries that let API libraries be reused without booting the API."""

import subprocess
import sys
from pathlib import Path


def test_libraries_and_registrars_import_without_the_application_root():
    # A fresh process matters: the rest of the API suite legitimately imports
    # create_app during collection and would hide a new eager dependency here.
    result = subprocess.run(
        [sys.executable, "-c", """
import importlib
import sys

modules = (
    "http_support", "source_contract", "source_presenters",
    "finding_presenters", "finding_routes", "detection_catalog", "rule_payloads",
    "governance_presenters", "aws_support", "search_service", "route_context",
)
for name in modules:
    importlib.import_module("cremore.api." + name)
assert "cremore.api.app" not in sys.modules
assert "cremore.api.dashboard" not in sys.modules
assert "cremore.api.routes" not in sys.modules

import cremore.api.routes
assert "cremore.api.app" not in sys.modules
assert "cremore.api.dashboard" not in sys.modules
"""],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_existing_factory_and_projection_imports_remain_compatible():
    import cremore.api
    from cremore.api import create_app, dashboard
    from cremore.api.app import create_app as original_factory
    from cremore.api.aws_support import access_key_metadata, sign_in_diagnosis
    from cremore.api.finding_presenters import present_finding
    from cremore.api.http_support import log_safe
    from cremore.api.search_service import search_payload

    assert create_app is original_factory
    assert cremore.api.create_app is original_factory
    assert "create_app" in dir(cremore.api)
    assert dashboard._dashboard_finding is present_finding
    assert dashboard._access_key_metadata is access_key_metadata
    assert dashboard._sign_in_diagnosis is sign_in_diagnosis
    assert dashboard._log_safe is log_safe
    assert dashboard.search_payload is search_payload


def test_library_resource_lookup_survives_extraction(monkeypatch, tmp_path):
    from cremore.api.aws_support import member_template_path
    from cremore.api.detection_catalog import credential_type_catalog

    # No deployment override: exercise the source-tree fallback from the new
    # module location, rather than accidentally reading a developer's /app.
    monkeypatch.setenv("CREMORE_CLOUDFORMATION_DIR", str(tmp_path))
    template = member_template_path()
    assert template is not None and template.name == "member-account-role.yaml"
    assert "AWSTemplateFormatVersion" in template.read_text()
    catalog = credential_type_catalog()
    assert catalog["types"]
    assert catalog["counts"]["detectors"] == len(catalog["mappings"])
