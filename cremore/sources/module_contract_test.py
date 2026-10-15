"""Static content-source contracts retain public ordering and import boundaries."""

import subprocess
import sys

from cremore.sources import registry


def test_registered_source_contracts_have_unique_ids_and_known_scope_kinds():
    modules = tuple(registry.PROVIDERS.values())
    assert tuple(registry.PROVIDERS) == ("aws", "github", "notion", "gitlab", "gcp", "confluence", "bitbucket",
                                         "azure_blob", "azure_devops", "website")
    for attribute in ("PROVIDER", "SOURCE_TYPE", "CAPABILITY_ORDER"):
        values = [getattr(module, attribute) for module in modules]
        assert len(values) == len(set(values))
    for attribute in ("JOB_KINDS", "RESOURCE_TYPES"):
        values = [value for module in modules for value in getattr(module, attribute)]
        assert len(values) == len(set(values))
    for module in modules:
        assert module.SCOPE_KIND in {"object", "path", "page"}
        assert isinstance(module.FILTERS, tuple)
        assert isinstance(module.INSTANCE_SCOPED, bool), module.PROVIDER
        assert len(module.FILTERS) == len(set(module.FILTERS))
        for name in ("validate_config", "job_payload", "job_kind", "config_from_scope",
                     "scope_ref", "build_collector", "build_root", "list_resources", "check_credential"):
            assert callable(getattr(module, name)), (module.PROVIDER, name)


def test_source_implementations_are_owned_by_top_level_provider_libraries():
    from importlib import import_module

    vendors = {"confluence": "atlassian", "bitbucket": "atlassian", "azure_blob": "azure", "azure_devops": "azure"}
    for provider, module in registry.PROVIDERS.items():
        assert module.__name__.startswith(f"cremore_{vendors.get(provider, provider)}_provider.")
        if provider in LEGACY_IMPORTS:
            assert import_module(f"cremore.sources.{provider}") is module


# Compatibility import paths predate the provider libraries; new sources get none.
LEGACY_IMPORTS = ("aws", "github", "notion", "gitlab", "gcp", "confluence", "bitbucket")


def test_existing_public_orders_and_notion_resource_mapping_are_preserved():
    assert registry.SOURCE_TYPES == ["s3", "github", "notion", "gitlab", "gcp", "confluence", "bitbucket", "azure_blob",
                                     "azure_devops", "website"]
    assert [item["id"] for item in registry.SOURCE_CAPABILITIES] == [
        "s3", "github", "notion", "bitbucket", "gitlab", "gcp", "confluence", "azure_blob", "azure_devops", "website"]
    assert registry.CONTENT_SCAN_KINDS == (
        "s3", "github", "github-org", "notion", "gitlab", "gcp", "confluence", "bitbucket", "azure_blob", "azure_devops",
        "website", "scope", "inline")
    assert registry.STRUCTURED_PROVIDERS == ("gitlab", "gcp", "confluence", "bitbucket", "azure_blob", "azure_devops",
                                            "website")
    assert registry.INSTANCE_SOURCES == ("gitlab", "confluence", "bitbucket", "azure_devops")
    assert registry.TOKEN_KINDS == (
        "github", "github-org", "notion", "gitlab", "gcp", "confluence", "bitbucket", "azure_blob", "azure_devops",
        "scope", "catalog-refresh")
    assert registry.EXACT_FIELDS == {
        "S3_BUCKET": "exact_keys", "GITHUB_REPOSITORY": "exact_paths", "NOTION_PAGE": "exact_page_ids",
        "NOTION_DATA_SOURCE": "exact_page_ids", "GITLAB_REPOSITORY": "exact_paths", "GCS_BUCKET": "exact_keys",
        "CONFLUENCE_PAGE": "exact_paths", "BITBUCKET_REPOSITORY": "exact_paths", "AZURE_BLOB_CONTAINER": "exact_keys",
        "AZURE_DEVOPS_REPOSITORY": "exact_paths", "AZURE_DEVOPS_TFVC": "exact_paths", "WEBSITE": "exact_paths"}
    assert registry.BY_RESOURCE_TYPE["NOTION_DATA_SOURCE"] is registry.PROVIDERS["notion"]
    assert "NOTION_DATA_SOURCE" not in registry.RESOURCE_SOURCE
    assert registry.RESOURCE_SOURCE["NOTION_PAGE"] == "notion"


def test_registry_import_does_not_load_domain_collectors_api_or_database():
    script = """import sys
from cremore.sources import registry
for prefix in ('cremore.domain', 'cremore.collectors', 'cremore.api', 'cremore.worker', 'sqlalchemy'):
    assert not any(name == prefix or name.startswith(prefix + '.') for name in sys.modules), prefix
assert len(registry.PROVIDERS) == 10
for name in sys.modules:
    if name.startswith('cremore_') and '_provider.' in name:
        leaf = name.split('_provider.', 1)[1]
        assert leaf in ('source', 'confluence_source', 'bitbucket_source', 'blob_source', 'devops_source'), name
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_platform_source_lists_derive_from_the_registry():
    """Integration: consumers that copied the source list now read the registry (web keeps one constant)."""
    import re
    from pathlib import Path

    from cremore.db import scan_state

    assert scan_state.INSTANCE_SOURCES is registry.INSTANCE_SOURCES
    web = (Path(__file__).resolve().parents[2] / "web" / "lib" / "source-types.ts").read_text(encoding="utf-8")
    declared = re.search(r"CONTENT_SOURCE_TYPES = \[([^\]]*)\]", web)
    assert declared and re.findall(r'"([^"]+)"', declared.group(1)) == registry.SOURCE_TYPES
