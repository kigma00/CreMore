"""Presentation metadata stays separate from provider execution and availability."""

import subprocess
import sys
from importlib import import_module

import pytest

from cremore.coverage import providers
from cremore.coverage.providers import catalog
from cremore.coverage.store import CoverageError

NAMES = ("gitlab", "gcp", "github", "atlassian", "bitbucket", "azure_key_vault", "notion", "slack", "azure_entra",
         "azure_resource_manager", "azure_devops", "okta", "keycloak", "entra_id", "github_identity", "google_workspace")


def test_onboarding_reuses_collection_defaults_and_provider_overrides():
    assert catalog.descriptor("gitlab")["defaults"]["options"]["include_self_pat"] is True
    assert catalog.descriptor("azure_key_vault")["defaults"]["options"]["include_values"] is False
    assert catalog.descriptor("gcp")["defaults"]["options"]["include_values"] is True
    assert catalog.descriptor("notion")["defaults"]["options"]["sources"] == ["personal_access_tokens"]


def test_catalog_preserves_order_and_returns_shallow_entry_copies(monkeypatch):
    monkeypatch.setattr(providers, "adapter_for", lambda provider: object())
    entries = catalog.catalog()
    assert tuple(entry["provider"] for entry in entries) == NAMES
    for entry in entries:
        original = catalog.descriptor(entry["provider"])
        assert entry == original
        assert entry is not original
        assert entry["limitations"] is original["limitations"]


@pytest.mark.parametrize("unavailable", NAMES)
def test_catalog_omits_each_unavailable_adapter_in_place(monkeypatch, unavailable):
    attempted = []

    def adapter_for(provider):
        attempted.append(provider)
        if provider == unavailable:
            raise CoverageError("METADATA_ADAPTER_UNAVAILABLE")
        return object()

    monkeypatch.setattr(providers, "adapter_for", adapter_for)
    assert tuple(entry["provider"] for entry in catalog.catalog()) == tuple(
        name for name in NAMES if name != unavailable
    )
    assert tuple(attempted) == NAMES


def test_catalog_does_not_hide_unexpected_adapter_errors(monkeypatch):
    def broken(provider):
        raise RuntimeError("unexpected adapter failure")

    monkeypatch.setattr(providers, "adapter_for", broken)
    with pytest.raises(RuntimeError, match="unexpected adapter failure"):
        catalog.catalog()


def test_descriptors_keep_unknown_and_shared_adapter_provider_behavior():
    assert catalog.descriptor("unknown") is None
    assert catalog.descriptor("atlassian")["scope_kinds"] == ["organization"]
    assert catalog.descriptor("bitbucket")["scope_kinds"] == ["workspace", "user", "project", "repository"]
    assert catalog.descriptor("atlassian") is not catalog.descriptor("bitbucket")


def test_reading_descriptors_does_not_import_provider_execution_modules():
    # A fresh interpreter exposes import side effects hidden by a warm test process.
    script = """
import importlib.abc
import sys

provider_roots = tuple('cremore_' + name + '_provider' for name in
                       ('gcp', 'github', 'gitlab', 'atlassian', 'azure', 'notion', 'okta', 'keycloak'))

class NoProviderExecution(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        parts = fullname.split('.')
        if (fullname.startswith('cremore.coverage.providers.')
                and len(parts) > 4 and parts[4] != 'descriptor'):
            raise AssertionError('descriptor imported execution module: ' + fullname)
        if (parts[0] in provider_roots and len(parts) > 1
                and parts[1:] not in (['metadata'], ['metadata', 'descriptor'], ['entra'], ['entra', 'descriptor'], ['arm'], ['arm', 'descriptor'],
                                  ['devops_tokens'], ['devops_tokens', 'descriptor'], ['entra_id'], ['entra_id', 'descriptor'],
                                  ['identity'], ['identity', 'descriptor'], ['workspace'], ['workspace', 'descriptor'],
                                  ['descriptor'])):
            raise AssertionError('descriptor imported execution module: ' + fullname)

sys.meta_path.insert(0, NoProviderExecution())
from cremore.coverage.providers.catalog import PROVIDERS, descriptor
for entry in PROVIDERS:
    assert descriptor(entry['provider']) == entry
assert descriptor('unknown') is None
"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_atlassian_public_exports_keep_original_object_identity():
    from cremore.coverage.providers import atlassian
    from cremore.coverage.providers.atlassian.collector import collect
    from cremore.coverage.providers.atlassian.http import CloudClient, Limits

    assert atlassian.__all__ == ["CloudClient", "Limits", "collect"]
    assert atlassian.collect is collect
    assert atlassian.CloudClient is CloudClient
    assert atlassian.Limits is Limits
    with pytest.raises(AttributeError):
        _ = atlassian.unknown_export


@pytest.mark.parametrize("legacy,vendor", [
    ("gcp", "gcp"), ("github", "github"), ("gitlab", "gitlab"),
    ("atlassian", "atlassian"), ("azure_key_vault", "azure"),
])
def test_legacy_adapter_alias_preserves_private_objects_and_patch_identity(monkeypatch, legacy, vendor):
    old = import_module(f"cremore.coverage.providers.{legacy}.adapter")
    native = import_module(f"cremore_{vendor}_provider.metadata.adapter")
    assert old is native
    assert providers.adapter_for(legacy) is native
    assert old.__dict__ is native.__dict__
    marker = object()
    monkeypatch.setattr(old, "_compatibility_identity", marker, raising=False)
    assert native._compatibility_identity is marker


@pytest.mark.parametrize("legacy,vendor", [
    ("gcp", "gcp"), ("github", "github"), ("gitlab", "gitlab"),
    ("atlassian", "atlassian"), ("azure_key_vault", "azure"),
])
def test_legacy_package_star_import_preserves_native_public_exports(legacy, vendor):
    native = import_module(f"cremore_{vendor}_provider.metadata")
    exports = {}
    # Fixed test parameters exercise Python's actual import-star protocol.
    exec(f"from cremore.coverage.providers.{legacy} import *", exports)  # noqa: S102
    names = getattr(native, "__all__", [name for name in vars(native) if not name.startswith("_")])
    for name in names:
        assert exports[name] is getattr(native, name)
