"""Provider services are declared, never inferred from native signatures."""

from types import SimpleNamespace

import pytest
from cremore_azure_provider.metadata.azure_key_vault_test import spec

from cremore.coverage.collector_runtime import CollectionContext, CollectorRuntime
from cremore.coverage.metadata_models import MetadataPage
from cremore.coverage.providers import adapter_for, catalog, collector_for, validate_spec
from cremore.coverage.store import CoverageError


def context(**changes):
    return CollectionContext(**{
        "secrets": {}, "checkpoint": {}, "check": lambda: None,
        "read_records": lambda: iter(()), **changes,
    })


@pytest.mark.parametrize("provider,values,recollect", [
    ("gitlab", True, False), ("github", True, True), ("gcp", True, False),
    ("atlassian", False, True), ("bitbucket", False, True),
    ("azure_key_vault", True, False), ("azure_entra", False, False), ("notion", False, False),
    ("azure_resource_manager", True, False),
])
def test_registered_services_and_ui_agree(provider, values, recollect):
    runtime = collector_for(provider)
    assert runtime.uses_value_context is values
    assert runtime.supports_recollection is recollect
    assert catalog.descriptor(provider)["recollect"] is recollect
    assert catalog.descriptor(provider)["compare"] is runtime.supports_comparison
    assert runtime.adapter is adapter_for(provider)


def test_existing_module_entry_point_and_validation_remain_available():
    assert validate_spec(spec()) is adapter_for("azure_key_vault")
    with pytest.raises(CoverageError, match="INVALID_METADATA_PROVIDER_SCOPE"):
        validate_spec(spec(scopes=[{"kind": "vault", "id": "different-vault"}]))


def test_unregistered_or_broken_adapter_fails_closed(monkeypatch):
    from cremore.coverage import providers

    with pytest.raises(CoverageError, match="METADATA_ADAPTER_UNAVAILABLE"):
        collector_for("unknown")
    monkeypatch.setattr(providers, "import_module", lambda name: SimpleNamespace(
        collect_pages=lambda *a, **kw: (), validate_spec=lambda s: None,
        validate_record=lambda s, r: True,
    ))
    # A declared retry provider must supply its planner, even if its native
    # collect_pages happens to accept arbitrary keywords.
    with pytest.raises(CoverageError, match="METADATA_ADAPTER_UNAVAILABLE"):
        collector_for("atlassian")


def test_collect_is_lazy_and_forwards_only_declared_services():
    seen = []

    def native(spec, **kwargs):
        seen.append(kwargs)
        yield MetadataPage(status="COMPLETE")

    runtime = CollectorRuntime(adapter=SimpleNamespace(collect_pages=native))
    request = context(checkpoint={"page": 2})
    pages = runtime.collect(spec(), request)
    assert seen == []
    assert next(iter(pages)).status == "COMPLETE"
    assert seen == [{"secrets": request.secrets, "checkpoint": {"page": 2},
                     "check": request.check, "read_records": request.read_records}]


def test_value_services_are_forwarded_only_to_declared_provider():
    seen = []
    adapter = SimpleNamespace(collect_pages=lambda spec, **kw: seen.append(kw) or ())
    value = {"engine": object()}
    request = context(value_context=value)
    with pytest.raises(CoverageError, match="METADATA_VALUE_CONTEXT_UNSUPPORTED"):
        CollectorRuntime(adapter=adapter).collect(spec(), request)
    assert seen == []
    CollectorRuntime(adapter=adapter, uses_value_context=True).collect(spec(), request)
    assert seen[0]["value_context"] is value


def test_recollection_forwards_validated_plan_and_selection():
    seen = []
    records = [{"status": "FAILED"}]
    plan = {"report_type": "metadata_recollection_plan"}

    def planner(rows, **selection):
        seen.append((list(rows), selection))
        return plan

    adapter = SimpleNamespace(collect_pages=lambda spec, **kw: seen.append(kw) or ())
    runtime = CollectorRuntime(adapter=adapter, planner=planner)
    selected = runtime.plan_recollection(iter(records), scope_id="lab",
        operations=["service_accounts"], include_unverified=True)
    runtime.collect(spec(), context(recollection_plan=selected))
    assert seen[0] == (records, {"scope_id": "lab", "operations": ["service_accounts"],
                               "include_unverified": True})
    assert seen[1]["recollection_plan"] is plan
    unsupported = CollectorRuntime(adapter=adapter)
    with pytest.raises(CoverageError, match="METADATA_RECOLLECTION_UNSUPPORTED"):
        unsupported.plan_recollection(iter(records))
    with pytest.raises(CoverageError, match="METADATA_RECOLLECTION_UNSUPPORTED"):
        unsupported.collect(spec(), context(recollection_plan=plan))


def test_context_repr_does_not_disclose_authentication_or_value_services():
    marker = "synthetic-credential-not-for-network-use"
    request = context(secrets={"token": marker}, value_context={"capture_value": marker})
    assert marker not in repr(request)


@pytest.mark.parametrize("provider", ["gitlab", "gcp", "atlassian", "bitbucket", "azure_key_vault"])
def test_comparison_preserves_provider_native_order_and_arguments(monkeypatch, provider):
    runtime = collector_for(provider)
    before, after = [{"run": "before"}], [{"run": "after"}]
    connection = SimpleNamespace(provider=provider)
    seen = []
    expected = {"comparison": "native output unchanged"}
    def native(*args, **kwargs):
        seen.append((args, kwargs))
        return expected
    monkeypatch.setattr(runtime.adapter, "compare_records", native)
    assert runtime.compare_records(before, after, spec=connection, scope_id="selected") is expected
    if provider in {"gitlab", "gcp"}:
        assert seen == [((after, before), {"spec": connection})]
    elif provider in {"atlassian", "bitbucket"}:
        assert seen == [((before, after), {"scope_id": "selected"})]
    else:
        assert seen == [((before, after), {})]


def test_machine_guard_is_a_registration_fact(monkeypatch):
    from cremore.coverage import providers

    # Integration: GitLab's stricter machine-record guard is declared, not keyed on its name. Identity
    # collections declare one that refuses every machine-submitted record: a digest proves nothing.
    assert [name for name, item in providers._ADAPTERS.items() if item.machine_guard] == [
        "gitlab", "okta", "keycloak", "entra_id", "github_identity", "google_workspace"]
    assert not collector_for("okta").adapter.validate_machine_record(None, None)
    assert callable(collector_for("gitlab").adapter.validate_machine_record)
    # A guarded provider whose adapter lost its guard fails when it loads instead of accepting records.
    monkeypatch.setattr(providers, "import_module", lambda name: SimpleNamespace(
        collect_pages=lambda *args, **kwargs: (), validate_spec=lambda spec: None,
        validate_record=lambda spec, record: True, _compare_runs=lambda *args, **kwargs: {},
    ))
    with pytest.raises(CoverageError, match="METADATA_ADAPTER_UNAVAILABLE"):
        collector_for("gitlab")


def test_comparison_requires_explicit_registration(monkeypatch):
    from cremore.coverage import providers

    runtime = collector_for("github")
    monkeypatch.setattr(runtime.adapter, "compare_records", lambda *args, **kwargs: {}, raising=False)
    with pytest.raises(CoverageError, match="METADATA_COMPARISON_UNSUPPORTED"):
        runtime.compare_records([], [], spec=SimpleNamespace(provider="github"))
    # A declared comparison must supply its provider-owned call bridge.
    monkeypatch.setattr(providers, "import_module", lambda name: SimpleNamespace(
        collect_pages=lambda *args, **kwargs: (), validate_spec=lambda spec: None,
        validate_record=lambda spec, record: True, compare_records=lambda *args: {},
    ))
    with pytest.raises(CoverageError, match="METADATA_ADAPTER_UNAVAILABLE"):
        collector_for("azure_key_vault")
