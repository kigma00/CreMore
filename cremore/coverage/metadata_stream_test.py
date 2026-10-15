"""Storage byte/count limits and summary truncation survive library reuse."""

from types import SimpleNamespace

import pytest
from cremore_azure_provider.metadata.azure_key_vault_test import spec
from cremore_azure_provider.metadata.normalization import report

from cremore.coverage import metadata_auth, metadata_job, metadata_stream
from cremore.coverage.metadata_models import MetadataFact
from cremore.coverage.metadata_stream import batches_for, safe_error_code, source_summary
from cremore.coverage.models import MAX_BATCH
from cremore.coverage.store import CoverageError


def row(**changes):
    connection = spec()
    return report(connection, connection.scopes[0], "azure.key_vault.secrets", **changes)


def test_batches_keep_order_and_resume_index_at_item_limit():
    records = [row(received=i) for i in range(MAX_BATCH + 2)]
    batches = list(batches_for(iter(records), 7))
    assert [(b.index, len(b.items)) for b in batches] == [(7, MAX_BATCH), (8, 2)]
    assert [r.received_records for b in batches for r in b.items] == list(range(MAX_BATCH + 2))
    assert list(batches_for([], 0)) == []


def test_utf8_byte_budget_splits_before_item_limit():
    record = row()
    record.facts = [MetadataFact(name="name", value=["한" * 1000] * 20)]
    batches = list(batches_for([record] * 80, 0))
    assert len(batches) > 1
    assert sum(len(b.items) for b in batches) == 80
    assert all(len(b.model_dump_json().encode()) <= 2_000_000 for b in batches)


def test_summary_keeps_last_report_for_same_operation_and_scope():
    records = [row(status="FAILED", reasons=["FORBIDDEN"]).model_dump(),
               row(status="COMPLETE", received=3, saved=3).model_dump()]
    store = SimpleNamespace(iter_records=lambda rid: iter(records))
    result = source_summary(store, "run")
    assert result["source_reports_total"] == 1
    assert result["source_reports_truncated"] is False
    assert result["source_reports"][0]["status"] == "COMPLETE"
    assert result["source_reports"][0]["saved_records"] == 3


@pytest.mark.parametrize("long_labels", [False, True])
def test_summary_is_bounded_by_both_count_and_encoded_size(long_labels):
    records = []
    for i in range(1001):
        record = row().model_dump()
        record["provenance"]["resource_id"] = str(i) + ("a" * 500 if long_labels else "")
        records.append(record)
    result = source_summary(SimpleNamespace(iter_records=lambda rid: iter(records)), "run")
    assert result["source_reports_total"] == 1001
    assert result["source_reports_truncated"] is True
    assert len(result["source_reports"]) < (1000 if long_labels else 1001)


def test_only_safe_error_codes_are_persistable():
    assert safe_error_code(CoverageError("METADATA_RETRY_LATER")) == "METADATA_RETRY_LATER"
    assert safe_error_code(RuntimeError("provider response with sensitive text")) == "METADATA_COLLECTION_FAILED"
    assert safe_error_code(CoverageError("invalid code with response text")) == "METADATA_COLLECTION_FAILED"


def test_resolved_slots_cleanup_on_success_and_failure():
    spec = SimpleNamespace(secret_refs={"token": "vault://synthetic/token"})
    resolver = SimpleNamespace(resolve=lambda ref: {"token": "synthetic-value"})
    with metadata_auth.resolved_slots(spec, resolver) as values:
        assert values == {"token": "synthetic-value"}
    assert values == {}
    with pytest.raises(RuntimeError), metadata_auth.resolved_slots(spec, resolver) as values:
        raise RuntimeError("synthetic planning failure")
    assert values == {}


def test_an_optional_secret_role_that_cannot_be_resolved_is_left_out():
    from cremore.coverage.providers import collector_for

    def resolve(ref):
        if ref == "sealed:rotated":
            raise RuntimeError("synthetic backend diagnostic: do not publish")
        return {} if ref == "vault://synthetic/empty" else {"token": "synthetic-value"}

    resolver = SimpleNamespace(resolve=resolve)
    optional = collector_for("github").optional_secret_roles
    assert optional == {"installation_id", "audit_token"}
    assert collector_for("notion").optional_secret_roles == frozenset()
    for ref in ("sealed:rotated", "vault://synthetic/empty"):
        spec = SimpleNamespace(secret_refs={"token": "vault://synthetic/token", "audit_token": ref})
        assert metadata_auth.resolve_slots(spec, resolver, optional) == {"token": "synthetic-value"}
        # Without the declaration every role is required, as before.
        with pytest.raises(CoverageError, match="METADATA_SECRET_UNAVAILABLE"):
            metadata_auth.resolve_slots(spec, resolver)
    # A required role still fails the run, whatever else is optional.
    spec = SimpleNamespace(secret_refs={"token": "sealed:rotated", "audit_token": "vault://synthetic/token"})
    with pytest.raises(CoverageError, match="METADATA_SECRET_UNAVAILABLE"):
        metadata_auth.resolve_slots(spec, resolver, optional)


def test_old_worker_helper_imports_remain_compatible():
    assert metadata_job.resolve_slots is metadata_auth.resolve_slots
    assert metadata_job.batches_for is metadata_stream.batches_for
    assert metadata_job.source_summary is metadata_stream.source_summary
