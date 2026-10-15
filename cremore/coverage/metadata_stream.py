"""Bounded metadata batches and operation summaries shared by collector runners."""

import json
import re

from cremore.coverage.metadata_models import MetadataBatch
from cremore.coverage.models import MAX_BATCH
from cremore.coverage.store import CoverageError


def safe_error_code(exc):
    code = getattr(exc, "code", "")
    if isinstance(exc, CoverageError):
        code = str(exc)
    return code if isinstance(code, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", code) else "METADATA_COLLECTION_FAILED"


def batches_for(records, index):
    """Respect the byte budget as well as the item limit before opening a tx."""
    pending, size = [], 100
    for record in records:
        count = len(record.model_dump_json().encode()) + 1
        if pending and (len(pending) == MAX_BATCH or size + count > 1_999_900):
            yield MetadataBatch(index=index, items=pending)
            index += 1
            pending, size = [], 100
        pending.append(record)
        size += count
    if pending:
        yield MetadataBatch(index=index, items=pending)


def source_summary(store, rid):
    latest = {}
    for record in store.iter_records(rid):
        if record["record_type"] == "operation_report":
            key = (record["provenance"]["operation"], str(record["scope"]), record["provenance"]["resource_id"])
            latest[key] = {"operation": key[0], "scope": record["scope"], "resource_id": key[2],
                           "status": record["status"], "reasons": record["reasons"],
                           "received_records": record["received_records"], "saved_records": record["saved_records"]}
    shown, size = [], 0
    for key in sorted(latest):
        row = latest[key]
        size += len(json.dumps(row).encode())
        if len(shown) >= 1000 or size > 256000:
            break
        shown.append(row)
    return {"source_reports": shown, "source_reports_total": len(latest), "source_reports_truncated": len(shown) < len(latest)}
