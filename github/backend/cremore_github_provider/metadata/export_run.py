"""Export lifecycle within the existing atomic metadata page/checkpoint protocol."""

from __future__ import annotations

import hashlib
import json
import math
from contextlib import closing
from copy import deepcopy
from datetime import UTC, datetime

from cremore.coverage.metadata_models import MetadataPage

from . import export_http
from .exports import ExportError, Projection, rows
from .http import Budget, SourceError


def _canonical(value):
    if isinstance(value, dict):
        return {key: _canonical(child) for key, child in value.items() if key not in {"observed_at", "read_at"}}
    if isinstance(value, list):
        result = [_canonical(child) for child in value]
        if result and all(isinstance(child, dict) and "name" in child for child in result):
            result.sort(key=lambda child: child["name"])
        elif result and all(isinstance(child, dict) and "path" in child for child in result):
            result.sort(key=lambda child: (child["path"], child.get("reason", "")))
        return result
    return value


def _prefix(digest, records):
    # Bind a resume cursor to normalized evidence, including keyed digest when
    # selected. No raw row, download location or provider hash is checkpointed.
    data = [_canonical(record.model_dump()) for record in records]
    digest.update(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())
    digest.update(b"\n")


def collect(spec, run, current, transport, broker, *, value_context, spent, report, validate,
            control=None):
    """Return True when the worker must defer, False when this source finished.

    `control` is the worker's durable Enterprise reservation service. The page
    protocol also commits submission intent before the one non-idempotent POST.
    An interrupted POST with no confirmed export ID is never submitted again.
    """
    current = deepcopy(current)
    state = current.setdefault("export", {})
    # Authentication may fail before a reservation exists. Never let a state
    # update hide that failure behind a reservation ownership error.
    can_save = False

    def publish(records=(), *, waiting=False, reason=None, retry_after=30):
        checked = validate(spec, list(records))
        run.charge(checked)
        run.tasks[current["id"]] = deepcopy(current)
        run.requests = spent + transport.requests
        run.refused = broker.refused()
        return MetadataPage(records=checked, checkpoint=run.checkpoint(),
            status="WAITING" if waiting else None, reasons=[reason] if reason else [],
            retry_after_seconds=max(1, min(3600, math.ceil(retry_after))))

    def budget():
        transport.check()
        if run.out_of_time():
            raise Budget("TIME_BUDGET_EXCEEDED")
        if sum(task["pages"] for task in run.tasks.values()) >= spec.max_pages:
            raise Budget("PAGE_BUDGET_EXCEEDED")

    def save():
        if control is not None and can_save:
            control.save(dict(state))

    try:
        budget()
        bearer = broker.token_for("enterprise", run.enterprise)
        can_save = bool(state.get("export_id"))
        if not state:
            if control is not None:
                reserved = control.reserve()
                state.update(reserved)
                can_save = state.get("stage") not in {"quota_wait", "submission_unknown"}
                if state.get("stage") == "quota_wait":
                    # Quota deferral is surfaced by the platform; no new
                    # export or synthetic empty successful run is produced.
                    raise ExportError("github_export_quota_wait")
            if not state.get("export_id"):
                if state.get("stage") in {"submitting", "submission_unknown"}:
                    raise ExportError("github_export_submission_unknown")
                moment = run.now() if callable(run.now) else datetime.now(UTC)
                state.update(stage="submitting", submitted_at=moment.astimezone(UTC).isoformat())
                save()
                # The worker commits this intent before requesting the next
                # page and hence before the export is submitted externally.
                yield publish()
                try:
                    created = export_http.create(transport, bearer)
                except SourceError as exc:
                    state["stage"] = ("quota_wait" if exc.code == "github_rate_limited" else "rejected"
                                      if exc.status in (401, 403, 404, 422) else "submission_unknown")
                    state["error"] = exc.code
                    if exc.retry_after:
                        state["retry_after_seconds"] = int(exc.retry_after)
                    save()
                    if exc.code == "github_rate_limited":
                        raise ExportError("github_export_quota_wait") from None
                    if exc.status in (401, 403, 404, 422):
                        raise
                    raise ExportError("github_export_submission_unknown") from None
                state.update(created)
                save()
                run.generated_at = state.get("as_of")
                yield publish(waiting=True, reason="GITHUB_EXPORT_QUEUED")
                return True
        if state.get("stage") in {"submitting", "submission_unknown"} or not state.get("export_id"):
            raise ExportError("github_export_submission_unknown")
        run.generated_at = state.get("as_of")
        if state.get("warnings"):
            current["warnings"] = list(state["warnings"])
            run.degrade("PARTIAL", "github_inventory_metadata_incomplete")
        known = state.get("as_of")
        location = export_http.poll(transport, bearer, state)
        if state.get("as_of") != known:
            # GitHub documents as_of as nullable until the snapshot is taken.
            run.generated_at = state["as_of"]
            save()
        if location is None:
            yield publish(waiting=True, reason="GITHUB_EXPORT_QUEUED")
            return True
        projection = Projection(spec, export=state["export_id"], generated_at=state.get("as_of"), value_context=value_context)
        cursor, expected = state.get("rows", 0), state.get("prefix")
        if (isinstance(cursor, bool) or not isinstance(cursor, int) or cursor < 0
                or cursor and (not isinstance(expected, str) or len(expected) != 64)):
            raise ExportError("github_export_invalid_cursor")
        pending, digest, index = [], hashlib.sha256(), 0
        state["stage"] = "reading"
        save()
        with closing(export_http.download(transport, location)) as chunks:
            for index, raw in rows(chunks, check=budget):
                records = projection.project(index, raw)
                if any(omission.reason == "INVALID_PROVIDER_DIGEST" for record in records for omission in record.omissions):
                    run.degrade("PARTIAL", "invalid_provider_digest")
                    current["warnings"] = sorted(set(current["warnings"] + ["invalid_provider_digest"]))
                _prefix(digest, records)
                # Drop the transient CSV row (including optional provider
                # hash) before returning control to the worker.
                del raw
                if index <= cursor:
                    if index == cursor and digest.hexdigest() != expected:
                        raise ExportError("github_export_content_changed")
                    continue
                pending.extend(records)
                if (index - cursor) % spec.options.page_size == 0:
                    state.update(rows=index, prefix=digest.hexdigest())
                    current["pages"] += 1
                    current["count"] += len(pending)
                    current["received_count"] = index
                    yield publish(pending)
                    pending = []
        if index < cursor:
            raise ExportError("github_export_content_changed")
        current["count"] += len(pending)
        current["received_count"] = index
        current["pages"] += 1
        state.update(stage="complete", rows=index, prefix=digest.hexdigest())
        current.update(status="complete", next_path=None)
        pending.extend(_discovered(spec, broker))
        pending.append(report(spec, run, current, generated_at=state.get("as_of")))
        yield publish(pending)
        # The worker has now committed the final source page and checkpoint.
        save()
        return False
    except SourceError as exc:
        if exc.code in {"github_unavailable", "github_rate_limited", "github_export_download_expired", "github_export_dns_unavailable"}:
            # An existing export is retained; signed URLs are freshly polled.
            yield publish(waiting=True, reason=exc.code.upper(), retry_after=exc.retry_after or 30)
            return True
        code = "github_export_unavailable_or_not_authorized" if exc.code == "github_http_404" else exc.code
        state["error"] = code
        if state.get("stage") not in {"submitting", "submission_unknown", "quota_wait", "rejected"}:
            state["stage"] = "failed"
        save()
        current.update(status="failed", error=code)
        run.degrade("PARTIAL", code)
        yield publish([*_discovered(spec, broker), report(spec, run, current)])
        return False


def _discovered(spec, broker):
    # Reuse the existing installation evidence projection; import at call time
    # to keep the adapter and this specialized task independent on import.
    from .adapter import _installation_records
    return _installation_records(spec, broker.discovered())
