"""Offline cursor-collection contract experiment for API Access keys/tokens.

No HTTP client, credential loading, logging, or output storage is provided here.
The supplied fetch_page callable owns transport. Records are retained as observed;
an eventual collector must select metadata fields before persisting them.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Page:
    status: int
    body: Any


@dataclass
class Collection:
    records: list[dict[str, Any]] = field(default_factory=list)
    coverage: str = "failed"
    reason: str | None = None
    requests: int = 0
    pages: int = 0
    invalid_records: int = 0
    duplicate_ids: int = 0


def collect_cursor_pages(
    fetch_page: Callable[[dict[str, Any]], Page],
    params: dict[str, Any],
    *,
    max_pages: int = 100,
    max_records: int = 10000,
) -> Collection:
    """Evaluate data/links pagination, preserving parameters and partial results.

    `complete` describes traversal of this one requested collection, not an atomic
    snapshot or organization-wide credential coverage. No retries are performed.
    Duplicate ID observations are retained and make coverage unverified.
    """
    if type(max_pages) is not int or max_pages < 1:
        raise ValueError("max_pages must be a positive integer")
    if type(max_records) is not int or max_records < 1:
        raise ValueError("max_records must be a positive integer")
    original = dict(params)
    cursor = original.pop("cursor", None)
    if cursor is not None and not isinstance(cursor, str):
        raise ValueError("cursor must be a string or None")
    seen_cursors = {cursor} if cursor else set()
    seen_ids = set()
    result = Collection()

    def stop(reason):
        result.coverage = "partial" if result.pages else "failed"
        result.reason = reason
        return result

    while result.pages < max_pages:
        query = dict(original)
        if cursor:
            query["cursor"] = cursor
        result.requests += 1
        try:
            page = fetch_page(query)
        except Exception:  # noqa: BLE001 - CLI/QA boundary must suppress credential-bearing errors.
            # Transport exceptions may contain URLs, headers, or response bodies.
            return stop("fetch_error")
        if not isinstance(page, Page) or type(page.status) is not int:
            return stop("invalid_transport_response")
        if page.status != 200:
            if 100 <= page.status <= 599:
                return stop("http_" + str(page.status))
            return stop("invalid_http_status")
        if not isinstance(page.body, dict) or not isinstance(page.body.get("data"), list):
            return stop("unexpected_collection_shape")

        result.pages += 1
        for record in page.body["data"]:
            if not isinstance(record, dict):
                result.invalid_records += 1
                continue
            record_id = record.get("id")
            if not isinstance(record_id, str) or not record_id.strip():
                result.invalid_records += 1
                continue
            if len(result.records) >= max_records:
                return stop("record_limit")
            if record_id in seen_ids:
                result.duplicate_ids += 1
            seen_ids.add(record_id)
            result.records.append(record)

        links = page.body.get("links")
        if not isinstance(links, dict):
            return stop("missing_pagination_contract")
        next_cursor = links.get("next")
        if next_cursor is not None and not isinstance(next_cursor, str):
            return stop("unexpected_cursor_type")
        if not next_cursor:
            if result.invalid_records:
                return stop("invalid_records")
            result.coverage = "unverified" if result.duplicate_ids else "complete"
            result.reason = "duplicate_ids" if result.duplicate_ids else None
            return result
        if next_cursor in seen_cursors:
            return stop("repeated_cursor")
        if len(result.records) >= max_records:
            return stop("record_limit")
        seen_cursors.add(next_cursor)
        cursor = next_cursor

    return stop("page_limit")
