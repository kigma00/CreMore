"""aws metadata-only resource listing."""
from __future__ import annotations

from cremore.collectors.base import CollectorError, RequestBudget, error_label
from cremore.scanning.catalog_projection import MAX_LISTED
from cremore.scanning.scope import resource


def _bucket(kind, cid, name: str, account_id: str, now, *, partition: str = "aws",
            visible: bool = True, reason: str | None = None, **extra) -> dict:
    return resource(kind, cid, "S3_BUCKET", name, name, f"arn:{partition}:s3:::{name}", "aws", now=now,
                    account_id=account_id or None, list_visibility="VISIBLE" if visible else "DENIED",
                    reason_code=reason, **extra)


def _head(client, name: str, budget: RequestBudget) -> tuple[bool, str | None]:
    budget.consume()
    try:
        client.head_bucket(Bucket=name)
        return True, None
    except Exception as exc:  # noqa: BLE001 -- Provider failures retain incomplete visibility and safe labels, never confirmed absence.
        return False, "INSUFFICIENT_PERMISSION" if error_label(exc) in ("403", "AccessDenied", "Forbidden") else error_label(exc)


def _aws(payload, kind, cid, client, now, budget: RequestBudget, *, partition: str = "aws") -> tuple[list[dict], str]:
    if partition not in ("aws", "aws-cn", "aws-us-gov", "aws-eusc"):
        raise CollectorError("AWS_PARTITION_UNAVAILABLE")
    account = str(payload.get("account_id") or "")
    reference = payload.get("reference")
    if reference:
        if kind == "source" and reference != payload.get("bucket"):
            return [_bucket(kind, cid, reference, account, now, partition=partition,
                            visible=False, reason="OUT_OF_CONNECTION_SCOPE")], "PARTIAL"
        visible, reason = _head(client, reference, budget)
        return [_bucket(kind, cid, reference, account, now, partition=partition, visible=visible, reason=reason)], "PARTIAL"
    if kind == "source":
        name = payload.get("bucket", "")
        visible, reason = _head(client, name, budget)
        return [_bucket(kind, cid, name, account, now, partition=partition, visible=visible, reason=reason)], "COMPLETE"
    out, cursor, seen = [], None, set()
    while len(out) < MAX_LISTED:
        budget.consume()
        kwargs = {"MaxBuckets": 1000}
        if cursor:
            kwargs["ContinuationToken"] = cursor
        try:
            listed = client.list_buckets(**kwargs)
        except Exception as exc:
            raise CollectorError("S3_LIST_FAILED", error_label(exc)) from exc
        if not isinstance(listed, dict) or not isinstance(listed.get("Buckets", []), list):
            raise CollectorError("S3_LIST_FAILED", "invalid listing response")
        for b in listed.get("Buckets", []):
            name = b.get("Name")
            if name:
                created = b.get("CreationDate")
                out.append(_bucket(kind, cid, name, account, now, partition=partition,
                                   region=b.get("BucketRegion") or None,
                                   last_edited_at=created.isoformat() if hasattr(created, "isoformat") else None))
            if len(out) > MAX_LISTED:
                return out[:MAX_LISTED], "PARTIAL"
        cursor = listed.get("ContinuationToken")
        if not cursor:
            return out, "COMPLETE"
        if cursor in seen:
            return out, "PARTIAL"
        seen.add(cursor)
    return out, "PARTIAL"
