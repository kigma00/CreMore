"""Which existing S3 Inventory report a bucket's INVENTORY scan should read.

An Inventory run reads a report AWS already writes, instead of listing the
bucket. CreMore never configures Inventory on a bucket and never creates a
report; it is given a pointer to one and reads it.

The pointer is per connection and per bucket, so it was a JSON object in an
environment variable -- one blob holding every bucket in the installation. The
person who knows which report belongs to which bucket is the one using the
dashboard, and they had to hand an operator a JSON edit to add a single line.
It is a setting now, and each change records who made it.

``SCAN_INVENTORY_MANIFESTS`` still works and still wins: an installation that
wants its bindings fixed in configuration keeps them there, and the dashboard
shows them as fixed rather than pretending they can be edited.

Nothing here provisions anything. A binding is a claim that a report exists at
an exact bucket and key; if it does not, the scan fails rather than falling back
to listing, because a silent fallback would read the whole bucket under a budget
sized for a report.
"""

from __future__ import annotations

import json
import re
import uuid as _uuid

KEY = "inventory_manifests"
# One installation's bindings, bounded so a settings row cannot become a payload.
MAX_BINDINGS = 10_000
MAX_SERIALIZED_BYTES = 4 << 20
MAX_KEY_BYTES = 1024

_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class ManifestBindingError(ValueError):
    """A stable code the dashboard can localize, never a raw value."""


def _identity(value) -> str:
    """``<connection uuid>/<bucket>``, the pair a binding belongs to."""
    try:
        connection, bucket = str(value).split("/", 1)
        connection = str(_uuid.UUID(connection))
    except (ValueError, AttributeError, TypeError):
        raise ManifestBindingError("MANIFEST_IDENTITY_INVALID") from None
    if not _BUCKET.fullmatch(bucket):
        raise ManifestBindingError("MANIFEST_IDENTITY_INVALID")
    return f"{connection}/{bucket}"


def _pointer(value) -> dict:
    """The exact report objects to read, and nothing else.

    Only ``manifest_bucket`` and ``manifest_key`` are accepted: an extra field
    would be a place to put a URL, and this is never fetched over HTTP.
    """
    if (not isinstance(value, dict) or set(value) != {"manifest_bucket", "manifest_key"}
            or not isinstance(value["manifest_bucket"], str)
            or not _BUCKET.fullmatch(value["manifest_bucket"])):
        raise ManifestBindingError("MANIFEST_POINTER_INVALID")
    key = value["manifest_key"]
    if (not isinstance(key, str) or not key or len(key.encode()) > MAX_KEY_BYTES
            or _CONTROL.search(key) or "://" in key
            or not key.endswith("/manifest.json")
            or any(part in ("", ".", "..") for part in key.split("/"))):
        raise ManifestBindingError("MANIFEST_KEY_INVALID")
    return {"manifest_bucket": value["manifest_bucket"], "manifest_key": key}


def normalize(values) -> dict:
    """Validate a whole set of bindings, as a PUT or the environment supplies it."""
    if not isinstance(values, dict) or len(values) > MAX_BINDINGS:
        raise ManifestBindingError("MANIFEST_BINDINGS_INVALID")
    out: dict[str, dict] = {}
    for identity, pointer in values.items():
        normalized = _identity(identity)
        if normalized in out:
            raise ManifestBindingError("MANIFEST_IDENTITY_REPEATED")
        out[normalized] = _pointer(pointer)
    return out


def pinned(settings) -> dict | None:
    """The bindings configuration fixes, or None when it fixes none."""
    raw = getattr(settings, "scan_inventory_manifests", "") or "{}"
    if len(raw.encode()) > MAX_SERIALIZED_BYTES:
        raise ManifestBindingError("MANIFEST_BINDINGS_TOO_LARGE")
    try:
        values = json.loads(raw)
    except (ValueError, TypeError):
        raise ManifestBindingError("MANIFEST_BINDINGS_INVALID") from None
    return normalize(values) or None


def stored(repo) -> dict:
    """The Admin's saved bindings. A binding that no longer validates is dropped.

    Reading a report from a bucket whose name stopped being a bucket name is not
    something to attempt; the scan reports INVENTORY_NOT_CONFIGURED instead.
    """
    record = repo.get_setting(KEY) or {}
    saved = (record.get("value") or {}).get("bindings") or {}
    out: dict[str, dict] = {}
    if isinstance(saved, dict):
        for identity, pointer in list(saved.items())[:MAX_BINDINGS]:
            try:
                out[_identity(identity)] = _pointer(pointer)
            except ManifestBindingError:
                continue
    return out


def record(repo) -> dict:
    """The saved bindings with who last changed them."""
    saved = repo.get_setting(KEY) or {}
    return {"bindings": stored(repo), "updated_by": saved.get("updated_by") or None,
            "updated_at": saved.get("updated_at")}


def bindings(settings, repo) -> dict:
    """What a scan uses: configuration's bindings when it pins any, else the Admin's."""
    fixed = pinned(settings)
    return fixed if fixed is not None else stored(repo)


def config(settings, repo) -> dict:
    """The dashboard view: the bindings in force and whether they can be edited."""
    current = record(repo)
    fixed = pinned(settings)
    return {"bindings": fixed if fixed is not None else current["bindings"],
            "locked": fixed is not None,
            "updated_by": None if fixed is not None else current["updated_by"],
            "updated_at": None if fixed is not None else current["updated_at"]}
