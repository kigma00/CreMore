"""Built-in detectors an administrator turned off for this installation.

Each disabled detector is its own installation setting (``detection_detector:<id>``),
so turning two detectors off at once never loses either change. The scan engine
leaves disabled detectors out from its next rule refresh (workers refresh every
minute), which also changes the detection digest: cached results, value comparisons
and the customer-side hasher follow the new policy. An exposure a disabled detector
found is never marked removed by a later scan.
"""

from __future__ import annotations

PREFIX = "detection_detector:"


def disabled(repo) -> frozenset[str]:
    return frozenset(row["key"][len(PREFIX):] for row in repo.list_settings(PREFIX)
                     if ((row.get("value") or {}).get("enabled")) is False)


def changes(repo) -> dict:
    """``{detector id: {enabled, updated_by, updated_at}}`` for every detector ever switched."""
    return {row["key"][len(PREFIX):]: {"enabled": (row.get("value") or {}).get("enabled") is not False,
                                        "updated_by": row.get("updated_by"), "updated_at": row.get("updated_at")}
            for row in repo.list_settings(PREFIX)}


def require_known(detector_id: str) -> None:
    from cremore.detection.catalog import builtin_definitions

    if detector_id not in {definition.catalog.id for definition in builtin_definitions()}:
        raise ValueError("DETECTOR_UNKNOWN")


def is_on(record) -> bool:
    """Whether a detector's stored switch (or none) leaves it on."""
    return ((record or {}).get("value") or {}).get("enabled") is not False


def set_enabled(repo, detector_id: str, enabled: bool, actor: str) -> dict:
    require_known(detector_id)
    return repo.put_setting(PREFIX + detector_id, {"enabled": bool(enabled)}, actor)
