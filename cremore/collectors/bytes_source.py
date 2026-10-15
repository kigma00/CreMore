"""In-memory collector for inline scans and tests."""

from __future__ import annotations

from collections.abc import Iterator

from cremore.collectors.base import CollectedObject
from cremore.detection import ResourceRef


class BytesCollector:
    failed_objects = 0

    def __init__(self, objects: list[CollectedObject]) -> None:
        self._objects = objects

    @classmethod
    def one(cls, data: bytes, *, source_type: str = "inline", resource: str = "inline",
            location: str = "inline", exposure: str = "unknown") -> BytesCollector:
        ref = ResourceRef(source_type=source_type, resource=resource, location=location,
                          metadata={"exposure": exposure})
        return cls([CollectedObject(ref, data)])

    def collect(self) -> Iterator[CollectedObject]:
        yield from self._objects
