"""SIEM adapters receive sanitized events, never repositories or scan credentials."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

EVENT_FAMILIES = ("finding", "connection", "collection", "platform", "siem", "identity", "coverage", "audit")


def event_family(event_type) -> str:
    """The part of an event type a sink can label by, e.g. a Splunk sourcetype."""
    family = event_type.split(".", 1)[0] if isinstance(event_type, str) else ""
    return family if family in EVENT_FAMILIES else "other"


class DeliveryError(Exception):
    """A failed delivery. The dispatcher records a fixed code, not exception text."""

    def __init__(self, code: str = "DELIVERY_FAILED", *, retry_after_seconds: int | None = None):
        self.code = code
        # Provider hints may extend, never shorten, the dispatcher's backoff.
        self.retry_after_seconds = (min(86400, max(0, retry_after_seconds))
                                    if type(retry_after_seconds) is int else None)
        super().__init__(code)


class Sink(Protocol):
    def send(self, event: dict) -> None:
        """Return after acceptance, or raise; retries retain the same event_id."""
        ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class SinkProvider:
    id: str
    build: Callable[[Mapping[str, object]], Sink]
    api_version: int = 1
    event_schema_versions: tuple[int, ...] = (1,)
