"""Incremental collection without file storage or worker-owned background threads."""

from copy import deepcopy
from dataclasses import dataclass


class CollectionInterrupted(Exception):
    """Carry a worker cancellation/lease failure past native sanitizing boundaries."""

    def __init__(self, cause):
        super().__init__("Collection interrupted")
        self.cause = cause


def check_collection(client):
    callback = getattr(client, "check", None)
    if callback is not None:
        callback()


@dataclass(frozen=True)
class CollectionStep:
    operation: str
    report: dict
    page: dict | None = None
    observations: tuple = ()
    completed: bool = False


def step(operation, report, *, page=None, observations=(), completed=False):
    """Detach emitted evidence from the report that the collector continues mutating."""
    header = {key: value for key, value in report.items() if key != "pages"}
    header["page_count"] = (
        len(report["pages"]) if isinstance(report.get("pages"), list) else report.get("pages", 0)
    )
    return CollectionStep(
        operation,
        deepcopy(header),
        deepcopy(page),
        tuple(deepcopy(observations)),
        completed,
    )


def consume(iterator):
    """Preserve synchronous native return contracts while exposing incremental APIs."""
    while True:
        try:
            next(iterator)
        except StopIteration as completed:
            return completed.value


def completed_report(client, operation, *, identifier=None, body=None):
    callback = getattr(client, "completed_report", None)
    if callback is None:
        return None
    check_collection(client)
    return callback(operation, identifier=identifier, body=body)
