"""Explicit metadata collector execution contract, independent of the worker.

Provider modules keep their native collect_pages entry points. Registration
declares which optional worker services they accept; a parameter name alone
does not establish support; the registry declares which adapters accept value_context.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol

# errors.py, not store.py: the runtime contract must not pull in SQLAlchemy.
from cremore.coverage.errors import CoverageError
from cremore.coverage.metadata_models import MetadataConnectionSpec, MetadataPage

RecordReader = Callable[[], Iterable[dict[str, Any]]]


class ProviderAdapter(Protocol):
    # Native adapters accept different test transports and optional services.
    # CollectorRuntime is the common, typed entry point for callers.
    collect_pages: Callable[..., Iterable[MetadataPage]]

    def validate_spec(self, spec: MetadataConnectionSpec) -> None: ...


class RecollectionPlanner(Protocol):
    def __call__(
        self, records: Iterable[dict[str, Any]], *, scope_id: str | None = None,
        operations: list[str] | None = None, include_unverified: bool = False,
    ) -> dict[str, Any]: ...


class RecordComparer(Protocol):
    def __call__(
        self, before: Iterable[dict[str, Any]], after: Iterable[dict[str, Any]], *,
        spec: MetadataConnectionSpec, scope_id: str | None = None,
    ) -> dict[str, Any] | list[dict[str, Any]]: ...


@dataclass(frozen=True, slots=True, kw_only=True)
class CollectionContext:
    """Per-attempt services; never serialize this object into task state."""

    secrets: dict[str, str] = field(repr=False)
    checkpoint: dict[str, Any]
    check: Callable[[], None] = field(repr=False)
    read_records: RecordReader = field(repr=False)
    value_context: dict[str, Any] | None = field(default=None, repr=False)
    recollection_plan: dict[str, Any] | None = field(default=None, repr=False)
    # cremore.identity.keys.Digester: identity collectors digest emails and logins
    # with it and never see the key.
    identity_digest: Callable[[str], str | None] | None = field(default=None, repr=False)
    export_control: Any | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True, kw_only=True)
class CollectorRuntime:
    adapter: ProviderAdapter = field(repr=False)
    uses_value_context: bool = False
    uses_identity_digest: bool = False
    uses_export_control: bool = False
    planner: RecollectionPlanner | None = field(default=None, repr=False)
    comparison: RecordComparer | None = field(default=None, repr=False)
    # Secret roles a run can do without; one that cannot be resolved is left out.
    optional_secret_roles: frozenset[str] = frozenset()

    @property
    def supports_recollection(self) -> bool:
        return self.planner is not None

    @property
    def supports_comparison(self) -> bool:
        return self.comparison is not None

    def compare_records(
        self, before: Iterable[dict[str, Any]], after: Iterable[dict[str, Any]], *,
        spec: MetadataConnectionSpec, scope_id: str | None = None,
    ) -> dict[str, Any] | list[dict[str, Any]]:
        """Compare committed runs in chronological order using the native output."""
        if self.comparison is None:
            raise CoverageError("METADATA_COMPARISON_UNSUPPORTED")
        return self.comparison(before, after, spec=spec, scope_id=scope_id)

    def validate_spec(self, spec: MetadataConnectionSpec) -> None:
        try:
            self.adapter.validate_spec(spec)
        except CoverageError:
            raise
        except (TypeError, ValueError):
            raise CoverageError("INVALID_METADATA_PROVIDER_SCOPE") from None

    def plan_recollection(
        self, records: Iterable[dict[str, Any]], *, scope_id: str | None = None,
        operations: list[str] | None = None, include_unverified: bool = False,
    ) -> dict[str, Any]:
        if self.planner is None:
            raise CoverageError("METADATA_RECOLLECTION_UNSUPPORTED")
        return self.planner(records, scope_id=scope_id, operations=operations,
                            include_unverified=include_unverified)

    def collect(
        self, spec: MetadataConnectionSpec, context: CollectionContext,
    ) -> Iterable[MetadataPage]:
        """Return the lazy stream; the caller owns validation and persistence."""
        kwargs: dict[str, Any] = {
            "secrets": context.secrets, "checkpoint": context.checkpoint,
            "check": context.check, "read_records": context.read_records,
        }
        if self.uses_value_context:
            kwargs["value_context"] = context.value_context
        elif context.value_context is not None:
            raise CoverageError("METADATA_VALUE_CONTEXT_UNSUPPORTED")
        if context.recollection_plan is not None:
            if not self.supports_recollection:
                raise CoverageError("METADATA_RECOLLECTION_UNSUPPORTED")
            kwargs["recollection_plan"] = context.recollection_plan
        if self.uses_identity_digest:
            if context.identity_digest is None:
                raise CoverageError("IDENTITY_KEY_UNAVAILABLE")
            kwargs["identity_digest"] = context.identity_digest
        if context.export_control is not None:
            if not self.uses_export_control:
                raise CoverageError("METADATA_EXPORT_CONTROL_UNSUPPORTED")
            kwargs["export_control"] = context.export_control
        return self.adapter.collect_pages(spec, **kwargs)
