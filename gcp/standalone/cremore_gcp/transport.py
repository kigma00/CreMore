"""The shared, safe Google API error contract."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol


class ApiError(Exception):
    """Sanitized HTTP failure: no response body, URL, or token is retained."""

    def __init__(self, code: str, *, retry_after: float | None = None):
        self.code = code
        self.retry_after = retry_after
        super().__init__(code)


class JsonTransport(Protocol):
    def get(self, url: str, params: Mapping[str, str | int] | None = None) -> dict[str, Any]: ...


def _forbidden_code(payload: Any) -> str:
    """Keep only a known provider reason; never retain the error response."""
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            details = error.get("details")
            if isinstance(details, list) and any(
                isinstance(detail, dict) and detail.get("reason") == "SERVICE_DISABLED"
                for detail in details
            ):
                return "api_disabled"
    return "permission_denied_or_api_disabled"
