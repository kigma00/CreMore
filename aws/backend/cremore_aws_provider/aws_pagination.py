"""Bounded IAM reads with explicit evidence of pagination completeness."""

from __future__ import annotations


class IamPaginationError(ValueError):
    code = "IAM_PAGINATION_INCOMPLETE"


def iam_pages(call, **kwargs):
    """Yield each page once; incomplete or cyclic pagination is an error."""
    marker, seen = None, set()
    for _ in range(100):
        page = call(**kwargs, **({"Marker": marker} if marker else {}))
        if not isinstance(page, dict) or type(page.get("IsTruncated", False)) is not bool:
            raise IamPaginationError(IamPaginationError.code)
        yield page
        if not page.get("IsTruncated", False):
            return
        marker = page.get("Marker")
        if not isinstance(marker, str) or not marker or len(marker) > 4096 or marker in seen:
            raise IamPaginationError(IamPaginationError.code)
        seen.add(marker)
    raise IamPaginationError(IamPaginationError.code)
