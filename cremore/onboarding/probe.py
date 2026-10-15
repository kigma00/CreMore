"""Read-only permission probes for provider checks (cremore.onboarding.check).

A provider that cannot list the permissions a credential holds is asked for one
small read that needs the permission: success means held, a refusal means missing,
anything else is reported as the status it was. Pure: provider libraries import it.
"""

from __future__ import annotations

from cremore.http_client import bounded_request

REFUSED = (401, 403)


def probe(client, method, url, *, ok=(200,), missing=REFUSED, max_bytes=1 << 20, **kwargs):
    """``(status, detail, response)`` for one read; the body is bounded and never logged."""
    try:
        response = bounded_request(client, method, url, max_response_bytes=max_bytes, follow_redirects=False,
                                   **kwargs)
    except Exception as exc:  # noqa: BLE001 -- transport failures become a code, never their text
        return "ERROR", "REQUEST_FAILED" if not getattr(exc, "code", None) else exc.code, None
    code = getattr(response, "status_code", 0)
    if code in ok:
        return "GRANTED", None, response
    if code in missing:
        return "MISSING", f"HTTP_{code}", response
    return "NOT_REPORTED", f"HTTP_{code}", response


def item(permission, result, subject=None) -> dict:
    status, detail, _response = result
    row = {"permission": permission, "status": status}
    if detail:
        row["detail"] = detail
    if subject:
        row["subject"] = subject
    return row


def all_items(permissions, status, detail=None) -> list[dict]:
    return [{"permission": name, "status": status, **({"detail": detail} if detail else {})} for name in permissions]


def json_body(response):
    try:
        return response.json() if response is not None and response.content else None
    except ValueError:
        return None
