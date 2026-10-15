"""Bounded root-list health checks for token-authenticated content sources."""

from cremore.collectors.base import CollectorError, RequestBudget
from cremore.collectors.credential_result import ACTIVE, INDETERMINATE, REJECTED, CredentialCheck


def check_roots(roots, payload, client) -> CredentialCheck:
    try:
        next(iter(roots(payload, client, RequestBudget(3))), None)
        return CredentialCheck(ACTIVE, detail={
            "credential_mode": "PROVIDER_TOKEN", "refresh_supported": False,
        })
    except CollectorError as exc:
        return CredentialCheck(REJECTED if exc.detail == "401" else INDETERMINATE, error=exc.code)
    except Exception:  # noqa: BLE001 -- Expose a safe code, never credential-bearing provider exception text.
        return CredentialCheck(INDETERMINATE, error="SOURCE_IDENTITY_CHECK_FAILED")
