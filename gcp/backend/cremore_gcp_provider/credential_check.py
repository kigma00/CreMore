"""Read-only IAM or Storage identity checks for a configured GCP connection."""

from cremore.collectors.base import CollectorError, RequestBudget
from cremore.collectors.credential_result import ACTIVE, INDETERMINATE, REJECTED, CredentialCheck
from cremore_gcp_provider.content import roots
from cremore_gcp_provider.gcp_auth import GcpAuthError


def check_gcp(payload, client) -> CredentialCheck:
    token = payload.get("token", "") or ""
    try:
        # This function checks a content source. IAM inventory has its own
        # onboarding checks; requiring IAM here rejects Storage-only identities.
        next(iter(roots(payload, client, RequestBudget(3))), None)
        return CredentialCheck(ACTIVE, detail={
            "credential_mode": "ADC" if not token else "GOOGLE_OAUTH" if callable(token) else "PROVIDER_TOKEN",
            "refresh_supported": not token or callable(token),
        })
    except CollectorError as exc:
        error = {
            "401": "GCP_AUTHENTICATION_FAILED",
            "403": "GCP_PERMISSION_DENIED_OR_API_DISABLED",
        }.get(exc.detail, exc.code)
        return CredentialCheck(REJECTED if exc.detail == "401" else INDETERMINATE, error=error)
    except GcpAuthError as exc:
        from cremore_gcp_provider.oauth import REAUTH
        return CredentialCheck(REJECTED if exc.code in REAUTH else INDETERMINATE, error=exc.code)
    except Exception:  # noqa: BLE001 -- Expose a safe code, never credential-bearing provider exception text.
        return CredentialCheck(INDETERMINATE, error="SOURCE_IDENTITY_CHECK_FAILED")
