"""Google ADC for both content and inventory workers, with safe diagnostics."""

from __future__ import annotations

import threading


class GcpAuthError(ValueError):
    def __init__(self, code: str, retry_after: float | None = None):
        self.code = code
        # Seconds Google asked to wait (a numeric Retry-After), when it said so.
        self.retry_after = retry_after
        super().__init__(code)


# Token-service failures that mean "try again later", not "reauthorize": a collecting
# worker waits and resumes its run from the checkpoint instead of ending it. A one-time
# authorization code is never retried; the API reports the code and the flow restarts.
# GCP_OAUTH_NETWORK_OR_RESPONSE_FAILED keeps its name for the dashboard label but now
# means only an unreachable or interrupted token service (a malformed body is invalid).
TRANSIENT_AUTH_CODES = frozenset({"GCP_OAUTH_RATE_LIMITED", "GCP_OAUTH_TEMPORARILY_UNAVAILABLE",
                                  "GCP_OAUTH_NETWORK_OR_RESPONSE_FAILED", "GCP_AUTH_NETWORK_FAILED"})


def adc_token(scopes=("https://www.googleapis.com/auth/cloud-platform",)):
    """Resolve lazily in the worker. Never return credential files or SDK errors.

    A scan's concurrent readers share the source: one of them refreshes while the
    others wait, then take the same token (google-auth credentials are not thread-safe).
    """
    credentials = None
    lock = threading.Lock()

    def token():
        nonlocal credentials
        try:
            import google.auth
            from google.auth.exceptions import DefaultCredentialsError, RefreshError, TransportError
            from google.auth.transport.requests import Request
        except ImportError:
            raise GcpAuthError("GCP_AUTH_DEPENDENCY_MISSING") from None
        with lock:
            if credentials is None:
                try:
                    credentials, _ = google.auth.default(scopes=list(scopes))
                except (DefaultCredentialsError, OSError, ValueError):
                    raise GcpAuthError("GCP_ADC_NOT_CONFIGURED") from None
            try:
                if not credentials.valid:
                    request = Request()
                    try:
                        credentials.refresh(lambda *args, **kwargs: request(
                            *args, **{**kwargs, "timeout": 30}))
                    finally:
                        request.session.close()
            except RefreshError:
                raise GcpAuthError("GCP_ADC_REFRESH_FAILED") from None
            except (TransportError, OSError):
                raise GcpAuthError("GCP_AUTH_NETWORK_FAILED") from None
            if not isinstance(credentials.token, str) or not credentials.token:
                raise GcpAuthError("GCP_ADC_TOKEN_UNAVAILABLE")
            return credentials.token

    return token
