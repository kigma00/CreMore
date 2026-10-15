from types import SimpleNamespace

import pytest

from cremore_gcp_provider.gcp_auth import GcpAuthError, adc_token


def test_adc_failure_is_actionable_and_never_echoes_sdk_text(monkeypatch):
    google = pytest.importorskip("google.auth")
    from google.auth.exceptions import DefaultCredentialsError
    def missing(**_):
        raise DefaultCredentialsError("private-sdk-message-with-token")
    monkeypatch.setattr(google, "default", missing)
    token = adc_token()
    with pytest.raises(GcpAuthError, match="^GCP_ADC_NOT_CONFIGURED$"):
        token()


def test_refresh_failure_and_reusable_valid_token(monkeypatch):
    google = pytest.importorskip("google.auth")
    from google.auth.exceptions import RefreshError
    def refresh(_request):
        raise RefreshError("private-refresh-token")
    credentials = SimpleNamespace(valid=False, token=None, refresh=refresh)
    monkeypatch.setattr(google, "default", lambda **_: (credentials, None))
    token = adc_token()
    with pytest.raises(GcpAuthError, match="^GCP_ADC_REFRESH_FAILED$"):
        token()
    credentials.valid, credentials.token = True, "synthetic-access-token"
    assert token() == token() == "synthetic-access-token"


def test_gcs_check_retains_adc_error_and_refresh_evidence(monkeypatch):
    from cremore.collectors.credential_check import CredentialCheck, run_credential_check
    from cremore_gcp_provider import content
    def missing():
        raise GcpAuthError("GCP_ADC_NOT_CONFIGURED")
    monkeypatch.setattr(content, "adc_token", lambda: missing)
    result = run_credential_check({"provider": "gcp", "project": "demo-project"},
                                  http_client_factory=lambda: object())
    assert result.error == "GCP_ADC_NOT_CONFIGURED"
    evidence = CredentialCheck("ACTIVE", detail={"credential_mode": "ADC", "refresh_supported": True}).as_evidence("2026-09-22T00:00:00Z")
    assert evidence["refresh_supported"] and evidence["credential_mode"] == "ADC"


def test_content_project_check_uses_storage_without_requiring_iam_access(monkeypatch):
    import httpx

    from cremore.collectors.credential_check import run_credential_check
    from cremore_gcp_provider import content
    calls = []
    def answer(request):
        calls.append(request)
        return httpx.Response(200, json={"items": []})
    monkeypatch.setattr(content, "adc_token", lambda: lambda: "synthetic-token")
    with httpx.Client(transport=httpx.MockTransport(answer)) as client:
        result = run_credential_check({"provider": "gcp", "project": "demo-project"},
                                      http_client_factory=lambda: client)
    assert result.status == "ACTIVE"
    assert len(calls) == 1
    assert calls[0].url.host == "storage.googleapis.com"
    assert calls[0].url.params["maxResults"] == "100"


def test_concurrent_readers_refresh_adc_once_and_share_the_token(monkeypatch):
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    google = pytest.importorskip("google.auth")
    refreshes, lock = [], threading.Lock()

    class Credentials:
        valid, token = False, None

        def refresh(self, _request):
            with lock:
                refreshes.append(1)
            time.sleep(0.05)  # the other readers arrive while this one waits on Google
            self.token = "synthetic-access-token"
            self.valid = True

    credentials = Credentials()
    monkeypatch.setattr(google, "default", lambda **_: (credentials, None))
    token = adc_token()
    with ThreadPoolExecutor(8) as pool:
        assert list(pool.map(lambda _: token(), range(8))) == ["synthetic-access-token"] * 8
    assert len(refreshes) == 1
