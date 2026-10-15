"""GET /app: the App behind the key is confirmed and recorded before any installation is used."""

import base64
import json
from datetime import timedelta

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cremore_github_provider.metadata import adapter
from cremore_github_provider.metadata.http import SourceError
from cremore_github_provider.metadata.normalization import record_values
from cremore_github_provider.metadata.snapshot import organization_roster

from .fake import (
    ENTERPRISE,
    ORG,
    SECRETS,
    FakeBroker,
    FakeTransport,
    enterprise_responses,
    enterprise_spec,
    org_responses,
    spec,
)
from .test_adapter import NOW, drive


def test_app_identity_record_opens_every_run_and_stays_out_of_the_organization_roster():
    connection = enterprise_spec()
    _t, broker, records, _s, final = drive(connection, enterprise_responses(window=adapter._window(connection, NOW.isoformat())),
                                           enterprise=ENTERPRISE)
    assert records[0]["identity"]["object_id"] == "app:12345"
    values = record_values(records[0])
    assert (values["slug"], values["owner"], values["client_id"]) == ("cremore-metadata", ORG, "Iv23liSynthetic00000")
    assert {grant["name"]: grant["actions"] for grant in records[0]["permissions"]}[
        "organization_personal_access_tokens"] == ["read"]
    report = next(row for row in records if row["record_type"] == "operation_report"
                  and row["provenance"]["operation"] == "github.app")
    assert report["status"] == "COMPLETE" and broker.app_calls == 1 and final is not None
    assert ENTERPRISE not in [row["org"] for row in organization_roster(records)["items"]]
    assert adapter.native_snapshots(records)["enterprise"]["app"]["slug"] == "cremore-metadata"


def test_app_identity_record_failure_stops_the_run_before_any_installation_is_used():
    transport, broker = FakeTransport(org_responses()), FakeBroker(app="github_app_identity_mismatch")
    pages = list(adapter.collect_pages(spec(), secrets=SECRETS, checkpoint={}, check=lambda: None,
                                       transport=transport, broker=broker, now=lambda: NOW))
    assert pages[-1].status == "FAILED"
    assert {"GITHUB_APP_IDENTITY_MISMATCH", "COLLECTION_STOPPED"} <= set(pages[-1].reasons)
    assert not transport.calls and not broker.issued


@pytest.mark.parametrize("code", ["github_app_private_key_invalid", "github_app_id_invalid",
                                  "github_app_identity_mismatch", "github_http_401"])
def test_the_app_credential_failing_fails_the_run(code):
    # A misconfigured App is a failed collection (the job fails), not a partial one.
    transport, broker = FakeTransport(org_responses()), FakeBroker(app=code)
    pages = list(adapter.collect_pages(spec(), secrets=SECRETS, checkpoint={}, check=lambda: None,
                                       transport=transport, broker=broker, now=lambda: NOW))
    assert pages[-1].status == "FAILED" and {code.upper(), "COLLECTION_STOPPED"} <= set(pages[-1].reasons)
    assert not transport.calls and not broker.issued


def test_the_app_credential_failing_on_a_later_read_fails_the_run():
    class KeyFails(FakeBroker):
        def token_for(self, scope, name=""):
            raise SourceError("github_app_private_key_invalid")

    transport = FakeTransport(org_responses())
    pages = list(adapter.collect_pages(spec(), secrets=SECRETS, checkpoint={}, check=lambda: None,
                                       transport=transport, broker=KeyFails(), now=lambda: NOW))
    assert pages[-1].status == "FAILED" and "GITHUB_APP_PRIVATE_KEY_INVALID" in pages[-1].reasons
    assert not transport.calls


HELD = {"organization_personal_access_tokens": "write", "metadata": "read"}  # an App that may also revoke


def _http_run(app_id, *, answered_client_id="Iv1.8a61f9b3a7aba766", asked=None):
    calls = []

    def request(req):
        path = req.url.raw_path.decode()
        calls.append((req.method, path))
        if path == "/app":
            return httpx.Response(200, json={"id": 12345, "client_id": answered_client_id, "slug": "cremore",
                                             "name": "CreMore", "owner": {"login": ORG, "type": "Organization"},
                                             "permissions": HELD})
        if path == f"/orgs/{ORG}/installation":
            return httpx.Response(200, json={"id": 101, "app_id": 12345, "permissions": HELD,
                                             "target_type": "Organization", "account": {"login": ORG}})
        if path == "/app/installations/101":
            return httpx.Response(200, json={"id": 101, "permissions": HELD})
        if path == "/app/installations/101/access_tokens":
            wanted = json.loads(req.content)["permissions"]
            if asked is not None:
                asked.append(wanted)
            return httpx.Response(201, json={"token": "test-token-101", "permissions": wanted,
                                             "expires_at": (NOW + timedelta(hours=1)).isoformat()})
        value = org_responses(ORG).get(path)
        if value is None:
            return httpx.Response(404, json={})
        return httpx.Response(200, json=value[0] if isinstance(value, tuple) else value)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    connection = spec(options={"sources": ["org_fgpat"], "requests_per_second": 100.0, "burst": 100})
    with httpx.Client(transport=httpx.MockTransport(request)) as client:
        pages = list(adapter.collect_pages(connection, secrets={"app_id": app_id, "private_key": base64.b64encode(key).decode()},
                                           checkpoint={}, check=lambda: None, client=client, now=lambda: NOW))
    return pages, calls


def test_a_client_id_resolves_the_numeric_app_id_before_installations_are_compared():
    asked = []
    pages, calls = _http_run("Iv1.8a61f9b3a7aba766", asked=asked)
    assert calls[0] == ("GET", "/app") and calls.count(("GET", "/app")) == 1
    assert ("POST", "/app/installations/101/access_tokens") in calls
    assert pages[-1].status == "COMPLETE", pages[-1].reasons
    # The collection's token reads, though the App may revoke tokens too.
    assert asked == [{"organization_personal_access_tokens": "read", "metadata": "read"}]
    numeric, numeric_calls = _http_run("12345")
    assert numeric[-1].status == "COMPLETE" and numeric_calls.count(("GET", "/app")) == 1


def test_app_identity_mismatch_requests_no_installation_token():
    pages, calls = _http_run("Iv1.8a61f9b3a7aba766", answered_client_id="Iv1.0000000000000000")
    assert calls == [("GET", "/app")]
    assert "GITHUB_APP_IDENTITY_MISMATCH" in pages[-1].reasons
