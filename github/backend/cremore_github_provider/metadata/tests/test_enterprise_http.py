"""Actual token broker and HTTP adapter against a local, scripted transport."""

import base64
import json
from datetime import timedelta

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cremore_github_provider.metadata import adapter
from cremore_github_provider.metadata.snapshot import organization_roster

from .fake import (
    ENTERPRISE,
    ORG,
    OTHER_ORG,
    enterprise_responses,
    enterprise_spec,
    export_csv,
    org_responses,
)
from .test_adapter import NOW


def test_two_organizations_use_their_own_installations_and_reach_credential_sources(monkeypatch):
    spec = enterprise_spec(options={"requests_per_second": 100.0, "burst": 100})
    responses = enterprise_responses(window=adapter._window(spec, NOW.isoformat()), orgs=(ORG, OTHER_ORG))
    # The legacy fixture keys /installation/repositories only by path. Real
    # GitHub scopes it by bearer as well, so script each organization separately.
    org_pages = {org: json.loads(json.dumps(org_responses(ORG)).replace(ORG, org)) for org in (ORG, OTHER_ORG)}
    installations = {ENTERPRISE: 100, ORG: 101, OTHER_ORG: 102}
    tokens = {"test-token-" + str(value): name for name, value in installations.items()}
    calls = []

    def request(req):
        path = req.url.raw_path.decode()
        bearer = req.headers.get("Authorization", "").removeprefix("Bearer ")
        calls.append((req.method, path, tokens.get(bearer, "app")))
        if path == "/app":
            assert bearer not in tokens  # the App JWT, never an installation token
            return httpx.Response(200, json={"id": 12345, "client_id": "Iv1.8a61f9b3a7aba766", "slug": "cremore",
                                             "name": "CreMore", "owner": {"login": ORG, "type": "Organization"},
                                             "permissions": {"organization_administration": "read"}})
        for name, iid in installations.items():
            discovery = f"/enterprises/{name}/installation" if name == ENTERPRISE else f"/orgs/{name}/installation"
            if path == discovery:
                return httpx.Response(200, json={"id": iid, "app_id": 12345, "permissions": {},
                    "target_type": "Enterprise" if name == ENTERPRISE else "Organization",
                    "account": {"login": name}})
            if path == f"/app/installations/{iid}":
                assert bearer not in tokens  # read with the App JWT before a read-only token is asked for
                return httpx.Response(200, json={"id": iid, "permissions": {
                    "organization_administration": "read", "organization_personal_access_tokens": "write"}})
            if path == f"/app/installations/{iid}/access_tokens":
                assert req.method == "POST"
                wanted = json.loads(req.content or b"{}").get("permissions")
                # Organization tokens read only; the enterprise one keeps what the installation holds (unconfirmed
                # whether GitHub takes enterprise permissions at read).
                assert (wanted is None) if name == ENTERPRISE else set(wanted.values()) == {"read"}
                return httpx.Response(201, json={"token": "test-token-" + str(iid), "permissions": wanted or {
                    "enterprise_organization_installations": "read"}, "expires_at": (NOW + timedelta(hours=1)).isoformat()})
        name = tokens[bearer]
        if path == f"/enterprises/{ENTERPRISE}/credentials/exports":
            assert name == ENTERPRISE and req.method == "POST"
            return httpx.Response(202, json={"export_id": "export-1", "status": "queued", "as_of": "2026-03-02T00:00:00Z"},
                                  headers=responses[path][1])
        if path == f"/enterprises/{ENTERPRISE}/credentials/exports/export-1":
            assert name == ENTERPRISE
            return httpx.Response(302, headers={"location": "https://download.example/export"})
        if name == ENTERPRISE:
            assert path.startswith("/enterprises/")
            value = responses[path]
        else:
            assert not path.startswith("/enterprises/")
            value = org_pages[name][path]
        if isinstance(value, tuple):
            return httpx.Response(200, json=value[0], headers=value[1])
        return httpx.Response(200, json=value)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    secrets = {"app_id": "12345", "private_key": base64.b64encode(pem).decode()}
    body = export_csv(responses[f"/enterprises/{ENTERPRISE}/credentials/exports"][0])
    monkeypatch.setattr("cremore_github_provider.metadata.export_http.download", lambda *a, **kw: (chunk for chunk in [body]))
    with httpx.Client(transport=httpx.MockTransport(request)) as client:
        pages = list(adapter.collect_pages(spec, secrets=secrets, checkpoint={}, check=lambda: None,
                                           client=client, now=lambda: NOW))
        assert pages[-1].status == "WAITING"
        committed = [row.model_dump() for page in pages for row in page.records]
        pages += list(adapter.collect_pages(spec, secrets=secrets, checkpoint=pages[-1].checkpoint,
            read_records=lambda: iter(committed), check=lambda: None, client=client, now=lambda: NOW))
    assert pages[-1].status == "PARTIAL"
    assert "GITHUB_INVENTORY_METADATA_INCOMPLETE" in pages[-1].reasons
    roster = organization_roster(row.model_dump() for page in pages for row in page.records)
    assert [row["org"] for row in roster["items"]] == [ORG, OTHER_ORG]
    for org in (ORG, OTHER_ORG):
        assert ("GET", f"/orgs/{org}/personal-access-tokens?per_page=100", org) in calls
    assert sum(method == "POST" and path.endswith("/exports") for method, path, _ in calls) == 1
    for org in (ORG, OTHER_ORG):
        assert sum(method == "POST" and path == f"/app/installations/{installations[org]}/access_tokens"
                   for method, path, _ in calls) == 1
