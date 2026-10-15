"""The Microsoft connection end to end with a synthetic Microsoft: a certificate CreMore makes (only its public
part is shown), one sealed envelope for every record of Entra ID, Azure and Azure DevOps, and the worker's
renewal before it expires. Nothing here reaches Microsoft."""

import base64
import datetime as dt
import json
import uuid
from urllib.parse import parse_qs

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from cremore.coverage.store import CoverageStore
from cremore.db.repository import InMemoryRepository
from cremore.onboarding import renewal, service
from cremore.onboarding.onboarding_test import SETTINGS, run_check
from cremore.onboarding.store import ProviderConnectionStore
from cremore.secretstore.resolver import SecretResolver, inject_secret

TENANT = "11111111-2222-4333-8444-555555555555"
CLIENT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
OBJECT = "99999999-8888-4777-8666-555555555555"
OLD_KEY = "12121212-3434-4545-8656-787878787878"
RESOLVER = SecretResolver(sealing_key=SETTINGS.sealing_keys)


def body(**changes):
    return {"provider": "azure", "purposes": ["inventory", "exposure", "vault", "identity"], "auth_method": "certificate",
            "target": {"tenant": TENANT, "storage_account": "acmedata", "key_vaults": ["acme-vault"],
                       "devops_organization": "acme", "devops_project": "Payments"},
            "credential": {"client_id": CLIENT}, **changes}


def microsoft(calls=None, *, certificate=None, app_status=200):
    """Microsoft Entra sign-in, Graph (with the application's own key credentials), Azure and Azure DevOps."""
    calls = [] if calls is None else calls

    def handler(request):
        host, path = request.url.host, request.url.path
        calls.append((request.method, host, path, request.content))
        if host == "login.microsoftonline.com":
            form = parse_qs(request.content.decode())
            assert form["client_id"] == [CLIENT] and form["client_assertion"][0].count(".") == 2
            return httpx.Response(200, json={"access_token": "entra-token", "expires_in": 3600})
        assert request.headers["authorization"] == "Bearer entra-token"
        if host == "graph.microsoft.com" and path.startswith("/v1.0/applications(") and request.method == "GET":
            keys = [{"keyId": OLD_KEY, "type": "AsymmetricX509Cert", "key": certificate()}] if certificate else []
            return httpx.Response(app_status, json={"id": OBJECT, "keyCredentials": keys})
        if path.endswith("/addKey"):
            return httpx.Response(200, json={"keyId": str(uuid.uuid4()), "type": "AsymmetricX509Cert"})
        if path.endswith("/removeKey"):
            return httpx.Response(204)
        if path.endswith("/_apis/graph/users"):
            return httpx.Response(200, json={"value": [{"descriptor": "aad.MDAwMDAw"}]})
        if host == "acmedata.blob.core.windows.net":
            return httpx.Response(200, content=b"<EnumerationResults/>")
        return httpx.Response(200, json={"value": []})

    return lambda: httpx.Client(transport=httpx.MockTransport(handler))


def activated(repo):
    record = service.create(repo, SETTINGS, body(), "admin")
    service.request_check(repo, record["id"], "admin", {"plans": {
        "inventory": {}, "exposure": {}, "vault": {}, "identity": {"people_details": True}}})
    run_check(repo, record, microsoft())
    view = service.activate(repo, SETTINGS, record["id"], {"purposes": {
        "inventory": {}, "exposure": {}, "vault": {}, "identity": {"people_details": True}}}, "admin")
    return record, view


def test_the_certificate_is_made_sealed_and_only_its_public_part_is_shown():
    repo = InMemoryRepository()
    view = service.create(repo, SETTINGS, body(), "admin")
    generated = view["target"]["generated"]
    assert view["target"]["auth"] == {"client_id": CLIENT} and view["credential"] == {"roles": ["credential"],
                                                                                        "reference": False, "shared_with": []}
    certificate = x509.load_pem_x509_certificate(generated["certificate"].encode())
    assert len(generated["thumbprint"]) == 40 and generated["not_after"].endswith("Z")
    assert "PRIVATE KEY" not in json.dumps(view)
    ref = ProviderConnectionStore(repo).get(view["id"])["secret_refs"]["credential"]
    envelope = RESOLVER.resolve(ref)
    assert envelope["client_id"] == CLIENT and envelope["tenant_id"] == TENANT and "PRIVATE KEY" in envelope["private_key"]
    assert certificate.public_bytes(Encoding.PEM).decode() in envelope["private_key"]
    # The client ID must be an application (client) ID; a vault reference cannot stand for a made key.
    for credential, code in (({"client_id": "nope"}, "AZURE_CLIENT_ID_INVALID"),
                             ({"vault_ref": "vault://x/y"}, "CREDENTIAL_REFERENCE_NOT_ALLOWED")):
        with pytest.raises(service.OnboardingError) as refused:
            service.create(repo, SETTINGS, body(credential=credential), "admin")
        assert refused.value.code == code


def test_every_record_of_every_service_signs_in_with_the_one_envelope():
    repo = InMemoryRepository()
    record, view = activated(repo)
    assert view["status"] == "ACTIVE"
    ref = ProviderConnectionStore(repo).get(record["id"])["secret_refs"]["credential"]
    specs = [CoverageStore(repo).get(uuid.UUID(row["id"]))["spec"] for row in view["created"] if row["kind"] == "metadata"]
    assert {spec["provider"] for spec in specs} == {"azure_entra", "azure_key_vault", "entra_id", "azure_devops"}
    for spec in specs:
        assert spec["auth_type"] == "private_key_jwt"
        assert spec["secret_refs"] == {"client_id": ref, "private_key": ref, "tenant_id": ref}
    sources = [repo.get_connection(uuid.UUID(row["id"])) for row in view["created"] if row["kind"] == "content"]
    assert {source.provider for source in sources} == {"azure_blob", "azure_devops"}
    assert {source.secret_ref for source in sources} == {ref}
    # A content scan takes a token for its own Azure service, sent as a bearer.
    for source in sources:
        payload = inject_secret(source.provider, {"provider": source.provider, **source.config,
                                                  "secret_ref": source.secret_ref}, RESOLVER)
        assert payload["token"].bearer
        assert payload["token"].scope == {"azure_blob": "https://storage.azure.com/.default",
                                          "azure_devops": "499b84ac-1321-427f-aa17-267ca6975798/.default"}[source.provider]


def test_a_new_certificate_is_a_new_credential_but_another_app_is_not():
    repo = InMemoryRepository()
    record, view = activated(repo)
    before = service.view(repo, service.get(repo, record["id"]))
    renewed = service.set_credential(repo, SETTINGS, record["id"], {"credential": {"client_id": CLIENT}}, "admin")
    assert renewed["not_updated"] == [] and renewed["checks"]["stale"]
    assert renewed["target"]["generated"]["thumbprint"] != before["target"]["generated"]["thumbprint"]
    source = next(uuid.UUID(row["id"]) for row in view["created"] if row["kind"] == "content")
    assert repo.get_connection(source).secret_ref == ProviderConnectionStore(repo).get(record["id"])["secret_refs"]["credential"]
    with pytest.raises(service.OnboardingError) as refused:
        service.set_credential(repo, SETTINGS, record["id"], {"credential": {"client_id": TENANT}}, "admin")
    assert refused.value.code == "AUTH_SETTINGS_FIXED_WHILE_IN_USE"


def der_of(repo, record):
    pem = ProviderConnectionStore(repo).get(record["id"])["target"]["generated"]["certificate"]
    return base64.b64encode(x509.load_pem_x509_certificate(pem.encode()).public_bytes(Encoding.DER)).decode()


def test_the_worker_renews_the_certificate_before_it_expires_and_retires_the_old_one():
    repo = InMemoryRepository()
    record, view = activated(repo)
    stored = ProviderConnectionStore(repo).get(record["id"])
    until = dt.datetime.fromisoformat(stored["target"]["generated"]["not_after"])
    calls = []
    # Not yet: the certificate has months left.
    assert renewal.sweep(repo, SETTINGS, RESOLVER, microsoft(calls), now=until - dt.timedelta(days=90)) == 0
    now = until - dt.timedelta(days=30)
    old_ref = stored["secret_refs"]["credential"]
    assert renewal.sweep(repo, SETTINGS, RESOLVER, microsoft(calls, certificate=lambda: der_of(repo, record)), now=now) == 1
    after = service.view(repo, service.get(repo, record["id"]))
    new_ref = ProviderConnectionStore(repo).get(record["id"])["secret_refs"]["credential"]
    assert new_ref != old_ref and after["target"]["generated"]["thumbprint"] != stored["target"]["generated"]["thumbprint"]
    assert after["checks"]["renewal"]["state"] == "OK" and "keep" not in after["checks"]["renewal"]
    assert after["checks"]["job_id"] and after["checks"]["stale"]
    added = [json.loads(content) for method, _host, path, content in calls if path.endswith("/addKey")]
    assert len(added) == 1 and "PRIVATE" not in json.dumps(added)
    # Every record now points at the new envelope.
    for row in view["created"]:
        if row["kind"] == "metadata":
            assert set(CoverageStore(repo).get(uuid.UUID(row["id"]))["spec"]["secret_refs"].values()) == {new_ref}
        else:
            assert repo.get_connection(uuid.UUID(row["id"])).secret_ref == new_ref
    assert any(event.event_type == "PROVIDER_CONNECTION_CREDENTIAL_RENEWED" for event in repo.finding_events.values())
    # The same slot does not sweep twice; a day later the old certificate is removed with the new key's proof.
    assert renewal.sweep(repo, SETTINGS, RESOLVER, microsoft(), now=now) == 0
    calls.clear()
    assert renewal.sweep(repo, SETTINGS, RESOLVER, microsoft(calls), now=now + dt.timedelta(days=2)) == 1
    removed = [json.loads(content) for method, _host, path, content in calls if path.endswith("/removeKey")]
    assert [item["keyId"] for item in removed] == [OLD_KEY]
    kept = ProviderConnectionStore(repo).get(record["id"])["checks"]["renewal"]
    assert kept["keep"] is None and kept["action"] == "retire" and kept["state"] == "OK"
    assert renewal.sweep(repo, SETTINGS, RESOLVER, microsoft(), now=now + dt.timedelta(days=3)) == 0


def test_a_renewal_that_cannot_read_the_application_says_why_and_keeps_the_credential():
    repo = InMemoryRepository()
    record, _view = activated(repo)
    stored = ProviderConnectionStore(repo).get(record["id"])
    until = dt.datetime.fromisoformat(stored["target"]["generated"]["not_after"])
    renewal.sweep(repo, SETTINGS, RESOLVER, microsoft(app_status=403), now=until - dt.timedelta(days=30))
    after = ProviderConnectionStore(repo).get(record["id"])
    assert after["secret_refs"] == stored["secret_refs"]
    assert service.view(repo, after)["checks"]["renewal"]["code"] == "AZURE_APPLICATION_READ_REQUIRED"


def test_a_personal_access_token_and_a_microsoft_token_are_sent_their_own_way():
    from cremore_azure_provider.app_certificate import TokenSource
    from cremore_azure_provider.devops_content import SourceHTTP

    payload = {"organization": "acme", "project": "Payments"}
    assert SourceHTTP({**payload, "token": "p" * 52}, None).authorization("p" * 52).startswith("Basic ")
    token = TokenSource({}, "scope")
    assert SourceHTTP({**payload, "token": token}, None).authorization("entra") == "Bearer entra"


def test_a_renewal_keeps_the_approved_scan_scopes_and_retires_only_when_every_record_moved():
    from cremore.domain.models import ScopeProfile
    from cremore.scanning import scope

    repo = InMemoryRepository()
    record, view = activated(repo)
    blob = next(uuid.UUID(row["id"]) for row in view["created"] if row["kind"] == "content" and "Blob" in row["name"])
    approved = repo.create_scope_profile(ScopeProfile(kind="source", connection_id=blob, name="Blob",
                                                      auth_revision=scope.auth_revision("source", repo.get_connection(blob))))
    first = approved.auth_revision
    stored = ProviderConnectionStore(repo).get(record["id"])
    until = dt.datetime.fromisoformat(stored["target"]["generated"]["not_after"])
    now = until - dt.timedelta(days=30)
    renewal.sweep(repo, SETTINGS, RESOLVER, microsoft(certificate=lambda: der_of(repo, record)), now=now)
    # The same app with the same permissions: the approval follows the renewed credential.
    assert repo.get_scope_profile(approved.id).auth_revision == scope.auth_revision("source", repo.get_connection(blob))
    assert repo.get_scope_profile(approved.id).auth_revision != first
    # A record left on the old credential holds the retirement back, and is moved first.
    repo.update_connection(blob, secret_ref=stored["secret_refs"]["credential"])
    calls = []
    renewal.sweep(repo, SETTINGS, RESOLVER, microsoft(calls), now=now + dt.timedelta(days=2))
    assert not [call for call in calls if call[2].endswith("/removeKey")]
    note = service.view(repo, service.get(repo, record["id"]))["checks"]["renewal"]
    assert note["code"] == "RECORDS_NOT_ON_THE_NEW_CREDENTIAL"
    assert repo.get_connection(blob).secret_ref == ProviderConnectionStore(repo).get(record["id"])["secret_refs"]["credential"]
    renewal.sweep(repo, SETTINGS, RESOLVER, microsoft(calls), now=now + dt.timedelta(days=2, hours=1))
    assert [call for call in calls if call[2].endswith("/removeKey")]
    events = [event.event_type for event in repo.finding_events.values()]
    assert "PROVIDER_CONNECTION_CREDENTIAL_RETIRED" in events and "PROVIDER_CONNECTION_CREDENTIAL_RENEWAL_FAILED" in events


def test_a_failed_renewal_is_audited_and_a_new_certificate_starts_clean():
    repo = InMemoryRepository()
    record, _view = activated(repo)
    stored = ProviderConnectionStore(repo).get(record["id"])
    until = dt.datetime.fromisoformat(stored["target"]["generated"]["not_after"])
    renewal.sweep(repo, SETTINGS, RESOLVER, microsoft(app_status=403), now=until - dt.timedelta(days=30))
    assert any(event.event_type == "PROVIDER_CONNECTION_CREDENTIAL_RENEWAL_FAILED"
               and event.note == "renew AZURE_APPLICATION_READ_REQUIRED" for event in repo.finding_events.values())
    fresh = service.set_credential(repo, SETTINGS, record["id"], {"credential": {"client_id": CLIENT}}, "admin")
    assert fresh["checks"]["renewal"] is None


def test_the_app_token_never_goes_to_a_server_address():
    from cremore_azure_provider.app_certificate import TokenSource
    from cremore_azure_provider.devops_content import SourceHTTP

    from cremore.collectors.base import CollectorError

    payload = {"organization": "acme", "project": "Payments", "base_url": "https://devops.example.com/tfs"}
    with pytest.raises(CollectorError, match="AZURE_DEVOPS_ENTRA_TOKEN_CLOUD_ONLY"):
        SourceHTTP({**payload, "token": TokenSource({}, "scope")}, None)
    assert SourceHTTP({**payload, "token": "p" * 52}, None).authorization("p" * 52).startswith("Basic ")
