"""Real onboarding/child contracts with public-only admission and fake providers."""

import copy
import json
import uuid
from types import SimpleNamespace

import httpx
import pytest

from cremore.config import Settings
from cremore.domain.connections import job_payload_for
from cremore.identity import machine
from cremore.identity.machine_test import body as machine_body
from cremore.identity.machine_test import idp
from cremore.onboarding import check, sessions
from cremore.onboarding.credential_access import resolver_for_child
from cremore.onboarding.sessions_test import KEY, PAGE, TOKEN, body
from cremore.onboarding.sessions_test import repo as repo  # noqa: PLC0414
from cremore.onboarding.store import ProviderConnectionStore
from cremore.secretstore.provision import provision
from cremore.secretstore.resolver import SecretRefError, SecretResolver, inject_secret
from cremore.secretstore.sealed import SealedSecretError


@pytest.fixture(scope="module")
def credentials(tmp_path_factory):
    root = tmp_path_factory.mktemp("isolated") / "keys"
    provision({"version": 1, "connections": [
        {"provider": "notion", "auth_method": "integration", "target": {}, "purposes": ["exposure"]},
        {"provider": "machine_identity", "idp": machine_body()["idp"]},
    ]}, root)
    shared = {"FINGERPRINT_KEY": "ab" * 32, "ISOLATED_DEPLOYMENT": True,
              "SEALING_PUBLIC_KEYS_FILE": str(root / "recipients.json")}
    return (Settings(**shared, WORKER_EXECUTION_ROLE="control", CONTROL_SEALING_KEY="cd" * 32),
            Settings(**shared, WORKER_EXECUTION_ROLE="collector",
                     SEALING_PRIVATE_KEYS_FILE=str(root / "collector-private.json")))


def activated(repo, credentials):
    api_settings, worker_settings = credentials
    calls = []

    def respond(request):
        calls.append(request.url.path)
        assert request.headers["Authorization"] == "Bearer " + TOKEN
        if request.url.path == "/v1/users/me":
            return httpx.Response(200, json={"object": "user", "id": "bot-id", "name": "Test bot",
                "bot": {"workspace_name": "Test workspace"}})
        assert request.url.path == "/v1/search"
        return httpx.Response(200, json={"results": [{"object": "page", "id": PAGE,
            "properties": {"Name": {"type": "title", "title": [{"plain_text": "PoC"}]}},
            "parent": {"type": "workspace"}}], "has_more": False})

    worker = SimpleNamespace(repo=repo, settings=worker_settings,
        metadata_secret_resolver=SecretResolver(sealing_key=worker_settings.credential_sealing_keys),
        http_client_factory=lambda: httpx.Client(transport=httpx.MockTransport(respond)))

    def finish(view):
        check.run(worker, repo.get_job(uuid.UUID(view["job_id"])))
        return sessions.read(repo, view["id"], body(view), "admin")

    view = sessions.create(repo, api_settings, {"browser_key": KEY, "provider": "notion", "edition": "standard",
        "auth_method": "integration", "credential": {"token": TOKEN}}, "admin")
    view = finish(view)
    assert view["state"] == "AUTHENTICATED", view
    view = finish(sessions.discover(repo, view["id"], body(view, purposes=["exposure"]), "admin"))
    view = finish(sessions.inspect(repo, view["id"], body(view, target_ids=[view["roots"][0]["id"]],
        plans={"exposure": {}}), "admin"))
    assert view["state"] == "CHECKED", view
    view = sessions.select(repo, view["id"], body(view, snapshot_id=view["snapshot_id"],
        resource_ids=[view["resources"][0]["id"]]), "admin")
    result = sessions.complete(repo, api_settings, view["id"], body(view, name="Isolated source"), "admin")
    assert TOKEN not in json.dumps(result)
    assert calls[0] == "/v1/users/me" and "/v1/search" in calls
    assert set(calls) == {"/v1/users/me", "/v1/search"}
    return repo.list_connections()[0], result, worker


def test_public_only_onboarding_through_content_reader(repo, credentials):
    source, _, worker = activated(repo, credentials)
    payload = {**job_payload_for(source), "secret_ref": source.secret_ref}
    bound = resolver_for_child(repo, "content", source.id, worker.metadata_secret_resolver,
        payload=payload, settings=worker.settings, job_kind="notion")
    assert inject_secret("notion", payload, bound)["token"] == TOKEN
    with pytest.raises(SealedSecretError):
        SecretResolver(sealing_key=credentials[0].credential_sealing_keys, binding=bound.binding).resolve(source.secret_ref)


@pytest.mark.parametrize("mutation", ["authority", "provider", "job", "reference", "disabled", "unowned"])
def test_content_binding_rejects_changed_context_before_decryption(repo, credentials, mutation):
    source, result, worker = activated(repo, credentials)
    payload = {**job_payload_for(source), "secret_ref": source.secret_ref}
    job_kind = "notion"
    child_id = source.id
    if mutation == "authority":
        payload["base_url"] = "https://other.example.test"
    elif mutation == "provider":
        payload["provider"] = "gitlab"
    elif mutation == "job":
        job_kind = "gitlab"
    elif mutation == "reference":
        payload["secret_ref"] += "x"
    elif mutation == "unowned":
        child_id = uuid.uuid4()
    else:
        store = ProviderConnectionStore(repo)
        owner = store.get(result["id"])
        store.update(owner["id"], owner["revision"], "admin", disabled_purposes=["exposure"])
    with pytest.raises(SecretRefError):
        resolver_for_child(repo, "content", child_id, worker.metadata_secret_resolver,
            payload=payload, settings=worker.settings, job_kind=job_kind)


def test_machine_credential_is_bound_and_only_collector_can_refresh(repo, credentials, tmp_path):
    api_settings, worker_settings = credentials
    saved = machine.save(repo, api_settings, machine_body(), "admin")
    assert saved["value"]["secret"].startswith("sealed:v3:")
    changed = copy.deepcopy(machine_body())
    changed.update(client_secret=None, expected_revision=machine.revision_of(repo.get_setting(machine.KEY)))
    changed["idp"]["client_id"] = "other-app"
    with pytest.raises(machine.MachineIdentityError, match="NEW_SECRET_REQUIRED"):
        machine.save(repo, api_settings, changed, "admin")
    record = repo.get_setting(machine.KEY)["value"]
    api_keeper = machine.Keeper(repo, api_settings, "api", directory=tmp_path / "api", environ={})
    with pytest.raises(machine.MachineIdentityError, match="COLLECTOR_ONLY"):
        api_keeper._secret(record)
    calls = []
    keeper = machine.Keeper(repo, worker_settings, "worker:test", directory=tmp_path / "worker",
        environ={}, client=idp(calls))
    keeper.tick()
    assert calls and all(item["client_id"] == record["idp"]["client_id"] for item in calls)
    assert machine_body()["client_secret"] not in json.dumps(machine.public(repo.get_setting(machine.KEY)))


def test_machine_check_queues_without_api_decryption_and_cancel_can_be_retried(repo, credentials):
    from fastapi.testclient import TestClient

    from cremore.api import create_app

    token = "synthetic-admin-" + "a" * 32
    settings = credentials[0].model_copy(update={"api_token": token})
    machine.save(repo, settings, machine_body(), "admin")
    client = TestClient(create_app(repo=repo, settings=settings,
        aws_identity_probe=lambda **kwargs: {"state": "NO_CREDENTIALS"}))
    headers = {"Authorization": "Bearer " + token}
    path = "/api/v1/settings/machine-identity"
    queued = client.post(path + "/test", headers=headers)
    assert queued.status_code == 200, queued.text
    test = queued.json()["test"]
    assert test["state"] == "QUEUED" and test["tokens"] == {}
    assert client.post(path + "/test", headers=headers).json()["test"]["job_id"] == test["job_id"]
    repo.cancel_job(uuid.UUID(test["job_id"]))
    failed = client.get(path, headers=headers).json()["test"]
    assert failed["state"] == "FAILED" and failed["tokens"] == {}
    new = client.post(path + "/test", headers=headers).json()["test"]
    assert new["job_id"] != test["job_id"]
    repo.put_setting(machine.STATUS_PREFIX + "old-worker", {"revision": 1,
        "tokens": {"aws": {"claims": {"iss": "https://old-identity.example.test", "sub": "old-subject"}}}}, "system")
    machine.save(repo, settings, {**machine_body(), "expected_revision": 1}, "admin")
    assert client.get(path, headers=headers).json()["test"]["error"] == "MACHINE_IDENTITY_CHANGED"
    setup = client.get(path + "/setup", headers=headers)
    assert setup.status_code == 200 and "old-identity" not in setup.text and "old-subject" not in setup.text


@pytest.mark.parametrize("field", [None, "origin", "tenant", "tls_ca_pem", "api_path"])
def test_metadata_normalized_authority_matches_current_child(repo, credentials, field):
    from cremore.coverage.metadata_models import MetadataConnectionSpec
    from cremore.coverage.metadata_store import MetadataStore
    from cremore.onboarding import catalog, children
    from cremore.secretstore.isolation import binding_for_record

    settings = credentials[0]
    owner = {"provider": "notion", "edition": "enterprise", "name": "Inventory",
             "auth_method": "organization_bot", "target": {"workspace": PAGE},
             "purposes": ["inventory"], "plans": {"inventory": {}}, "status": "ACTIVE",
             "secret_refs": {"credential": "sealed:v3:" + "a" * 40 + "." + "b" * 40 + "." + "c" * 40}}
    store = ProviderConnectionStore(repo)
    owner = store.create(owner, "admin")
    child = catalog.module("notion").children(owner, "inventory", {})[0]
    made = children.create(repo, settings, owner, "inventory", child, "admin")[0]
    row = MetadataStore(repo).require_connection(uuid.UUID(made["id"]))
    spec = MetadataConnectionSpec.model_validate(row["spec"])
    if field:
        data = spec.model_dump()
        if field == "api_path":
            data["options"]["api_path"] = "/other"
        else:
            data[field] = "https://other.example.test" if field == "origin" else "other"
        # Mutated data represents an untrusted persisted task; the boundary must
        # reject it before a reader, independent of the initial form validator.
        spec = data
    resolver = SecretResolver()
    if field:
        with pytest.raises(SecretRefError, match="AUTHORITY_CHANGED"):
            resolver_for_child(repo, "metadata", made["id"], resolver, spec=spec, settings=settings)
    else:
        bound = resolver_for_child(repo, "metadata", made["id"], resolver, spec=spec, settings=settings)
        assert bound.binding == binding_for_record(owner)
