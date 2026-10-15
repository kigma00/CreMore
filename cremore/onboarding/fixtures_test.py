"""Records as the connection wizard's step 4 leaves them, for tests of what runs on them.

Providers are connected only through the wizard (cremore/onboarding). A test of
scanning, collection, governance or the dashboard needs the record the wizard
creates, not the wizard itself, so these helpers create it in the store that runs
it -- validated the same way -- and, like the wizard, never keep a plain secret.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from unittest.mock import patch

from cremore.domain.connections import validate_connection
from cremore.domain.models import Connection


@contextmanager
def legacy_auth_method(provider, method_id):
    """Seed a pre-retirement fixture, restoring the new-connection gate immediately."""
    from cremore.onboarding import catalog

    method = next(m for m in catalog.descriptor(provider)["auth_methods"] if m["id"] == method_id)
    with patch.dict(method, {"new_setup": True}):
        yield


@contextmanager
def legacy_aws_setup(method="role"):
    """Seed only a pre-server-policy AWS connection for compatibility tests."""
    from cremore_aws_provider import aws_identity

    with legacy_auth_method("aws", method), patch.object(aws_identity, "require_server_workload"):
        yield


def sealed(settings, token: str) -> str:
    from cremore.secretstore.sealed import seal_token

    return seal_token(settings.sealing_keys, token)


def sealed_fields(settings, fields: dict) -> str:
    from cremore.secretstore.sealed import seal_fields

    return seal_fields(settings.sealing_keys, fields)


def content_source(repo, provider: str, config: dict, *, name: str | None = None, secret_ref: str | None = None,
                   status: str = "PENDING") -> Connection:
    """A content source connection (``provider`` is the connection provider: aws, github, gitlab, ...)."""
    conn = Connection(provider=provider, name=name or provider, config=dict(config), secret_ref=secret_ref)
    validate_connection(conn)
    created = repo.create_connection(conn)
    if status != created.status:
        created = repo.update_connection(created.id, status=status)
    return created


def collection(repo, spec: dict, actor: str = "admin", *, connection_id=None):
    """A schema 1 or schema 2 collection; returns (row, collector token)."""
    from cremore.coverage.store import CoverageStore

    if spec.get("schema_version") == 2:
        from cremore.coverage.metadata_models import MetadataConnectionSpec
        from cremore.coverage.metadata_store import MetadataStore
        from cremore.coverage.providers import validate_spec

        model = MetadataConnectionSpec.model_validate(spec)
        validate_spec(model)
        return MetadataStore(repo).create(model, actor, connection_id=connection_id)
    from cremore.coverage.models import ConnectionSpec

    return CoverageStore(repo).create(ConnectionSpec.model_validate(spec), actor, connection_id=connection_id)


def aws_account(repo, settings, account_id: str, **fields):
    """An AWS account registered in its access mode, as the AWS connection's step 2 does."""
    from cremore_aws_provider import aws_access

    from cremore.api.aws_support import register_account

    approved = aws_access.approval(repo, aws_access.SCANNER, settings)
    return register_account(repo, settings, approved, {"account_id": account_id, **fields})


def wizard(client, headers, body: dict, *, plans: dict | None = None) -> dict:
    """Connect through the API as an administrator: create, mark checked, activate.

    The check itself runs in a worker; tests of the check use cremore/onboarding/onboarding_test.py.
    """
    from cremore.onboarding.store import ProviderConnectionStore

    created = client.post("/api/v1/provider-connections", headers=headers, json=body)
    assert created.status_code == 201, created.text
    view = created.json()
    store = ProviderConnectionStore(client.app.state.repo)
    record = store.get(uuid.UUID(view["id"]))
    grant_access(client.app.state.repo, record["id"], plans or {})
    if plans is None:
        return client.get(f"/api/v1/provider-connections/{view['id']}", headers=headers).json()
    activated = client.post(f"/api/v1/provider-connections/{view['id']}/activate", headers=headers,
                            json={"purposes": plans})
    assert activated.status_code == 200, activated.text
    return activated.json()


def grant_access(repo, connection_id, plans, *, status="GRANTED"):
    """Synthetic access evidence for tests of child/renewal/storage contracts.

    Permission tests run the real fake provider checks instead. This helper
    explicitly supplies every required answer, for the exact normalized plan.
    """
    import datetime as dt

    from cremore.onboarding import catalog, service, targets
    from cremore.onboarding.store import ProviderConnectionStore

    store = ProviderConnectionStore(repo)
    record = store.get(connection_id)
    normalized = {p: targets.normalize_plan(record, p, plan) for p, plan in plans.items()}
    checks = {"requested_plans": normalized, "checked_at": dt.datetime.now(dt.UTC).isoformat(), "results": {}, "stale": False}
    for purpose, plan in normalized.items():
        items = []
        for root in targets.records_of(record):
            subjects = getattr(catalog.module(root["provider"]), "permission_subjects", lambda *args: [])
            for p in catalog.permissions_for(root["provider"], purpose, root["auth_method"], root["target"]):
                items.extend({"permission": p["id"], "status": status,
                              **({"target_id": root["target_id"]} if root.get("target_id") else {}),
                              **({"subject": subject} if subject else {})}
                             for subject in subjects(root, purpose, p["id"], plan) or [None])
        checks["results"][purpose] = {"status": "PASSED" if status == "GRANTED" else status, "items": items}
    checks["digest"] = service.check_digest({**record, "checks": checks})
    return store.update(record["id"], record["revision"], "fake-worker", status="ACTIVE" if record["plans"] else "CHECKED", checks=checks)


def activate_with_access(repo, settings, connection_id, body, actor):
    from cremore.onboarding import service

    grant_access(repo, connection_id, body["purposes"])
    return service.activate(repo, settings, connection_id, body, actor)
