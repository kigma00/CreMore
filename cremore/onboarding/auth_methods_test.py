"""New server integrations exclude interactive/CLI methods; existing owners still work."""

import pytest

from cremore.db.repository import InMemoryRepository
from cremore.onboarding import catalog, service, sessions
from cremore.onboarding.fixtures_test import legacy_auth_method
from cremore.onboarding.onboarding_test import SETTINGS


@pytest.mark.parametrize("provider,method", [
    ("aws", "sso"), ("aws", "customer_cli"), ("gcp", "customer_cli"),
    ("vault", "customer_cli"), ("openbao", "customer_cli"),
])
def test_retired_auth_cannot_create_through_either_api_flow(provider, method):
    descriptor = catalog.descriptor(provider)
    spec = next(m for m in descriptor["auth_methods"] if m["id"] == method)
    assert spec["new_setup"] is False
    body = {"provider": provider, "auth_method": method, "purposes": [spec["purposes"][0]]}
    repo = InMemoryRepository()
    for create in (service.create, sessions.create):
        with pytest.raises(service.OnboardingError, match="AUTH_METHOD_RETIRED_FOR_NEW_CONNECTIONS"):
            create(repo, SETTINGS, body, "admin")
    assert repo.list_jobs() == []
    assert service.list_views(repo) == []


def test_retirement_preserves_existing_owner_maintenance_but_rejects_switching_to_it():
    repo = InMemoryRepository()
    body = {"provider": "gcp", "auth_method": "customer_cli", "purposes": ["vault"],
            "target": {"project": "legacy-project"}}
    with legacy_auth_method("gcp", "customer_cli"):
        old = service.create(repo, SETTINGS, body, "admin")
    refreshed = service.set_credential(repo, SETTINGS, old["id"], {}, "admin")
    assert refreshed["auth_method"] == "customer_cli"
    service.set_enabled(repo, old["id"], False, "admin", settings=SETTINGS)
    service.set_enabled(repo, old["id"], True, "admin", settings=SETTINGS)
    current = service.create(repo, SETTINGS, {**body, "auth_method": "adc"}, "admin")
    with pytest.raises(service.OnboardingError, match="AUTH_METHOD_RETIRED_FOR_NEW_CONNECTIONS"):
        service.set_credential(repo, SETTINGS, current["id"], {"auth_method": "customer_cli"}, "admin")
    with pytest.raises(service.OnboardingError, match="AUTH_METHOD_RETIRED_FOR_NEW_CONNECTIONS"):
        service.create(repo, SETTINGS, body, "admin")


def test_new_setup_requires_boolean_and_keeps_retired_descriptor_for_compatibility():
    descriptor = catalog.descriptor("aws")
    with pytest.raises(catalog.CatalogError, match="new_setup"):
        catalog.validate({**descriptor, "auth_methods": [
            {**m, "new_setup": "false"} for m in descriptor["auth_methods"]]})
    aws = next(d for d in catalog.public() if d["provider"] == "aws")
    methods = {m["id"]: m for m in aws["auth_methods"]}
    assert methods["sso"]["new_setup"] is False
    assert methods["role"].get("new_setup", True) and methods["runtime"].get("new_setup", True)
