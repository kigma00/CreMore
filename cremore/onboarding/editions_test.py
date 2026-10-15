"""Product eligibility is enforced before auth and by the persisted plan owner."""

import pytest
from cremore_gitlab_provider import onboarding as gitlab
from cremore_vault_provider import onboarding as vault

from cremore.onboarding import catalog, service


@pytest.mark.parametrize("edition,subscription,resource_tokens", [
    ("cloud", "free", False), ("cloud", "premium", True), ("self_managed", "free", False),
    ("self_managed", "ultimate", False), ("dedicated", None, False), ("cloud", None, True)])
def test_gitlab_tier_never_confuses_hosted_and_self_managed(edition, subscription, resource_tokens):
    target = {"scope": "group", "id": "1", **({"subscription": subscription} if subscription else {})}
    if edition != "cloud":
        target["host"] = "https://gitlab.example.test"
    record = {"provider": "gitlab", "edition": edition, "auth_method": "token", "target": target}
    [child] = gitlab.children(record, "inventory", {})
    options = child["spec"]["options"]
    assert options.get("include_resource_access_tokens", True) is resource_tokens
    assert options.get("include_enterprise_pat", True) is (subscription != "free")
    if subscription == "free":
        with pytest.raises(ValueError, match="GITLAB_FEATURE_REQUIRES_PAID_PLAN"):
            gitlab.children(record, "inventory", {"audit_events": True})


def test_unknown_edition_and_invalid_tier_are_rejected_before_collection():
    with pytest.raises(service.OnboardingError):
        service._method("notion", ["inventory"], "organization_bot", "standard", new_setup=True)
    with pytest.raises(ValueError, match="SUBSCRIPTION_INVALID"):
        gitlab.auth_context("gitlab", "cloud", {"subscription": "invented"})
    assert catalog.applies({"when": {"subscription": [""]}}, {})
    assert not catalog.applies({"when": {"subscription": ["premium", "ultimate"]}}, {})


def test_vault_namespace_entitlement_does_not_restrict_openbao_or_legacy_maintenance():
    values = {"address": "https://vault.example.test", "namespace": "team", "mounts": ["secret"], "kv_version": "2"}
    with pytest.raises(ValueError):
        vault.target("vault", "community", values)
    for provider, edition in [("vault", "enterprise"), ("vault", "hcp_dedicated"),
                              ("vault", "self_managed"), ("openbao", "self_managed")]:
        assert vault.target(provider, edition, values)["namespace"] == "team"
    with pytest.raises(service.OnboardingError, match="EDITION_RETIRED_FOR_NEW_CONNECTIONS"):
        service._method("vault", ["vault"], "token", "self_managed", new_setup=True)
    assert service._method("vault", ["vault"], "token", "self_managed")
