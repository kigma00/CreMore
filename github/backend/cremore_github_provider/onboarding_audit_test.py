"""Organization audit selection binds preflight and the existing collector."""

from types import SimpleNamespace

import httpx
import pytest

from cremore.coverage.metadata_models import MetadataConnectionSpec
from cremore_github_provider import onboarding
from cremore_github_provider.metadata.adapter import validate_spec


@pytest.mark.parametrize("selected", [False, True])
def test_organization_audit_children_and_preflight(monkeypatch, selected):
    from cremore_github_provider import github_auth

    class Token:
        def __init__(self, *args, **kwargs):
            self.installation = {"account": {"login": "acme"}, "permissions": {}}

        def __call__(self):
            return "synthetic-installation-token"

        def scopes(self):
            return [name + ":read" for name in onboarding.APP_PERMISSIONS["inventory"]]

    monkeypatch.setattr(github_auth, "GitHubAppTokenSource", Token)
    plan = {"audit_events": selected, "audit_days": 7}
    connection = {"provider": "github", "edition": "enterprise_cloud", "auth_method": "github_app",
                  "target": {"organization": "acme"}, "secret_refs": {"credential": "sealed:synthetic"},
                  "purposes": ["inventory"], "plans": {"inventory": plan}}
    seen = []

    def handler(request):
        seen.append(request.url.path)
        assert request.url.host == "api.github.com" and request.method == "GET"
        return httpx.Response(403)

    context = SimpleNamespace(memo={}, http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    result = onboarding.check(connection, "inventory", {"credential": {}}, context)
    audits = [r for r in result if r["permission"] == "org_audit_read"]
    assert seen == (["/orgs/acme/audit-log"] if selected else [])
    assert [r["status"] for r in audits] == (["MISSING"] if selected else [])
    [child] = onboarding.children(connection, "inventory", plan)
    model = MetadataConnectionSpec.model_validate({**child["spec"],
        "secret_refs": {slot: "vault://github/" + slot for slot in child["secret_slots"]}})
    validate_spec(model)
    assert model.options.include_audit_events is selected
    assert ("audit" in model.capabilities) is selected
    if selected:
        assert model.options.audit_lookback_days == 7
