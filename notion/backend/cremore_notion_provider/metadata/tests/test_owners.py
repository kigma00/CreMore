"""Who owns each Notion PAT or MCP connection (departed-owner check)."""

import unittest

from cremore_notion_provider.metadata import owners
from cremore_notion_provider.metadata.normalization import observation

from cremore.coverage.metadata_models import MetadataConnectionSpec, MetadataScope

WORKSPACE = "11111111-2222-4333-8444-555555555555"
USER = "22222222-3333-4444-8555-666666666666"
SPEC = MetadataConnectionSpec.model_validate({
    "name": "notion", "provider": "notion", "origin": "https://api.notion.com",
    "scopes": [{"kind": "workspace", "id": WORKSPACE}], "capabilities": ["inventory"],
    "secret_refs": {"token": "vault://notion/bot"}, "options": {"sources": ["personal_access_tokens",
                                                                          "mcp_client_connections"]}})


def row(source, values):
    record = observation(SPEC, MetadataScope(kind="workspace", id=WORKSPACE), source, values,
                         observed_at="2026-09-28T00:00:00+00:00")
    return {"object_id": record.identity.object_id, "summary": record.model_dump()}


class OwnerTests(unittest.TestCase):
    def test_a_pat_is_its_creators_with_the_email_notion_verified(self):
        owner = owners.credential_owner(row("personal_access_tokens", {
            "id": "33333333-4444-4555-8666-777777777777", "creator": {"id": USER, "name": "Dana", "email": "dana@acme.test"},
            "created_at": 1_780_000_000_000, "status": "expired", "name": "export"}))
        self.assertEqual((owner["account"], owner["keys"], owner["state"]),
                         (USER, [("VERIFIED_EMAIL", "dana@acme.test")], "REVOKED_OR_EXPIRED"))

    def test_an_mcp_connection_belongs_to_its_user_and_links_only_by_confirmation(self):
        owner = owners.credential_owner(row("mcp_client_connections", {
            "client": {"key": "cursor", "name": "Cursor", "type": "public"}, "created_at": 1_780_000_000_000,
            "is_enterprise_managed": False, "user": {"id": USER}, "workspaces": [{"id": WORKSPACE}]}))
        self.assertEqual((owner["account"], owner["keys"], owner["credential_type"]),
                         (USER, [], "NOTION_MCP_CONNECTION"))
