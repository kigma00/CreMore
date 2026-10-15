"""Who owns each Atlassian credential the collector lists (departed-owner check)."""

import json
import unittest
from unittest.mock import Mock

from cremore_atlassian_provider.metadata import owners

from . import test_common_adapter as common


def rows(mode, status=None):
    def reply(request, **kwargs):
        answer = common.response(request, **kwargs)
        if status and request.full_url.split("?")[0].endswith("/api-tokens") and "/orgs/" in request.full_url:
            body = json.loads(answer.read())
            for row in body["data"]:
                row["status"] = status
            answer = common.Response(body)
        return answer

    opener = Mock()
    opener.open.side_effect = reply
    _pages, records = common.collect(common.spec(mode), opener)
    return [{"object_id": item.identity.object_id, "summary": item.model_dump()} for item in records
            if item.record_type == "entity_observation" and item.identity.kind == "credential"]


class OwnerTests(unittest.TestCase):
    def test_normalized_org_api_tokens_name_the_managed_account(self):
        found = [owners.credential_owner(row) for row in rows("inventory")]
        tokens = [item for item in found if item and item["credential_type"] == "ATLASSIAN_API_TOKEN"]
        self.assertTrue(tokens)
        self.assertEqual(tokens[0]["account"], "person-1")
        self.assertEqual(tokens[0]["state"], "ACTIVE")  # ALLOWED
        keys = {kind for item in tokens for kind, _value in item["keys"]}
        self.assertLessEqual(keys, {"VERIFIED_EMAIL"})

    def test_user_api_tokens_read_in_accounts_mode_keep_the_email(self):
        found = [owners.credential_owner(row) for row in rows("accounts")]
        tokens = [item for item in found if item]
        self.assertEqual([(item["account"], item["keys"]) for item in tokens],
                         [("person-1", [("VERIFIED_EMAIL", "person@example.invalid")])])

    def test_admin_api_keys_are_their_creators(self):
        found = [owners.credential_owner(row) for row in rows("inventory")]
        keys = [item for item in found if item and item["credential_type"] == "ATLASSIAN_ADMIN_API_KEY"]
        self.assertTrue(all(item["relation"] == "created_by" for item in keys))

    def test_a_policy_blocked_token_is_not_reported_as_revoked_or_expired(self):
        # API Access ApiToken.status is ALLOWED or BLOCKED; an admin can allow a blocked token again.
        for status, state in (("BLOCKED", "UNKNOWN"), ("EXPIRED", "REVOKED_OR_EXPIRED")):
            with self.subTest(status=status):
                found = [owners.credential_owner(row) for row in rows("inventory", status)]
                tokens = [item for item in found if item and item["credential_type"] == "ATLASSIAN_API_TOKEN"]
                self.assertTrue(tokens)
                self.assertEqual({item["state"] for item in tokens}, {state})
