"""Who owns each GitLab token the collector lists (departed-owner check)."""

import unittest
from datetime import UTC, datetime, timedelta

from cremore_gitlab_provider.metadata import owners

from .test_adapter import records, run, spec_for


def rows(items, namespace):
    return [{"object_id": item["identity"]["object_id"], "summary": item} for item in items
            if item["record_type"] == "entity_observation" and item["provenance"]["operation"] == "gitlab.native.inventory"
            and item["identity"]["object_id"].startswith(namespace + ":")]


class OwnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.items = records(run(spec_for(audit=True)))

    def test_a_personal_token_is_its_users(self):
        found = [owners.credential_owner(row) for row in rows(self.items, "personal_access_token")]
        people = [item for item in found if item]
        self.assertTrue(people)
        first = people[0]
        self.assertTrue(first["account"].startswith("user:"))
        self.assertEqual(first["credential_type"], "GITLAB_PERSONAL_ACCESS_TOKEN")
        self.assertIn(("PROVIDER_LOGIN", first["label"]), first["keys"])
        self.assertTrue(first["expires_at"].endswith("00:00:00+00:00"))

    def test_expiry_midnight_controls_leaver_verdict_and_retention(self):
        from cremore.coverage.facts import FactWriter
        from cremore.identity.leavers import _still_on, verdict_for

        values = {"identity": {"namespace": "personal_access_token"}, "family": "personal_access_token",
                  "metadata": {"user_id": 7, "active": True, "expires_at": "2026-10-13"}}
        row = {"summary": {"facts": [fact.model_dump() for fact in FactWriter().facts(values)]}}
        credential = {**owners.credential_owner(row), "current": True}
        midnight = datetime(2026, 10, 13, tzinfo=UTC)
        orphan = {"body": {"credential": credential}, "verdict": "ACTIVE"}
        self.assertEqual(verdict_for(credential, None, midnight - timedelta(seconds=1))[0], "ACTIVE")
        self.assertTrue(_still_on(orphan, midnight - timedelta(seconds=1)))
        self.assertEqual(verdict_for(credential, None, midnight)[0], "REVOKED_OR_EXPIRED")
        self.assertFalse(_still_on(orphan, midnight))
        for value, expected in ((None, None), ("2026-02-30", None),
                                ("2026-10-13T12:30:00Z", "2026-10-13T12:30:00Z")):
            self.assertEqual(owners._expires_at(value), expected)

    def test_service_account_and_resource_tokens_belong_to_no_person(self):
        service = [row for row in rows(self.items, "personal_access_token")
                   if "service_account" in str(row["summary"])]
        self.assertTrue(service)
        self.assertTrue(all(owners.credential_owner(row) is None for row in service))
        self.assertTrue(all(owners.credential_owner(row) is None for row in rows(self.items, "resource_access_token")))

    def test_the_confirmed_email_and_saml_identities_link_and_the_username_is_a_candidate(self):
        row = {"summary": {"facts": []}}
        from cremore.coverage.facts import FactWriter

        values = {"identity": {"namespace": "personal_access_token"}, "family": "personal_access_token",
                  "summary": {"owner": {"id": 7, "profile": {
                      "username": "dana", "email": "dana@acme.test", "public_email": "d@home.test",
                      "identities": [{"provider": "saml", "extern_uid": "00u1okta"},
                                     # Accounts at another service name nobody at the company's IdP.
                                     {"provider": "bitbucket", "extern_uid": "dana"},
                                     {"provider": "GitHub", "extern_uid": "2435223452345"},
                                     # An identity stored without its provider is kept, as before.
                                     {"extern_uid": "legacy-uid"},
                                     # A second SAML provider carries the name its administrator gave it.
                                     {"provider": "saml_entra", "extern_uid": "dana@acme.test"}]}}},
                  "metadata": {"active": True, "revoked": False, "last_used_at": "2026-09-01T00:00:00Z"}}
        row["summary"]["facts"] = [fact.model_dump() for fact in FactWriter().facts(values)]
        owner = owners.credential_owner(row)
        self.assertEqual(sorted(owner["keys"]), [("EXTERNAL_UID", "00u1okta"), ("EXTERNAL_UID", "dana@acme.test"),
                                                 ("EXTERNAL_UID", "legacy-uid"), ("PROVIDER_LOGIN", "dana"),
                                                 ("VERIFIED_EMAIL", "dana@acme.test")])
        self.assertEqual((owner["account"], owner["state"]), ("user:7", "ACTIVE"))
