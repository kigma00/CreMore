"""Who owns each GitHub credential the collector lists (departed-owner check)."""

import unittest

from cremore_github_provider.metadata import owners

from .fake import enterprise_responses, enterprise_spec, inventory_row, org_responses, spec
from .test_adapter import NOW, adapter, drive


def rows(committed, prefix):
    return [{"object_id": item["identity"]["object_id"], "object_kind": item["identity"]["kind"], "summary": item}
            for item in committed if item["record_type"] == "entity_observation"
            and item["identity"]["object_id"].startswith(prefix)]


class OwnerTests(unittest.TestCase):
    def test_fine_grained_pats_and_sso_authorizations_name_their_login(self):
        _t, _b, committed, _s, _f = drive(spec(), org_responses())
        pat = owners.credential_owner(rows(committed, "fgpat:")[0])
        self.assertEqual((pat["account"], pat["credential_type"], pat["state"]),
                         ("octocat", "GITHUB_FINE_GRAINED_PAT", "ACTIVE"))
        self.assertEqual(pat["keys"], [("PROVIDER_LOGIN", "octocat")])
        self.assertEqual(pat["expires_at"], "2026-12-01T00:00:00Z")
        sso = owners.credential_owner(rows(committed, "sso:")[0])
        self.assertEqual((sso["account"], sso["credential_type"]), ("octocat", "GITHUB_SSO_AUTHORIZED_CREDENTIAL"))
        self.assertFalse(owners.LISTS_EVERY_USER_CREDENTIAL)

    def test_enterprise_inventory_names_user_owned_credentials_only(self):
        connection = enterprise_spec()
        path = "/enterprises/" + connection.scopes[0].id + "/credentials/exports"
        responses = enterprise_responses(window=adapter._window(connection, NOW.isoformat()))
        responses[path] = ([inventory_row("a1", credential_type="classic_pat", credential_id=5),
                            inventory_row("a2", owner="deploy-bot", owner_type="Bot")], {})
        _t, _b, committed, _s, _f = drive(connection, responses, enterprise=connection.scopes[0].id)
        found = [owners.credential_owner(row) for row in rows(committed, "inventory:")]
        users = [item for item in found if item]
        self.assertEqual([(item["account"], item["credential_type"]) for item in users],
                         [("octocat", "GITHUB_CLASSIC_PAT")])

    def test_other_objects_have_no_owner(self):
        self.assertIsNone(owners.credential_owner({"object_id": "installation:1", "object_kind": "installation",
                                                   "summary": {"facts": []}}))


def exported(**values):
    """One Enterprise export CSV row as the stored entity row the platform passes to owners."""
    from .test_exports import projection, row
    record = projection().project(1, row(**values))[0].model_dump()
    return {"id": "e-1", "provider": "github", "origin": "https://api.github.com", "tenant": "acme",
            "object_id": record["identity"]["object_id"], "object_kind": record["identity"]["kind"],
            "observed_at": "2026-10-05T00:00:00Z", "summary": record}


class ExportOwnerTests(unittest.TestCase):
    def test_inventory_user_tokens_take_the_types_the_catalog_declares(self):
        for kind, expected in {"oauth_app_user_token": "GITHUB_OAUTH_TOKEN",
                               "github_app_user_token": "GITHUB_APP_USER_TOKEN",
                               "classic_pat": "GITHUB_CLASSIC_PAT"}.items():
            self.assertEqual(owners.credential_owner(exported(credential_type=kind))["credential_type"], expected)

    def test_an_inventory_ssh_key_names_its_user_owner(self):
        key = exported(credential_type="ssh_key", credential_id="", fingerprint="SHA256:" + "A" * 43)
        self.assertEqual(key["object_kind"], "public_key")
        found = owners.credential_owner(key)
        self.assertEqual((found["account"], found["credential_type"]), ("person", "GITHUB_SSH_KEY"))
        bot = exported(credential_type="ssh_key", credential_id="", fingerprint="SHA256:" + "B" * 43,
                       owner_type="github_app")
        self.assertIsNone(owners.credential_owner(bot))

    def test_expiry_status_never_reads_as_no_expiry_and_blank_stays_unknown(self):
        from cremore.api import credential_records
        modules = {"github": "cremore_github_provider.metadata.owners"}
        never = credential_records._entity_facts(exported(expiry_status="never"), modules)
        self.assertEqual((never["expires"], never["expiry_known"]), (None, True))
        for status in ("unknown", ""):
            blank = credential_records._entity_facts(exported(expiry_status=status), modules)
            self.assertEqual((blank["expires"], blank["expiry_known"]), (None, False))
