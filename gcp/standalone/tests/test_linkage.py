import json
import unittest

from cremore_gcp.linkage import (
    is_service_account_key_identifier,
    match_service_account_key,
    service_account_key_identifier,
)

PROJECT = "cremore-test-123"
EMAIL = f"test@{PROJECT}.iam.gserviceaccount.com"
KEY_ID = "abcdef0123456789" * 2 + "abcdef01"
SOURCE_ID = f"projects/{PROJECT}/serviceAccounts/{EMAIL}/keys/{KEY_ID}"


def inventory(status="complete"):
    return {
        "project_id": PROJECT,
        "coverage": {"service_account_keys": {"status": status}},
        "items": [{
            "object_type": "credential",
            "credential_type": "service_account_user_managed_key",
            "project_id": PROJECT,
            "service_account_email": EMAIL,
            "key_id": KEY_ID,
            "source_id": SOURCE_ID,
        }],
    }


class LinkageTests(unittest.TestCase):
    def test_only_provider_key_id_shape_can_cross_the_identifier_boundary(self):
        for invalid in ("legacy_key_1", "a" * 39, "a" * 41, "z" * 40):
            with self.subTest(invalid=invalid):
                self.assertIsNone(service_account_key_identifier({
                    "type": "service_account", "client_email": EMAIL, "private_key_id": invalid}))
                self.assertFalse(is_service_account_key_identifier(f"serviceAccountKey:{EMAIL}:{invalid}"))
        self.assertTrue(is_service_account_key_identifier(f"serviceAccountKey:{EMAIL}:{KEY_ID}"))
        for email in ("UPPER@project.iam.gserviceaccount.com", "not_an_account@project.iam.gserviceaccount.com"):
            self.assertIsNone(service_account_key_identifier({
                "type": "service_account", "client_email": email, "private_key_id": KEY_ID}))

    def test_matches_both_identifiers_and_drops_private_key(self):
        candidate = {
            "type": "service_account", "client_email": EMAIL,
            "private_key_id": KEY_ID, "private_key": "TEST_PRIVATE_KEY_MUST_NOT_LEAK",
        }
        result = match_service_account_key(inventory(), candidate)
        self.assertEqual(result["status"], "identifier_match")
        self.assertEqual(result["source_id"], SOURCE_ID)
        self.assertEqual(result["validity"], "unverified")
        self.assertNotIn(candidate["private_key"], json.dumps(result))

    def test_email_mismatch_is_not_a_match(self):
        result = match_service_account_key(inventory(), {
            "type": "service_account", "client_email": f"other@{PROJECT}.iam.gserviceaccount.com",
            "private_key_id": KEY_ID,
        })
        self.assertEqual(result["status"], "not_found_in_complete_scope")

    def test_partial_inventory_cannot_prove_absence(self):
        result = match_service_account_key(inventory("partial"), {
            "type": "service_account", "client_email": EMAIL,
            "private_key_id": "0" * 40,
        })
        self.assertEqual(result["status"], "unknown_in_partial_scope")

    def test_rejects_untyped_and_ambiguous_candidates(self):
        self.assertEqual(match_service_account_key(inventory(), {
            "client_email": EMAIL, "private_key_id": KEY_ID,
        })["status"], "invalid_candidate")
        duplicate = inventory()
        duplicate["items"].append(dict(duplicate["items"][0]))
        self.assertEqual(match_service_account_key(duplicate, {
            "type": "service_account", "client_email": EMAIL, "private_key_id": KEY_ID,
        })["status"], "ambiguous_inventory")


if __name__ == "__main__":
    unittest.main()
