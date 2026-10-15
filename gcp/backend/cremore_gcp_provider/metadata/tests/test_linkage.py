"""Identifier matching says the provider issued a key, never that it still works."""

from __future__ import annotations

import unittest

from cremore_gcp_provider.metadata.linkage import (
    LOOKUP_KEY_URL,
    match_api_key,
    match_service_account_key,
)

from .fake import API_KEY_NAME, EMAIL, KEY_ID, PROJECT, FakeTransport

SA_KEY = f"projects/{PROJECT}/serviceAccounts/{EMAIL}/keys/{KEY_ID}"
CANDIDATE = {"type": "service_account", "client_email": EMAIL, "private_key_id": KEY_ID,
             "private_key": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"}


def inventory(items, status="complete"):
    return {"provider": "gcp", "project_id": PROJECT, "items": items,
            "coverage": {"service_account_keys": {"status": status}}}


def key_item(**overrides):
    return {"object_type": "credential", "credential_type": "service_account_user_managed_key",
            "project_id": PROJECT, "source_id": SA_KEY, "service_account_email": EMAIL,
            "key_id": KEY_ID, **overrides}


class ServiceAccountKeyTests(unittest.TestCase):
    def test_a_matching_pair_names_the_issued_key_and_stays_unverified(self):
        result = match_service_account_key(inventory([key_item()]), CANDIDATE)
        self.assertEqual(result, {"status": "identifier_match", "source_id": SA_KEY,
                                  "basis": "client_email+private_key_id",
                                  "validity": "unverified"})

    def test_the_candidate_private_key_is_never_returned(self):
        result = match_service_account_key(inventory([key_item()]), CANDIDATE)
        self.assertNotIn("PRIVATE KEY", repr(result))

    def test_a_non_match_is_conclusive_only_for_a_complete_key_inventory(self):
        self.assertEqual(
            match_service_account_key(inventory([]), CANDIDATE)["status"],
            "not_found_in_complete_scope")
        self.assertEqual(
            match_service_account_key(inventory([], status="partial"), CANDIDATE)["status"],
            "unknown_in_partial_scope")

    def test_a_system_managed_key_is_not_a_candidate_for_a_leaked_json_key(self):
        items = [key_item(credential_type="service_account_system_managed_key")]
        self.assertEqual(match_service_account_key(inventory(items), CANDIDATE)["status"],
                         "not_found_in_complete_scope")

    def test_two_inventory_rows_for_one_identifier_stay_ambiguous(self):
        result = match_service_account_key(inventory([key_item(), key_item()]), CANDIDATE)
        self.assertEqual(result["status"], "ambiguous_inventory")
        self.assertIsNone(result["source_id"])

    def test_a_malformed_candidate_is_refused_before_any_comparison(self):
        for change in ({"type": "authorized_user"}, {"client_email": "nope"},
                       {"private_key_id": "../../x"}, {"private_key_id": None}):
            result = match_service_account_key(inventory([key_item()]), {**CANDIDATE, **change})
            self.assertEqual(result["status"], "invalid_candidate")

    def test_the_project_comes_from_the_inventory_not_from_the_candidate(self):
        items = [key_item(project_id="attacker-project")]
        self.assertEqual(match_service_account_key(inventory(items), CANDIDATE)["status"],
                         "not_found_in_complete_scope")


class ApiKeyLookupTests(unittest.TestCase):
    def item(self):
        return {"object_type": "credential", "credential_type": "api_key",
                "project_id": PROJECT, "source_id": API_KEY_NAME}

    def test_an_exact_resource_name_match_identifies_the_key(self):
        transport = FakeTransport({LOOKUP_KEY_URL: {
            "name": API_KEY_NAME, "parent": API_KEY_NAME.rsplit("/keys/", 1)[0]}})
        result = match_api_key(inventory([self.item()]), "AIza" + "B" * 35, transport)
        self.assertEqual(result["status"], "resource_match")
        self.assertEqual(result["validity"], "unverified")

    def test_a_key_google_knows_but_the_inventory_does_not_is_said_so(self):
        transport = FakeTransport({LOOKUP_KEY_URL: {
            "name": API_KEY_NAME, "parent": API_KEY_NAME.rsplit("/keys/", 1)[0]}})
        result = match_api_key(inventory([]), "AIza" + "B" * 35, transport)
        self.assertEqual(result["status"], "lookup_found_not_in_inventory")

    def test_a_candidate_outside_the_key_grammar_is_never_sent_to_google(self):
        transport = FakeTransport({})
        self.assertEqual(match_api_key(inventory([]), "not-a-key", transport)["status"],
                         "invalid_candidate")
        self.assertEqual(transport.calls, [])

    def test_an_unavailable_lookup_is_distinguished_from_a_missing_key(self):
        transport = FakeTransport({}, failures={LOOKUP_KEY_URL: "http_404"})
        self.assertEqual(match_api_key(inventory([]), "AIza" + "B" * 35, transport)["status"],
                         "lookup_not_found")
        transport = FakeTransport({}, failures={LOOKUP_KEY_URL: "permission_denied_or_api_disabled"})
        result = match_api_key(inventory([]), "AIza" + "B" * 35, transport)
        self.assertEqual(result["status"], "lookup_unavailable")
        self.assertEqual(result["error_code"], "permission_denied_or_api_disabled")

    def test_a_lookup_response_whose_parent_disagrees_is_refused(self):
        transport = FakeTransport({LOOKUP_KEY_URL: {
            "name": API_KEY_NAME, "parent": "projects/999/locations/global"}})
        self.assertEqual(match_api_key(inventory([]), "AIza" + "B" * 35, transport)["status"],
                         "invalid_lookup_response")


if __name__ == "__main__":
    unittest.main()
