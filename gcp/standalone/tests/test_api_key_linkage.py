import json
import unittest

from cremore_gcp.linkage import LOOKUP_KEY_URL, match_api_key, scan_text
from cremore_gcp.transport import ApiError

PROJECT = "cremore-test-123"
KEY = "AIza" + "a" * 35
NAME = "projects/123456789/locations/global/keys/123e4567-e89b-12d3-a456-426614174000"


def inventory(status="complete"):
    return {
        "provider": "gcp", "project_id": PROJECT, "collected_at": "2026-09-20T00:00:00Z",
        "coverage": {"api_keys": {"status": status}},
        "items": [{"object_type": "credential", "credential_type": "api_key",
                   "project_id": PROJECT, "source_id": NAME}],
    }


class FakeTransport:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, url, params=None):
        self.calls.append((url, params))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class ApiKeyLinkageTests(unittest.TestCase):
    def test_exact_lookup_matches_inventory_without_returning_key(self):
        transport = FakeTransport({"parent": NAME.rsplit("/keys/", 1)[0], "name": NAME})
        result = match_api_key(inventory(), KEY, transport)
        self.assertEqual(result["status"], "resource_match")
        self.assertEqual(result["source_id"], NAME)
        self.assertEqual(result["validity"], "unverified")
        self.assertEqual(transport.calls, [(LOOKUP_KEY_URL, {"keyString": KEY})])
        self.assertNotIn(KEY, json.dumps(result))

    def test_lookup_failure_and_stale_inventory_do_not_claim_no_key(self):
        failed = match_api_key(inventory(), KEY, FakeTransport(ApiError("permission_denied")))
        self.assertEqual(failed["status"], "lookup_unavailable")
        self.assertEqual(failed["error_code"], "permission_denied")
        stale = inventory()
        stale["items"] = []
        found = match_api_key(stale, KEY, FakeTransport({"parent": NAME.rsplit("/keys/", 1)[0], "name": NAME}))
        self.assertEqual(found["status"], "lookup_found_not_in_inventory")
        self.assertEqual(found["source_id"], NAME)
        not_found = match_api_key(inventory(), KEY, FakeTransport(ApiError("http_404")))
        self.assertEqual(not_found["status"], "lookup_not_found")

    def test_invalid_candidate_never_calls_provider(self):
        transport = FakeTransport({})
        result = match_api_key(inventory(), "not-a-google-key", transport)
        self.assertEqual(result["status"], "invalid_candidate")
        self.assertFalse(transport.calls)

    def test_scan_file_content_resolves_each_key_once(self):
        transport = FakeTransport({"parent": NAME.rsplit("/keys/", 1)[0], "name": NAME})
        result = scan_text(f"first {KEY}\nagain {KEY}\n".encode(), inventory(), transport)
        self.assertEqual(len(result["matches"]), 1)
        self.assertEqual(result["matches"][0]["line_numbers"], [1, 2])
        self.assertEqual(len(transport.calls), 1)
        self.assertNotIn(KEY, json.dumps(result))


if __name__ == "__main__":
    unittest.main()
