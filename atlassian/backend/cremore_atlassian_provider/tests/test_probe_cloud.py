"""Offline diagnostic checks. These never load the real lab connection."""

import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock, patch

from cremore_atlassian_provider.metadata.qa import probe_cloud as probe

from . import posix_native_io

ORG = "00000000-0000-0000-0000-000000000001"
SECRET = "SYNTHETIC_SECRET_MUST_NOT_APPEAR"


class Response(io.BytesIO):
    def __init__(self, body, code=200, headers=None):
        super().__init__(body)
        self.code = code
        self.headers = headers or {}


class ProbeTests(unittest.TestCase):
    def test_record_values_and_unknown_fields_never_enter_report(self):
        body = {
            "data": [
                {
                    "id": SECRET,
                    "label": SECRET,
                    "createdBy": {"email": SECRET},
                    "scopes": [SECRET],
                    "secret": SECRET,
                }
            ],
            "links": {"next": SECRET},
            SECRET: SECRET,
        }
        result = probe.summarize("admin-api-keys", 200, body)
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(result["field_types"]["systemAccountId"], ["missing"])
        self.assertEqual(result["field_types"]["createdBy.email"], ["str"])
        self.assertTrue(result["next_present"])
        self.assertFalse(result["inventory_complete"])

    def test_empty_success_is_distinct_from_denied_or_not_found(self):
        for status in (401, 403, 404, 429, 500):
            with self.subTest(status=status):
                result = probe.summarize("user-api-tokens", status, {"error": SECRET})
                self.assertEqual(result["outcome"], "http_error")
                self.assertNotIn("record_count", result)
                self.assertNotIn(SECRET, json.dumps(result))
        result = probe.summarize("user-api-tokens", 200, {"data": [], "links": {}})
        self.assertEqual(result["record_count"], 0)
        self.assertEqual(result["outcome"], "documented_shape")
        self.assertNotIn("field_types", result)

    def test_oauth_array_drift_is_not_silently_declared_documented(self):
        result = probe.summarize("org-oauth-clients", 200, [])
        self.assertEqual(result["outcome"], "observed_array_variant")
        self.assertFalse(result["inventory_complete"])
        self.assertEqual(result["record_count"], 0)
        other = probe.summarize("admin-api-keys", 200, [])
        self.assertEqual(other["outcome"], "unexpected_shape")

    def test_null_is_distinct_from_missing_and_malformed_records(self):
        result = probe.summarize(
            "user-api-tokens", 200, {"data": [{"lastActiveAt": None}, {}], "links": {"next": None}}
        )
        self.assertEqual(result["field_types"]["lastActiveAt"], ["missing", "null"])
        self.assertEqual(result["next_field_type"], "null")
        bad = probe.summarize("user-api-tokens", 200, {"data": [SECRET]})
        self.assertEqual(bad["outcome"], "unexpected_record_shape")
        self.assertNotIn(SECRET, json.dumps(bad))

    def test_http_request_is_one_bounded_get_to_fixed_origin(self):
        opener = Mock()
        opener.open.return_value = Response(b'{"data": [], "links": {}}')
        result = probe.probe("admin-api-keys", ORG, SECRET, opener)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(
            request.full_url, probe.BASE_URL + "/orgs/" + ORG + "/api-keys?pageSize=20"
        )
        self.assertEqual(request.get_header("Authorization"), "Bearer " + SECRET)
        self.assertEqual(opener.open.call_args.kwargs, {"timeout": 20})
        self.assertEqual(opener.open.call_count, 1)
        self.assertNotIn(SECRET, json.dumps(result))

    def test_http_error_and_transport_exception_do_not_echo_secrets(self):
        for error, outcome in [
            (
                urllib.error.HTTPError(
                    "https://example.invalid",
                    403,
                    SECRET,
                    {},
                    io.BytesIO(json.dumps({"message": SECRET}).encode()),
                ),
                "http_error",
            ),
            (urllib.error.URLError(SECRET), "transport_error"),
        ]:
            with self.subTest(outcome=outcome):
                opener = Mock()
                opener.open.side_effect = error
                result = probe.probe("admin-api-keys", ORG, SECRET, opener)
                self.assertEqual(result["outcome"], outcome)
                self.assertNotIn(SECRET, json.dumps(result))
                self.assertEqual(opener.open.call_count, 1)

    def test_non_json_oversized_responses_and_redirects_are_not_followed(self):
        for body, status, outcome in [
            (SECRET.encode(), 200, "invalid_json"),
            (b"x" * (probe.MAX_BYTES + 1), 200, "response_too_large"),
            (b"{}", 302, "http_error"),
        ]:
            with self.subTest(outcome=outcome):
                opener = Mock()
                opener.open.return_value = Response(body, status)
                result = probe.probe("admin-api-keys", ORG, SECRET, opener)
                self.assertEqual(result["outcome"], outcome)
                self.assertEqual(opener.open.call_count, 1)
                self.assertNotIn(SECRET, json.dumps(result))
        self.assertIsNone(
            probe.NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.invalid")
        )

    @posix_native_io
    def test_configuration_requires_private_permissions_and_valid_key(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            directory.chmod(0o700)
            path = directory / "connection.json"
            path.write_text("{}")
            path.chmod(0o600)
            # Parse synthetic credentials in memory; retain the real permission checks.
            with patch("cremore_atlassian_provider.metadata.connections.loads",
                       return_value={"org_id": ORG, "api_key": SECRET}):
                self.assertEqual(probe.load_connection(directory), (ORG, SECRET))
                path.chmod(0o644)
                with self.assertRaises(ValueError):
                    probe.load_connection(directory)
            path.chmod(0o600)
            with patch("cremore_atlassian_provider.metadata.connections.loads",
                       return_value={"org_id": ORG, "api_key": SECRET + "\r\n"}), self.assertRaises(ValueError):
                probe.load_connection(directory)


if __name__ == "__main__":
    unittest.main()
