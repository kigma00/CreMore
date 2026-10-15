import unittest

from cremore_gcp.transport import _forbidden_code


class TransportTests(unittest.TestCase):
    def test_error_reason_is_allowlisted_without_copying_response(self):
        response = {"error": {"message": "SENSITIVE_ERROR_TEXT", "details": [
            {"reason": "SERVICE_DISABLED", "metadata": {"credential": "SENSITIVE_VALUE"}}
        ]}}
        self.assertEqual(_forbidden_code(response), "api_disabled")
        self.assertEqual(_forbidden_code({"error": {"details": [{"reason": "UNKNOWN_REASON"}]}}),
                         "permission_denied_or_api_disabled")


if __name__ == "__main__":
    unittest.main()
