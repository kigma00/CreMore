"""Transport boundaries and retry budgets, without live credentials/network."""

import io
import unittest
import urllib.error
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

from cremore_atlassian_provider.metadata.discovery import collect_operation
from cremore_atlassian_provider.metadata.http import (
    MAX_BYTES,
    CloudClient,
    Limits,
    NoRedirect,
    retry_delay,
)

ORG = "00000000-0000-0000-0000-000000000001"
SECRET = "SYNTHETIC_AUTH_SECRET"


class Response(io.BytesIO):
    def __init__(self, body=b'{"data":[],"links":{"next":null}}', status=200, headers=None):
        super().__init__(body)
        self.code, self.headers = status, headers or {}


class Clock:
    def __init__(self):
        self.value, self.waits = 0, []

    def now(self):
        return self.value

    def sleep(self, seconds):
        self.waits.append(seconds)
        self.value += seconds


class HttpTests(unittest.TestCase):
    def test_token_page_size_is_preserved_across_cursors_without_changing_key_page_size(self):
        opener = Mock()
        opener.open.side_effect = [
            Response(b'{"data":[{"id":"one"}],"links":{"next":"opaque+/="}}'),
            Response(b'{"data":[{"id":"two"}],"links":{"next":null}}'),
            Response(),
        ]
        client = CloudClient(ORG, SECRET, token_page_size=1, opener=opener)
        report = collect_operation(client, "org-api-tokens")
        self.assertEqual(
            (report["coverage"], report["saved_records"], report["requests"]), ("complete", 2, 2)
        )
        client.read_metadata("admin-api-keys")
        queries = [
            parse_qs(urlsplit(call.args[0].full_url).query) for call in opener.open.call_args_list
        ]
        self.assertEqual(
            queries,
            [
                {"pageSize": ["1"]},
                {"pageSize": ["1"], "cursor": ["opaque+/="]},
                {"pageSize": ["20"]},
            ],
        )
        for invalid in (0, 1001, True, 1.5, "1"):
            with self.assertRaises(ValueError):
                CloudClient(ORG, SECRET, token_page_size=invalid, opener=opener)
        self.assertEqual(opener.open.call_count, 3)

    def client(self, responses, **limits):
        opener, clock = Mock(), Clock()
        opener.open.side_effect = responses
        client = CloudClient(
            ORG,
            SECRET,
            Limits(**limits),
            opener=opener,
            clock=clock.now,
            wall_clock=lambda: 0,
            sleep=clock.sleep,
            jitter=lambda: 0,
        )
        return client, opener, clock

    def test_cursor_is_encoded_query_and_never_a_target_url(self):
        cursor = "https://example.invalid/steal?x=1&auth=" + SECRET
        client, opener, _ = self.client([Response()])
        result = client.fetch("org-api-tokens", {"pageSize": 20, "cursor": cursor})
        req = opener.open.call_args.args[0]
        url = urlsplit(req.full_url)
        self.assertEqual(
            (url.scheme, url.netloc, url.path),
            ("https", "api.atlassian.com", "/admin/api-access/v1/orgs/" + ORG + "/api-tokens"),
        )
        self.assertEqual(parse_qs(url.query), {"pageSize": ["20"], "cursor": [cursor]})
        self.assertEqual(req.get_method(), "GET")
        self.assertEqual(req.get_header("Authorization"), "Bearer " + SECRET)
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 15)
        self.assertEqual(result.attempts, 1)
        self.assertNotIn(SECRET, repr(result))

    def test_non_retryable_errors_and_redirect_do_not_read_or_replay(self):
        for status in (301, 302, 307, 400, 401, 403, 404):
            with self.subTest(status=status):
                response = Response(
                    SECRET.encode(), status, {"Location": "https://example.invalid"}
                )
                response.read1 = Mock(side_effect=AssertionError("Do not read error bodies"))
                client, opener, clock = self.client([response])
                result = client.fetch("admin-api-keys", {"pageSize": 20})
                self.assertEqual(result.reason, "http_" + str(status))
                self.assertEqual(opener.open.call_count, 1)
                self.assertEqual(clock.waits, [])
                response.read1.assert_not_called()
        self.assertIsNone(
            NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.invalid")
        )

    def test_429_honors_retry_after_and_reuses_request(self):
        error = urllib.error.HTTPError(
            "https://example.invalid",
            429,
            SECRET,
            {"Retry-After": "3"},
            io.BytesIO(SECRET.encode()),
        )
        client, opener, clock = self.client([error, Response()])
        result = client.fetch("org-api-tokens", {"pageSize": 20, "cursor": "next"})
        self.assertEqual((result.status, result.attempts, result.reason), (200, 2, None))
        self.assertEqual(clock.waits, [3])
        self.assertEqual(
            opener.open.call_args_list[0].args[0].full_url,
            opener.open.call_args_list[1].args[0].full_url,
        )

    def test_retry_header_date_reset_and_invalid_header_fallback(self):
        self.assertEqual(retry_delay({"Retry-After": "Thu, 01 Jan 1970 00:00:05 GMT"}, 0), 5)
        self.assertEqual(retry_delay({"X-RateLimit-Reset": "1970-01-01T00:00:07Z"}, 0), 7)
        self.assertEqual(
            retry_delay(
                {"Retry-After": "invalid", "X-RateLimit-Reset": "1970-01-01T00:00:07+00:00"}, 0
            ),
            7,
        )
        self.assertIsNone(retry_delay({"Retry-After": "inf", "X-RateLimit-Reset": "1970-01-01"}, 0))
        self.assertEqual(retry_delay({"Retry-After": "Thu, 01 Jan 1970 00:00:00 GMT"}, 10), 0)

    def test_large_server_delay_is_deferred_not_shortened(self):
        client, opener, clock = self.client([Response(status=429, headers={"Retry-After": "120"})])
        result = client.fetch("org-api-tokens", {"pageSize": 20})
        self.assertEqual(result.reason, "retry_wait_exceeds_limit")
        self.assertEqual((opener.open.call_count, clock.waits), (1, []))

    def test_transient_failure_backoff_is_bounded_and_sanitized(self):
        client, _opener, clock = self.client(
            [urllib.error.URLError(SECRET), Response(status=503), Response()]
        )
        result = client.fetch("service-account-api-tokens", {})
        self.assertEqual(result.attempts, 3)
        self.assertEqual(clock.waits, [1, 2])
        self.assertNotIn(SECRET, repr(result))
        exhausted, _, _ = self.client([Response(status=503) for _ in range(3)])
        result = exhausted.fetch("org-api-tokens", {})
        self.assertEqual((result.attempts, result.reason), (3, "http_503"))

    def test_request_and_elapsed_budgets_are_shared_across_sources(self):
        client, opener, _ = self.client([Response()], max_requests=1)
        client.fetch("admin-api-keys", {})
        result = client.fetch("org-api-tokens", {})
        self.assertEqual((result.attempts, result.reason), (0, "request_limit"))
        self.assertEqual(opener.open.call_count, 1)
        client, opener, clock = self.client(
            [Response(status=429, headers={"Retry-After": "5"})], max_seconds=3
        )
        result = client.fetch("org-api-tokens", {})
        self.assertEqual((result.reason, clock.waits), ("time_limit", []))
        clock.value = 4
        self.assertEqual(client.fetch("org-api-tokens", {}).reason, "time_limit")
        self.assertEqual(opener.open.call_count, 1)

    def test_large_and_malformed_success_bodies_fail_without_echoing(self):
        for body, reason in (
            (b"x" * (MAX_BYTES + 1), "response_too_large"),
            (SECRET.encode(), "invalid_json"),
            (b"\xff", "invalid_json"),
        ):
            with self.subTest(reason=reason):
                client, _opener, _ = self.client([Response(body)])
                result = client.fetch("admin-api-keys", {})
                self.assertEqual((result.reason, result.attempts), (reason, 1))
                self.assertNotIn(SECRET, repr(result))

    def test_time_budget_is_checked_between_read_chunks(self):
        client, opener, clock = self.client([], max_seconds=2)
        response = Response()

        def slow_read(size):
            clock.value = 3
            return b"{"

        response.read1 = Mock(side_effect=slow_read)
        opener.open.side_effect = [response]
        result = client.fetch("org-api-tokens", {})
        self.assertEqual((result.reason, result.attempts), ("time_limit", 1))
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 2)
        self.assertEqual(response.read1.call_count, 1)

    def test_bad_limits_auth_and_queries_fail_before_network(self):
        for limits in (
            {"max_pages": True},
            {"retries": -1},
            {"max_seconds": float("nan")},
            {"max_requests": 1001},
            {"max_retry_wait": float("inf")},
            {"timeout": 0},
        ):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                Limits(**limits)
        with self.assertRaises(ValueError):
            CloudClient(ORG, SECRET + "\n")
        client, opener, _ = self.client([])
        for source, query in (
            ("org-api-tokens", {"url": "https://example.invalid"}),
            ("service-account-api-tokens", {"cursor": "x"}),
            ("admin-api-keys", {"pageSize": True}),
        ):
            with self.subTest(source=source, query=query), self.assertRaises(ValueError):
                client.fetch(source, query)
        opener.open.assert_not_called()


if __name__ == "__main__":
    unittest.main()
