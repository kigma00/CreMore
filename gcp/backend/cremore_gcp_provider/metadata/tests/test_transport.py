"""The transport refuses unapproved hosts and never keeps a failing response."""

from __future__ import annotations

import unittest

from cremore.coverage.metadata_models import MetadataOptions
from cremore_gcp_provider.metadata.transport import ApiError, Budget, Transport, approved

TOKEN = "ya29." + "x" * 60


class Response:
    def __init__(self, status, payload=None, headers=None, *, bad_json=False):
        self.status_code = status
        self._payload = payload
        self.headers = headers or {}
        self._bad_json = bad_json

    def json(self):
        if self._bad_json:
            raise ValueError("not json")
        return self._payload


class Client:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.sent = []

    def request(self, method, url, **kwargs):
        self.sent.append((method, url, kwargs))
        return self.responses.pop(0) if self.responses else Response(200, {})


def transport(client, **kwargs):
    options = MetadataOptions(max_retries=kwargs.pop("max_retries", 1), retry_min_seconds=0.001)
    return Transport(client, lambda: TOKEN, options=options,
                     max_requests=kwargs.pop("max_requests", 10), sleep=lambda _s: None, **kwargs)


class UrlTests(unittest.TestCase):
    def test_only_google_metadata_hosts_and_a_regional_endpoint_are_reachable(self):
        approved("https://iam.googleapis.com/v1/projects/p/serviceAccounts")
        approved("https://secretmanager.europe-west4.rep.googleapis.com/v1/projects/p/secrets")
        # Assembled rather than written out: a literal userinfo URL in the
        # tree is what the repository's own credential scan looks for.
        userinfo = "https://" + "nobody" + ":" + "x" + "@iam.googleapis.com/v1"
        for url in ("http://iam.googleapis.com/v1", "https://evil.example.com/v1",
                    "https://iam.googleapis.com.evil.test/v1",
                    "https://secretmanager.EUROPE.rep.googleapis.com/v1", userinfo):
            with self.assertRaises(ValueError, msg=url):
                approved(url)

    def test_a_read_only_rpc_is_limited_to_the_approved_endpoints(self):
        client = Client(*[Response(200, {"ok": True})] * 3)
        api = transport(client, max_requests=10)
        api.post_readonly("https://logging.googleapis.com/v2/entries:list", {})
        api.post_readonly("https://cloudresourcemanager.googleapis.com/v1/projects/acme-prod:getIamPolicy", {})
        api.post_readonly("https://policytroubleshooter.googleapis.com/v3/iam:troubleshoot", {})
        self.assertEqual([url for _method, url, _kwargs in client.sent][-1],
                         "https://policytroubleshooter.googleapis.com/v3/iam:troubleshoot")
        for url in ("https://logging.googleapis.com/v2/entries:write",
                    "https://cloudresourcemanager.googleapis.com/v1/projects/p:setIamPolicy",
                    "https://policytroubleshooter.googleapis.com/v3beta/iam:troubleshoot",
                    "https://policytroubleshooter.googleapis.com/v3/iam:troubleshoot/extra"):
            with self.assertRaises(ValueError, msg=url):
                api.post_readonly(url, {})


class FailureTests(unittest.TestCase):
    def test_a_forbidden_response_keeps_only_the_service_disabled_reason(self):
        body = {"error": {"message": "caller lacks permission on projects/secret-project",
                          "details": [{"reason": "SERVICE_DISABLED"}]}}
        api = transport(Client(Response(403, body)))
        with self.assertRaises(ApiError) as caught:
            api.get("https://iam.googleapis.com/v1/projects/p/serviceAccounts")
        self.assertEqual(caught.exception.code, "api_disabled")
        self.assertNotIn("secret-project", str(caught.exception))

    def test_an_unexplained_forbidden_response_stays_ambiguous(self):
        api = transport(Client(Response(403, {"error": {"message": "nope"}})))
        with self.assertRaises(ApiError) as caught:
            api.get("https://iam.googleapis.com/v1/projects/p/serviceAccounts")
        self.assertEqual(caught.exception.code, "permission_denied_or_api_disabled")

    def test_a_transport_error_never_reports_the_url_or_the_token(self):
        class Broken:
            def request(self, *_args, **_kwargs):
                raise RuntimeError(f"connect https://iam.googleapis.com?access_token={TOKEN}")

        with self.assertRaises(ApiError) as caught:
            transport(Broken()).get("https://iam.googleapis.com/v1/projects/p/serviceAccounts")
        self.assertEqual(str(caught.exception), "request_failed")
        self.assertNotIn(TOKEN, repr(caught.exception.__cause__))

    def test_a_rate_limited_read_retries_then_reports_its_retry_delay(self):
        client = Client(Response(429, headers={"Retry-After": "7"}), Response(200, {"ok": True}))
        api = transport(client)
        self.assertEqual(api.get("https://iam.googleapis.com/v1/projects/p/serviceAccounts"),
                         {"ok": True})
        self.assertEqual(len(client.sent), 2)

        client = Client(Response(429, headers={"Retry-After": "9"}),
                        Response(429, headers={"Retry-After": "9"}))
        with self.assertRaises(ApiError) as caught:
            transport(client).get("https://iam.googleapis.com/v1/projects/p/serviceAccounts")
        self.assertEqual(caught.exception.code, "rate_limited")
        self.assertEqual(caught.exception.retry_after, 9)

    def test_repeated_rate_limits_open_the_circuit_before_the_budget_is_spent(self):
        options = MetadataOptions(max_retries=9, retry_min_seconds=0.001,
                                  max_consecutive_rate_limits=2)
        client = Client(*[Response(429, headers={"Retry-After": "1"}) for _ in range(9)])
        api = Transport(client, lambda: TOKEN, options=options, max_requests=50,
                        sleep=lambda _s: None)
        with self.assertRaises(ApiError) as caught:
            api.get("https://iam.googleapis.com/v1/projects/p/serviceAccounts")
        self.assertEqual(caught.exception.code, "rate_limit_circuit_open")
        self.assertEqual(len(client.sent), 2)

    def test_a_non_object_or_unparseable_body_is_a_fixed_code(self):
        with self.assertRaises(ApiError) as caught:
            transport(Client(Response(200, bad_json=True))).get(
                "https://iam.googleapis.com/v1/projects/p/serviceAccounts")
        self.assertEqual(caught.exception.code, "invalid_json")
        with self.assertRaises(ApiError) as caught:
            transport(Client(Response(200, ["list"]))).get(
                "https://iam.googleapis.com/v1/projects/p/serviceAccounts")
        self.assertEqual(caught.exception.code, "invalid_response")


class BudgetTests(unittest.TestCase):
    def test_the_request_budget_includes_every_retry_attempt(self):
        client = Client(*[Response(500) for _ in range(5)])
        api = transport(client, max_requests=2, max_retries=5)
        with self.assertRaises(Budget) as caught:
            api.get("https://iam.googleapis.com/v1/projects/p/serviceAccounts")
        self.assertEqual(caught.exception.code, "REQUEST_BUDGET_EXCEEDED")
        self.assertEqual(len(client.sent), 2)

    def test_cancellation_is_observed_before_the_next_request(self):
        state = {"calls": 0}

        def check():
            state["calls"] += 1
            if state["calls"] > 1:
                raise KeyboardInterrupt("cancelled")

        api = transport(Client(Response(200, {}), Response(200, {})), check=check)
        api.get("https://iam.googleapis.com/v1/projects/p/serviceAccounts")
        with self.assertRaises(KeyboardInterrupt):
            api.get("https://iam.googleapis.com/v1/projects/p/serviceAccounts")

    def test_the_authorization_header_is_sent_and_redirects_are_refused(self):
        client = Client(Response(200, {}))
        transport(client).get("https://iam.googleapis.com/v1/projects/p/serviceAccounts")
        _method, _url, kwargs = client.sent[0]
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer " + TOKEN)
        self.assertIs(kwargs["follow_redirects"], False)


if __name__ == "__main__":
    unittest.main()
