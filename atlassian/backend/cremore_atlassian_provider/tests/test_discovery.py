"""Broad metadata preservation and bounded public read operations."""

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from cremore_atlassian_provider.metadata.discovery import (
    collect_discovery,
    collect_operation,
    discover_targets,
    discovery_summary,
)
from cremore_atlassian_provider.metadata.http import CloudClient, FetchResult, Limits
from cremore_atlassian_provider.metadata.read_operations import (
    READ_OPERATIONS,
    STATIC_OPERATIONS,
    operation_url,
    validate_next_url,
)
from cremore_atlassian_provider.metadata.snapshot import field_catalog, metadata_snapshot

from . import posix_native_io
from . import test_collector_cli as cli_helpers
from .test_collector import NOW, ORG, SECRET


class Response(io.BytesIO):
    def __init__(self, body):
        super().__init__(json.dumps(body).encode())
        self.code, self.headers = 200, {}


class Client:
    def __init__(self, pages, **limits):
        self.org_id, self.requests, self.calls = ORG, 0, []
        self.limits = Limits(**limits)
        self.pages = {name: iter(items) for name, items in pages.items()}

    def read_metadata(self, operation, **kwargs):
        self.calls.append((operation, kwargs))
        self.requests += 1
        return next(self.pages[operation])

    def snapshot(self, body):
        return metadata_snapshot(body, sensitive_values=(SECRET,))


def ok(body):
    return FetchResult(200, body, 1)


def empty_baseline():
    return {
        name: [
            ok({"data": [], "links": {"next": None}})
            if READ_OPERATIONS[name]["shape"] == "data"
            else ok([])
            if READ_OPERATIONS[name]["shape"] in ("array", "array_or_data")
            else ok({"items": [], "links": {}, "total": 0})
            if name == "service-accounts"
            else ok({"total": 0})
            if name == "org-oauth-client-count"
            else ok(0)
        ]
        for name in STATIC_OPERATIONS
    }


class SnapshotTests(unittest.TestCase):
    def test_jwk_private_and_symmetric_parameters_are_omitted_without_losing_public_fields(self):
        private = {
            name: "synthetic-private-" + name
            for name in ("d", "p", "q", "dp", "dq", "qi", "oth", "k")
        }
        for key_type in ("RSA", "EC", "OKP", "oct", None):
            with self.subTest(key_type=key_type):
                result, stats = metadata_snapshot(
                    {
                        "keys": [
                            dict(private, kty=key_type, kid="public-id", n="public-n", x="public-x")
                        ]
                    }
                )
                saved = result["keys"][0]
                self.assertTrue(all(isinstance(saved[name], dict) for name in private))
                self.assertEqual(
                    (saved["kid"], saved["n"], saved["x"]), ("public-id", "public-n", "public-x")
                )
                self.assertEqual(stats["secret_fields_omitted"], len(private))
                self.assertNotIn("synthetic-private-", json.dumps(result))
        result, _ = metadata_snapshot({"keys": [private], "ordinary": {"d": "ordinary-data"}})
        self.assertNotIn("synthetic-private-", json.dumps(result))
        self.assertEqual(result["ordinary"]["d"], "ordinary-data")

    def test_unselected_nested_metadata_and_provider_types_are_preserved(self):
        body = {
            "futureField": {
                "nullable": None,
                "disabled": False,
                "expiry": 123,
                "labels": ["x", {"rank": 1.5}],
            },
            "tokenEndpointAuthMethod": "client_secret_post",
            "apiToken.read": {"allowed": True},
        }
        snapshot, stats = metadata_snapshot(body)
        self.assertEqual(snapshot, body)
        self.assertEqual(sum(stats.values()), 0)
        self.assertEqual(field_catalog(snapshot)["/futureField/labels/[]"], ["dict", "str"])

    def test_secret_names_and_known_auth_values_removed_recursively(self):
        body = {
            "clientSecret": SECRET,
            "nested": [{"refresh_token": SECRET, "Private-Key": SECRET}],
            "label": "prefix" + SECRET,
            SECRET: "hidden",
            "future": "Bearer synthetic",
            "pem": "-----BEGIN RSA PRIVATE KEY-----",
            "disabled": False,
        }
        snapshot, stats = metadata_snapshot(body, sensitive_values=(SECRET,))
        self.assertNotIn(SECRET, json.dumps(snapshot))
        self.assertEqual(stats["secret_fields_omitted"], 3)
        self.assertEqual(stats["sensitive_values_omitted"], 4)
        self.assertFalse(snapshot["disabled"])

    def test_limits_non_json_and_pointer_escaping_are_explicit(self):
        snapshot, stats = metadata_snapshot(
            {"a": {"b": {"c": 1}}, "notJson": float("nan")}, max_depth=1
        )
        self.assertGreater(stats["truncated_nodes"], 0)
        json.dumps(snapshot, allow_nan=False)
        self.assertIn("/a~1b~0", field_catalog({"a/b~": []}))

    def test_node_limit_bounds_wide_arrays_and_secret_field_maps(self):
        snapshot, stats = metadata_snapshot(list(range(10000)), max_nodes=4)
        self.assertEqual(snapshot[:3], [0, 1, 2])
        self.assertEqual(len(snapshot), 4)
        self.assertEqual(stats["truncated_nodes"], 9997)
        body = {"field" + str(n) + "Secret": SECRET for n in range(10000)}
        body["_cremore_omitted_tail"] = "provider value"
        snapshot, stats = metadata_snapshot(body, max_nodes=4)
        self.assertEqual(len(snapshot), 4)
        self.assertIn("_cremore_omitted_tail_", snapshot)
        self.assertEqual(stats["secret_fields_omitted"], 3)
        self.assertNotIn(SECRET, json.dumps(snapshot))


class ReadTransportTests(unittest.TestCase):
    def test_only_fixed_read_only_post_operations_and_batches(self):
        opener = Mock()
        opener.open.side_effect = [
            Response({"validServiceAccountIds": [], "invalidServiceAccountIds": ["user-1"]}),
            Response({"validServiceAccountIds": [], "invalidServiceAccountIds": ["user-1"]}),
        ]
        client = CloudClient(ORG, SECRET, opener=opener)
        client.read_metadata("org-oauth-client-count", body=["user-1"])
        client.read_metadata("service-account-token-counts", body=["user-1"])
        first, second = [c.args[0] for c in opener.open.call_args_list]
        self.assertEqual(first.get_method(), "POST")
        self.assertEqual(json.loads(first.data), ["user-1"])
        self.assertEqual(first.get_header("Content-type"), "application/json")
        self.assertEqual(second.get_method(), "POST")
        self.assertEqual(json.loads(second.data), ["user-1"])
        self.assertEqual(second.get_header("Content-type"), "application/json")
        self.assertNotIn(SECRET, json.dumps(client.snapshot({"future": SECRET})[0]))

    def test_invalid_targets_body_or_write_operation_make_no_request(self):
        opener = Mock()
        client = CloudClient(ORG, SECRET, opener=opener)
        cases = [
            ("oauth-client-detail", {"identifier": "../api-keys"}),
            ("oauth-client-detail", {"identifier": "https://example.invalid"}),
            ("org-oauth-client-count", {"body": {"secret": SECRET}}),
            ("service-account-token-counts", {"body": ["x"] * 101}),
            ("service-account-token-counts", {"body": ["same", "same"]}),
            ("service-account-token-counts", {"body": ["x" * 101]}),
            ("service-account-token-counts", {"body": []}),
            ("delete-oauth-client", {}),
        ]
        for operation, kwargs in cases:
            with (
                self.subTest(operation=operation, kwargs=kwargs),
                self.assertRaises((ValueError, KeyError)),
            ):
                client.read_metadata(operation, **kwargs)
        opener.open.assert_not_called()

    def test_pagination_cannot_change_origin_resource_or_auth_destination(self):
        base = operation_url("service-accounts", ORG)
        self.assertEqual(validate_next_url(base, "?cursor=abc"), base + "?cursor=abc")
        for target in (
            "https://example.invalid/?cursor=x",
            "//example.invalid/",
            base.replace("/service-accounts", "/api-keys"),
            base + "#fragment",
            "http://api.atlassian.com/" + base.split("/", 3)[-1],
            base + "?cursor=a\nb",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                validate_next_url(base, target)
        opener = Mock()
        opener.open.return_value = Response([])
        client = CloudClient(ORG, SECRET, opener=opener)
        client.read_metadata("service-account-api-tokens-by-account", identifier="712020:abc-def")
        self.assertIn("712020%3Aabc-def", opener.open.call_args.args[0].full_url)
        self.assertEqual(opener.open.call_args.args[0].get_method(), "GET")


class DiscoveryTests(unittest.TestCase):
    def test_cursor_pages_keep_all_metadata_with_count_and_source(self):
        client = Client(
            {
                "admin-api-keys": [
                    ok(
                        {
                            "data": [{"id": "one", "newField": {"nested": 3}}],
                            "links": {"next": "opaque"},
                        }
                    ),
                    ok({"data": [{"id": "two"}], "links": {"next": None}}),
                ]
            }
        )
        report = collect_operation(client, "admin-api-keys", now=lambda: NOW)
        self.assertEqual(report["coverage"], "complete")
        self.assertEqual(report["saved_records"], 2)
        self.assertEqual(report["pages"][0]["metadata"]["data"][0]["newField"], {"nested": 3})
        self.assertEqual(client.calls[1][1]["cursor"], "opaque")

    def test_failed_next_page_keeps_prior_snapshot(self):
        client = Client(
            {
                "admin-api-keys": [
                    ok({"data": [{"id": "x"}], "links": {"next": "n"}}),
                    FetchResult(403, attempts=1, reason="http_403"),
                ]
            }
        )
        report = collect_operation(client, "admin-api-keys")
        self.assertEqual(
            (report["coverage"], report["reason"], report["requests"]), ("partial", "http_403", 2)
        )
        self.assertEqual(len(report["pages"]), 1)

    def test_limits_duplicates_missing_links_and_unknown_shape_do_not_claim_complete(self):
        cases = [
            (
                [ok({"data": [{"id": "x"}, {"id": "y"}], "links": {"next": None}})],
                {"max_records": 1},
                "partial",
                "record_limit",
            ),
            ([ok({"data": [], "links": {"next": "n"}})], {"max_pages": 1}, "partial", "page_limit"),
            ([ok({"data": []})], {}, "partial", "missing_pagination_contract"),
            (
                [
                    ok({"data": [], "links": {"next": "same"}}),
                    ok({"data": [], "links": {"next": "same"}}),
                ],
                {},
                "partial",
                "repeated_pagination",
            ),
            ([ok({"unexpected": {"new": True}})], {}, "unverified", "unexpected_response_shape"),
        ]
        for pages, limits, status, reason in cases:
            with self.subTest(reason=reason):
                report = collect_operation(
                    Client({"admin-api-keys": pages}, **limits), "admin-api-keys"
                )
                self.assertEqual((report["coverage"], report["reason"]), (status, reason))
                self.assertEqual(len(report["pages"]) > 0, True)

    def test_a_last_page_without_a_next_cursor_is_complete(self):
        # API Access: "If there are more results ... a `next` cursor is included in the response links."
        report = collect_operation(Client({"admin-api-keys": [ok({"data": [], "links": {}})]}), "admin-api-keys")
        self.assertEqual((report["coverage"], report["reason"]), ("complete", None))

    def test_count_contract_rejects_boolean_and_negative_without_losing_metadata(self):
        for value in (True, -1, {"total": 2}):
            report = collect_operation(
                Client({"admin-api-key-count": [ok(value)]}), "admin-api-key-count"
            )
            self.assertEqual(report["coverage"], "unverified")
            self.assertEqual(report["pages"][0]["metadata"], value)

    def test_url_paging_absent_terminal_next_and_observed_array(self):
        client = Client(
            {
                "service-accounts": [
                    ok({"items": [], "links": {"next": "?cursor=next"}, "total": 1}),
                    ok({"items": [{"id": "s"}], "links": {}, "total": 1}),
                ]
            }
        )
        report = collect_operation(client, "service-accounts")
        self.assertEqual(report["coverage"], "complete")
        self.assertEqual(client.calls[1][1]["next_url"], "?cursor=next")
        report = collect_operation(
            Client({"org-oauth-clients": [ok([{"clientId": "x", "custom": ["a"]}])]}),
            "org-oauth-clients",
        )
        self.assertEqual(report["coverage"], "unverified")
        self.assertEqual(report["pages"][0]["metadata"][0]["custom"], ["a"])

    def test_observed_targets_fan_out_independently_of_service_list_failure(self):
        pages = empty_baseline()
        pages["service-account-api-tokens"] = [ok([{"id": "token", "user": {"id": "service-1"}}])]
        pages["service-account-oauth-clients"] = [
            ok(
                [
                    {
                        "clientId": "client-1",
                        "serviceAccount": {"id": "service-1"},
                        "createdBy": {"id": "human-1"},
                    }
                ]
            )
        ]
        pages["service-accounts"] = [FetchResult(404, attempts=1, reason="http_404")]
        pages["service-account-token-counts"] = [
            ok(
                {
                    "validServiceAccountIds": [
                        {"serviceAccountId": "service-1", "credentialsCount": 1}
                    ],
                    "invalidServiceAccountIds": [],
                }
            )
        ]
        pages["service-account-api-tokens-by-account"] = [ok([])]
        pages["org-oauth-client-count"] = [ok({
            "validServiceAccountIds": [{"serviceAccountId": "service-1", "credentialsCount": 1}],
            "invalidServiceAccountIds": [],
        })]
        pages["service-account-oauth-clients-by-account"] = [ok([])]
        pages["oauth-client-detail"] = [ok({"clientId": "client-1", "new": 5})]
        for op in ("user-management-permissions", "user-profile", "user-api-tokens"):
            pages[op] = [
                FetchResult(403, attempts=1, reason="http_403"),
                FetchResult(403, attempts=1, reason="http_403"),
            ]
        client = Client(pages)
        result = collect_discovery(client)
        self.assertEqual(result["target_discovery"]["service_account_ids"], ["service-1"])
        self.assertEqual(result["target_discovery"]["user_ids"], ["human-1", "service-1"])
        self.assertEqual(result["run_status"], "partial")
        self.assertTrue(
            any(
                r["operation"] == "oauth-client-detail" and r["pages"]
                for r in result["collections"]
            )
        )
        output = json.dumps(discovery_summary(result))
        for value in ("service-1", "human-1", "client-1", ORG):
            self.assertNotIn(value, output)

    def test_empty_source_reports_dependency_gaps_and_counts_are_not_proof(self):
        result = collect_discovery(Client(empty_baseline()))
        self.assertIn("oauth-client-detail", result["not_requested_no_observed_targets"])
        self.assertEqual(result["run_status"], "unverified")
        self.assertTrue(all(c["equal_at_observation"] for c in result["count_comparisons"]))
        self.assertTrue(all(not c["proves_completeness"] for c in result["count_comparisons"]))

    def test_invalid_target_ids_are_not_queried(self):
        report = collect_operation(
            Client({"service-account-api-tokens": [ok([{"user": {"id": "../unsafe"}}])]}),
            "service-account-api-tokens",
        )
        targets = discover_targets([report])
        self.assertEqual(targets["service_account_ids"], [])
        self.assertGreater(targets["invalid_identifiers"], 0)

    def test_global_request_limit_prevents_additional_network_reads(self):
        opener = Mock()
        opener.open.return_value = Response({"data": [], "links": {"next": None}})
        client = CloudClient(ORG, SECRET, Limits(max_requests=1, retries=0), opener=opener)
        result = collect_discovery(client)
        self.assertEqual(opener.open.call_count, 1)
        self.assertEqual(discovery_summary(result)["request_count"], 1)
        self.assertEqual(result["run_status"], "partial")
        self.assertTrue(any(r["reason"] == "request_limit" for r in result["collections"]))

    def test_target_limit_is_reported_and_no_guessed_user_ids_are_added(self):
        pages = empty_baseline()
        pages["managed-accounts"] = [
            ok({"data": [{"account_id": "person-b"}, {"account_id": "person-a"}], "links": {}})
        ]
        for op in ("user-management-permissions", "user-profile", "user-api-tokens"):
            pages[op] = [FetchResult(403, attempts=1, reason="http_403")]
        client = Client(pages)
        result = collect_discovery(client, max_targets=1)
        self.assertEqual(result["targets_omitted_by_limit"]["user_ids"], 1)
        self.assertEqual(result["target_discovery"]["user_ids"], ["person-a"])
        self.assertEqual(
            [kwargs["identifier"] for op, kwargs in client.calls if op == "user-profile"],
            ["person-a"],
        )

    def test_discovery_and_explicit_sources_are_rejected_before_network(self):
        helper = cli_helpers.CliTests()
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            helper.connection(directory)
            code, _output, opener = helper.invoke(
                directory, [], ["--profile", "lab", "--discovery", "--sources", "admin-api-keys"]
            )
            self.assertEqual(code, 2)
            opener.open.assert_not_called()

    @posix_native_io
    def test_cli_discovery_private_output_and_existing_inventory_mode_are_separate(self):
        helper = cli_helpers.CliTests()
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            helper.connection(directory)
            bodies = [next(iter(empty_baseline()[op])).body for op in STATIC_OPERATIONS]
            bodies[0] = {
                "data": [
                    {
                        "id": "metadata-only",
                        "label": "private@example.invalid",
                        "futureField": {"x": 1},
                        "clientSecret": SECRET,
                    }
                ],
                "links": {"next": None},
            }
            code, output, opener = helper.invoke(
                directory,
                [cli_helpers.Response(b) for b in bodies],
                ["--profile", "lab", "--discovery", "--max-targets", "1", "--token-page-size", "1"],
            )
            self.assertEqual(code, 1)
            summary = json.loads(output)
            self.assertEqual(summary["report_type"], "metadata_discovery")
            self.assertNotIn("private@example.invalid", output)
            saved = json.loads(next(directory.glob("inventory-*.json")).read_text())
            self.assertNotIn(SECRET, json.dumps(saved))
            self.assertIn("futureField", json.dumps(saved))
            self.assertNotIn("inventory", saved)
            self.assertEqual(opener.open.call_count, len(STATIC_OPERATIONS))
            self.assertEqual(saved["limits"]["org_api_tokens_page_size"], 1)
            token_request = opener.open.call_args_list[
                list(STATIC_OPERATIONS).index("org-api-tokens")
            ].args[0]
            self.assertTrue(token_request.full_url.endswith("/api-tokens?pageSize=1"))


if __name__ == "__main__":
    unittest.main()
