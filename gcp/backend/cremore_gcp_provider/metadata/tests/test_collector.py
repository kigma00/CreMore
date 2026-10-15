"""The native inventory contract: allowlists, paging, coverage and lifecycle."""

from __future__ import annotations

import unittest

from cremore_gcp_provider.metadata.collector import (
    Collector,
    lifecycle,
    resolved_error,
    secret_api_base,
    time_value,
    validate_options,
)
from cremore_gcp_provider.metadata.transport import ApiError

from .fake import EMAIL, PROJECT, SECRET, FakeTransport, inventory_responses


def collector(transport, **kwargs):
    return Collector(PROJECT, transport, **kwargs)


class OptionTests(unittest.TestCase):
    def test_project_and_page_bounds_are_checked_before_any_request(self):
        for project in ("", "A-Project", "x", "project_with_underscore"):
            with self.assertRaises(ValueError):
                validate_options(project, 10)
        with self.assertRaises(ValueError):
            validate_options(PROJECT, 0)
        validate_options(PROJECT, 1)

    def test_a_regional_endpoint_comes_from_the_name_grammar_not_a_response(self):
        self.assertEqual(secret_api_base(SECRET), "https://secretmanager.googleapis.com/v1")
        regional = f"projects/{PROJECT}/locations/europe-west4/secrets/a"
        self.assertEqual(secret_api_base(regional),
                         "https://secretmanager.europe-west4.rep.googleapis.com/v1")
        with self.assertRaises(ApiError):
            secret_api_base(f"projects/{PROJECT}/locations/-bad/secrets/a")

    def test_a_forbidden_read_is_resolved_only_by_the_service_state(self):
        self.assertEqual(resolved_error("permission_denied_or_api_disabled", "enabled"),
                         "permission_denied")
        self.assertEqual(resolved_error("permission_denied_or_api_disabled", "disabled"),
                         "api_disabled")
        self.assertEqual(resolved_error("permission_denied_or_api_disabled", "unknown"),
                         "permission_denied_or_api_disabled")
        self.assertEqual(resolved_error(None, "enabled"), None)

    def test_only_a_parseable_timestamp_is_copied(self):
        self.assertEqual(time_value("2026-01-01T00:00:00Z"), "2026-01-01T00:00:00Z")
        for value in (None, 17, "yesterday", "2026-13-01T00:00:00Z", "x" * 41):
            self.assertIsNone(time_value(value))


class PagingTests(unittest.TestCase):
    def setUp(self):
        self.url = f"https://iam.googleapis.com/v1/projects/{PROJECT}/serviceAccounts"

    def pages(self, responses, **kwargs):
        transport = FakeTransport(responses)
        return transport, list(collector(transport, **kwargs).pages(self.url, "accounts"))

    def test_every_page_is_handed_back_with_the_cursor_that_follows_it(self):
        transport, pages = self.pages({
            (self.url, ""): {"accounts": [{"email": EMAIL}], "nextPageToken": "t1"},
            (self.url, "t1"): {"accounts": [{"email": EMAIL}]},
        })
        self.assertEqual([page.status for page in pages], ["running", "complete"])
        self.assertEqual(pages[0].cursor["page_token"], "t1")
        self.assertIsNone(pages[1].cursor)
        self.assertEqual([call[2].get("pageToken") for call in transport.calls], [None, "t1"])

    def test_a_repeated_page_token_stops_the_list_as_partial(self):
        _, pages = self.pages({
            (self.url, ""): {"accounts": [], "nextPageToken": "loop"},
            (self.url, "loop"): {"accounts": [], "nextPageToken": "loop"},
        })
        self.assertEqual(pages[-1].status, "partial")
        self.assertEqual(pages[-1].error, "page_token_cycle")

    def test_the_page_ceiling_is_partial_and_never_a_complete_listing(self):
        _, pages = self.pages({(self.url, ""): {"accounts": [], "nextPageToken": "a"},
                               (self.url, "a"): {"accounts": [], "nextPageToken": "b"}},
                              max_pages=2)
        self.assertEqual([page.status for page in pages], ["running", "running", "partial"])
        self.assertEqual(pages[-1].error, "page_limit_reached")

    def test_a_failure_keeps_the_rows_already_returned(self):
        _, pages = self.pages({
            (self.url, ""): {"accounts": [{"email": EMAIL}], "nextPageToken": "t1"},
        })
        self.assertEqual(pages[0].rows, [{"email": EMAIL}])
        self.assertEqual((pages[1].status, pages[1].error), ("partial", "http_404"))

    def test_a_response_that_is_not_a_list_of_objects_is_rejected(self):
        _, pages = self.pages({self.url: {"accounts": [{"email": EMAIL}, "nope"]}})
        self.assertEqual((pages[0].status, pages[0].error), ("partial", "invalid_response"))


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.transport = FakeTransport(inventory_responses())
        self.collector = collector(self.transport)

    def rows(self, url, field, **kwargs):
        return [page for page in self.collector.pages(url, field, **kwargs)][-1].rows

    def test_numeric_aliases_need_the_approved_project_canonical_metadata(self):
        c = self.collector
        self.assertTrue(c.project_resource(SECRET))
        self.assertEqual(self.transport.calls, [])
        self.assertTrue(c.project_resource("projects/419699000000/secrets/example"))
        self.assertFalse(c.project_resource("projects/419699000001/secrets/example"))
        self.assertFalse(c.project_resource("projects/other-project/secrets/example"))
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(c.project_aliases, {PROJECT, "419699000000"})

    def test_unavailable_or_mismatched_alias_metadata_never_authorizes_a_numeric_parent(self):
        url = f"https://cloudresourcemanager.googleapis.com/v3/projects/{PROJECT}"
        for response in ({"projectId": "other-project", "name": "projects/419699000000"},
                         {"projectId": PROJECT, "name": "projects/not-a-number"}, []):
            with self.subTest(response=response):
                transport = FakeTransport({url: response})
                c = collector(transport)
                self.assertFalse(c.project_resource("projects/419699000000/secrets/example"))
                self.assertTrue(c.project_resource(SECRET))
        transport = FakeTransport(failures={url: "permission_denied"})
        c = collector(transport)
        for _ in range(2):
            self.assertFalse(c.project_resource("projects/419699000000/secrets/example"))
        self.assertEqual(len(transport.calls), 1)

    def test_an_unparseable_service_account_is_counted_not_stored(self):
        rows = self.rows(f"https://iam.googleapis.com/v1/projects/{PROJECT}/serviceAccounts",
                         "accounts")
        items, invalid = self.collector.service_accounts(rows)
        self.assertEqual(invalid, 1)
        self.assertEqual([item["service_account_email"] for item in items].count(EMAIL), 1)
        self.assertEqual(items[0]["object_type"], "principal")

    def test_both_key_types_are_kept_and_an_unknown_one_is_an_error_count(self):
        items, errors = self.collector.service_account_keys(EMAIL)
        self.assertEqual({item["credential_type"] for item in items},
                         {"service_account_user_managed_key", "service_account_system_managed_key"})
        self.assertEqual(errors, {"invalid_key_identifier": 1})
        self.assertTrue(all(item["source_id"].startswith(f"projects/{PROJECT}/") for item in items))

    def test_a_key_listing_never_contains_private_key_material(self):
        items, _ = self.collector.service_account_keys(EMAIL)
        serialized = repr(items)
        self.assertNotIn("privateKeyData", serialized)
        self.assertNotIn("PRIVATE KEY", serialized)

    def test_one_client_restriction_is_named_and_several_are_ambiguous(self):
        items, invalid = self.collector.api_keys([
            {"name": "projects/419699000000/locations/global/keys/a", "restrictions": {
                "browserKeyRestrictions": {}, "serverKeyRestrictions": {}}},
            {"name": "projects/419699000000/locations/global/keys/b", "restrictions": {
                "apiTargets": [{"service": "maps.googleapis.com"}]}},
            {"name": "projects/419699000000/locations/global/keys/c"},
            {"name": "not-a-key"},
        ])
        self.assertEqual(invalid, 1)
        self.assertEqual([item["client_restriction_type"] for item in items],
                         ["ambiguous", "none", "unknown"])
        self.assertEqual(items[1]["api_target_services"], ["maps.googleapis.com"])
        # A listing gives the key's metadata, never the key string itself.
        self.assertNotIn("keyString", repr(items))

    def test_customer_labels_are_counted_and_not_carried_into_the_item(self):
        items, _ = self.collector.secrets([
            {"name": SECRET, "labels": {"team": "platform", "cost": "abc"}}])
        self.assertEqual(items[0]["label_count"], 2)
        self.assertNotIn("platform", repr(items))

    def test_a_regional_secret_must_carry_the_region_it_was_read_from(self):
        wrong = f"projects/{PROJECT}/locations/us-east1/secrets/a"
        items, invalid = self.collector.secrets([{"name": wrong}], region="europe-west4")
        self.assertEqual((items, invalid), ([], 1))

    def test_only_the_three_documented_version_states_are_stored(self):
        items, invalid = self.collector.versions([
            {"name": SECRET + "/versions/1", "state": "ENABLED"},
            {"name": SECRET + "/versions/2", "state": "PENDING"},
            {"name": "projects/other/secrets/x/versions/1", "state": "ENABLED"},
        ], SECRET)
        self.assertEqual([item["state"] for item in items], ["ENABLED"])
        self.assertEqual(invalid, 2)

    def test_a_disabled_service_does_not_decide_what_a_listing_returned(self):
        transport = FakeTransport({
            f"https://serviceusage.googleapis.com/v1/projects/{PROJECT}/services/"
            "iam.googleapis.com": {"state": "DISABLED"}})
        self.assertEqual(collector(transport).service_state("iam.googleapis.com"),
                         {"state": "disabled", "error_code": None})
        self.assertEqual(collector(transport).service_state("apikeys.googleapis.com"),
                         {"state": "unknown", "error_code": "http_404"})


class LifecycleTests(unittest.TestCase):
    def test_a_listing_gap_is_never_turned_into_a_deletion(self):
        self.assertEqual(lifecycle({"credential_type": "api_key", "deleted_at": "2026-01-01T00:00:00Z"}),
                         "deleted")
        self.assertEqual(lifecycle({"credential_type": "api_key"}), "active")
        self.assertEqual(lifecycle({"credential_type": "secret_version", "state": "DESTROYED"}),
                         "destroyed")
        self.assertEqual(lifecycle({"credential_type": "secret_version", "state": "PENDING"}),
                         "unknown")
        self.assertEqual(lifecycle({"disabled": True}), "disabled")
        self.assertEqual(lifecycle({"disabled": None}), "active")

    def test_a_service_account_key_past_its_valid_before_time_is_expired(self):
        key = {"source": "gcp_iam_service_account_keys", "credential_type": "service_account_user_managed_key",
               "disabled": False, "valid_before_time": "2026-09-21T12:00:00Z"}
        self.assertEqual(lifecycle(key, "2026-09-21T12:00:00+00:00"), "expired")
        self.assertEqual(lifecycle(key, "2026-09-21T11:59:59+00:00"), "active")
        # Without an observation time (the native export) and for a naive timestamp, nothing is inferred.
        self.assertEqual(lifecycle(key), "active")
        self.assertEqual(lifecycle({**key, "valid_before_time": "2020-01-01T00:00:00"}, "2026-09-21T12:00:00+00:00"),
                         "active")
        self.assertEqual(lifecycle({**key, "disabled": True}, "2026-09-21T12:00:00+00:00"), "disabled")


if __name__ == "__main__":
    unittest.main()
