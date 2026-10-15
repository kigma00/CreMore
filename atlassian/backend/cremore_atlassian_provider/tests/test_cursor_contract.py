"""Executable preparation scenarios, entirely offline and independent of secrets."""

import json
import unittest
from copy import deepcopy
from dataclasses import asdict

from cremore_atlassian_provider.metadata.qa.cursor_collection import Page, collect_cursor_pages


def page(records=None, next_cursor=None):
    return Page(
        200,
        {
            "data": records if records is not None else [{"id": "example-1"}],
            "links": {"next": next_cursor},
        },
    )


class ScriptedTransport:
    def __init__(self, pages):
        self.pages = iter(pages)
        self.requests = []

    def __call__(self, query):
        self.requests.append(deepcopy(query))
        result = next(self.pages)
        if isinstance(result, Exception):
            raise result
        return result


class CursorContractTests(unittest.TestCase):
    def test_multpage_preserves_query_and_opaque_cursor_and_missing_fields(self):
        params = {"pageSize": 5, "sort": "label", "q": "key"}
        original = deepcopy(params)
        fetch = ScriptedTransport([
            page([{"id": "key-1", "lastActiveAt": None}], "opaque+/cursor=="),
            page([{"id": "key-2"}]),
        ])
        result = collect_cursor_pages(fetch, params)
        self.assertEqual(result.coverage, "complete")
        self.assertEqual([r["id"] for r in result.records], ["key-1", "key-2"])
        self.assertEqual(result.requests, 2)
        self.assertEqual(fetch.requests, [original, dict(original, cursor="opaque+/cursor==")])
        self.assertEqual(params, original)
        self.assertNotIn("keyType", result.records[0])
        self.assertIsNone(result.records[0]["lastActiveAt"])

    def test_error_on_first_page_is_failed_not_empty_success(self):
        for status in (401, 403, 404, 429, 503):
            with self.subTest(status=status):
                result = collect_cursor_pages(
                    ScriptedTransport([Page(status, {"message": "SYNTHETIC_SECRET"})]), {}
                )
                self.assertEqual(result.coverage, "failed")
                self.assertEqual(result.reason, "http_" + str(status))
                self.assertNotIn("SYNTHETIC_SECRET", json.dumps(asdict(result)))

    def test_midstream_failure_preserves_earlier_records(self):
        for status in (403, 429, 503):
            with self.subTest(status=status):
                fetch = ScriptedTransport([page(next_cursor="cursor-2"), Page(status, {})])
                result = collect_cursor_pages(fetch, {"status": "allowed"})
                self.assertEqual(result.coverage, "partial")
                self.assertEqual(result.records, [{"id": "example-1"}])
                self.assertEqual((result.pages, result.requests), (1, 2))
                self.assertEqual(fetch.requests[1], {"status": "allowed", "cursor": "cursor-2"})

    def test_empty_page_with_next_does_not_stop_early(self):
        fetch = ScriptedTransport([page([], "second"), page([{"id": "example-2"}])])
        result = collect_cursor_pages(fetch, {})
        self.assertEqual(result.coverage, "complete")
        self.assertEqual(result.records, [{"id": "example-2"}])

    def test_empty_terminal_page_is_success(self):
        result = collect_cursor_pages(ScriptedTransport([page([])]), {})
        self.assertEqual((result.coverage, result.records, result.pages), ("complete", [], 1))

    def test_page_limit_and_record_limit_are_partial(self):
        fetch = ScriptedTransport([page(next_cursor="more")])
        result = collect_cursor_pages(fetch, {}, max_pages=1)
        self.assertEqual((result.coverage, result.reason), ("partial", "page_limit"))
        result = collect_cursor_pages(
            ScriptedTransport([page([{"id": "a"}, {"id": "b"}])]), {}, max_records=1
        )
        self.assertEqual(
            (result.coverage, result.reason, len(result.records)), ("partial", "record_limit", 1)
        )
        result = collect_cursor_pages(
            ScriptedTransport([page(next_cursor="more")]), {}, max_records=1
        )
        self.assertEqual(result.reason, "record_limit")

    def test_exact_limit_at_terminal_page_can_finish(self):
        result = collect_cursor_pages(ScriptedTransport([page()]), {}, max_pages=1, max_records=1)
        self.assertEqual(result.coverage, "complete")

    def test_cursor_cycle_terminates_and_preserves_observations(self):
        fetch = ScriptedTransport([page([{"id": "a"}], "next"), page([{"id": "b"}], "next")])
        result = collect_cursor_pages(fetch, {})
        self.assertEqual(
            (result.coverage, result.reason, result.requests), ("partial", "repeated_cursor", 2)
        )
        self.assertEqual(len(result.records), 2)

    def test_duplicate_id_versions_are_retained_and_marked_unverified(self):
        first = {"id": "a", "label": "before"}
        second = {"id": "a", "label": "after"}
        result = collect_cursor_pages(ScriptedTransport([page([first], "two"), page([second])]), {})
        self.assertEqual(
            (result.coverage, result.reason, result.duplicate_ids),
            ("unverified", "duplicate_ids", 1),
        )
        self.assertEqual(result.records, [first, second])

    def test_missing_links_and_bad_cursor_never_claim_completion(self):
        for body, reason in [
            ({"data": [{"id": "a"}]}, "missing_pagination_contract"),
            ({"data": [{"id": "a"}], "links": {"next": 7}}, "unexpected_cursor_type"),
        ]:
            with self.subTest(reason=reason):
                result = collect_cursor_pages(ScriptedTransport([Page(200, body)]), {})
                self.assertEqual((result.coverage, result.reason), ("partial", reason))
                self.assertEqual(result.records, [{"id": "a"}])

    def test_array_variant_requires_its_own_adapter(self):
        result = collect_cursor_pages(ScriptedTransport([Page(200, [])]), {})
        self.assertEqual(
            (result.coverage, result.reason), ("failed", "unexpected_collection_shape")
        )

    def test_invalid_records_are_counted_without_losing_valid_records(self):
        records = [{"id": "a"}, {}, {"id": None}, {"id": " "}, "not an object"]
        result = collect_cursor_pages(ScriptedTransport([page(records)]), {})
        self.assertEqual(
            (result.coverage, result.reason, result.invalid_records),
            ("partial", "invalid_records", 4),
        )
        self.assertEqual(result.records, [{"id": "a"}])

    def test_transport_exception_is_sanitized_and_not_retried(self):
        fetch = ScriptedTransport([RuntimeError("SYNTHETIC_SECRET")])
        result = collect_cursor_pages(fetch, {})
        self.assertEqual(
            (result.coverage, result.reason, result.requests), ("failed", "fetch_error", 1)
        )
        self.assertNotIn("SYNTHETIC_SECRET", json.dumps(asdict(result)))

    def test_invalid_limits_fail_before_transport(self):
        for limits in ({"max_pages": 0}, {"max_pages": True}, {"max_records": 0}):
            with self.subTest(limits=limits):
                fetch = ScriptedTransport([])
                with self.assertRaises(ValueError):
                    collect_cursor_pages(fetch, {}, **limits)
                self.assertEqual(fetch.requests, [])


if __name__ == "__main__":
    unittest.main()
