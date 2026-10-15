"""Same-resource Runner pagination using public UUID identity evidence."""

import unittest
from unittest.mock import Mock

from cremore_atlassian_provider.metadata.bitbucket import OPERATIONS, BitbucketClient
from cremore_atlassian_provider.metadata.discovery import collect_operation
from cremore_atlassian_provider.metadata.http import FetchResult, Limits
from cremore_atlassian_provider.metadata.runner_pagination import RunnerIdentities

from .test_bitbucket import SECRET
from .test_bitbucket_runners import runner
from .test_discovery import Response

WS = "{11111111-1111-4111-8111-111111111111}"
REPO = "{22222222-2222-4222-8222-222222222222}"
OTHER = "{33333333-3333-4333-8333-333333333333}"
WORKSPACE = {"slug": "lab", "uuid": WS}
REPOSITORY = {"slug": "repo", "uuid": REPO, "workspace": WORKSPACE}
ORIGIN = "https://api.bitbucket.org"


def internal(operation, encoded=True):
    path = (
        "/internal/workspaces/" + WS
        if operation == "workspace-runners"
        else "/internal/repositories/" + WS + "/" + REPO
    ) + "/pipelines-config/runners"
    return ORIGIN + (path.replace("{", "%7B").replace("}", "%7D") if encoded else path)


class RunnerPaginationTests(unittest.TestCase):
    def test_both_runner_scopes_follow_verified_internal_and_relative_next_unchanged(self):
        for operation in ("workspace-runners", "repository-runners"):
            for encoded in (True, False):
                with self.subTest(operation=operation, encoded=encoded):
                    nxt = internal(operation, encoded) + "?pagelen=1&page=2"
                    final = internal(operation, encoded) + "?pagelen=1&cursor=opaque%2Bthird"
                    opener = Mock()
                    opener.open.side_effect = [
                        Response(body)
                        for body in (
                            {"values": [REPOSITORY]},
                            {"values": [runner("one")], "size": 3, "next": nxt},
                            {
                                "values": [runner("two")],
                                "size": 3,
                                "next": "?pagelen=1&cursor=opaque%2Bthird",
                            },
                            {"values": [runner("three")], "size": 3},
                        )
                    ]
                    client = BitbucketClient("lab", SECRET, page_size=1, opener=opener)
                    client.read_metadata("repositories")
                    report = collect_operation(
                        client,
                        operation,
                        specs=OPERATIONS,
                        identifier="repo" if operation == "repository-runners" else None,
                    )
                    self.assertEqual(
                        (report["coverage"], report["saved_records"], report["requests"]),
                        ("complete", 3, 3),
                    )
                    requests = [c.args[0] for c in opener.open.call_args_list]
                    self.assertEqual([r.full_url for r in requests[2:]], [nxt, final])
                    self.assertTrue(
                        all(r.get_method() == "GET" and r.data is None for r in requests)
                    )

    def test_cross_resource_or_origin_and_malformed_urls_never_reach_network(self):
        valid = internal("repository-runners") + "?page=2"
        bad = [
            valid.replace("api.bitbucket.org", "other.example"),
            valid.replace("%7B22222222-2222-4222-8222-222222222222%7D", OTHER),
            valid.replace("%7B11111111-1111-4111-8111-111111111111%7D", OTHER),
            valid.replace("https:", "http:"),
            valid + "#fragment",
            valid.replace("api.bitbucket.org", "name@api.bitbucket.org"),
            valid.replace("/runners?", "/runners/one?"),
            valid.replace("/runners?", "/variables?"),
            " " + valid,
            valid + "\n",
            valid.replace("%7B", "%257B"),
        ]
        for nxt in bad:
            with self.subTest(nxt=nxt):
                opener = Mock()
                opener.open.return_value = Response({"values": [REPOSITORY]})
                client = BitbucketClient("lab", SECRET, opener=opener)
                client.read_metadata("repositories")
                with self.assertRaises(ValueError):
                    client.read_metadata("repository-runners", identifier="repo", next_url=nxt)
                self.assertEqual(opener.open.call_count, 1)

    def test_missing_foreign_or_conflicting_identity_keeps_first_page_partial(self):
        cases = [
            [],
            [{"slug": "repo", "uuid": REPO}],
            [dict(REPOSITORY, workspace={"slug": "other", "uuid": WS})],
            [dict(REPOSITORY, uuid="not-a-uuid")],
            [REPOSITORY, dict(REPOSITORY, uuid=OTHER)],
            [REPOSITORY, dict(REPOSITORY, workspace={"slug": "lab", "uuid": OTHER})],
        ]
        for rows in cases:
            with self.subTest(rows=rows):
                opener = Mock()
                opener.open.side_effect = [
                    Response({"values": rows}),
                    Response(
                        {
                            "values": [runner("one")],
                            "next": internal("repository-runners") + "?page=2",
                        }
                    ),
                ]
                client = BitbucketClient("lab", SECRET, opener=opener)
                client.read_metadata("repositories")
                report = collect_operation(
                    client, "repository-runners", identifier="repo", specs=OPERATIONS
                )
                self.assertEqual(
                    (report["coverage"], report["reason"], report["saved_records"]),
                    ("partial", "pagination_target_outside_resource", 1),
                )
                self.assertEqual(opener.open.call_count, 2)

    def test_identity_cannot_be_learned_from_errors_runners_or_links(self):
        identities = RunnerIdentities("lab")
        identities.observe("workspace-runners", {"values": [REPOSITORY]})
        identities.observe(
            "repositories", {"values": [{"slug": "repo", "links": {"workspace": WORKSPACE}}]}
        )
        self.assertEqual(identities.internal_paths("workspace-runners", None), ())
        client = BitbucketClient("lab", SECRET)
        client._request = Mock(
            return_value=FetchResult(403, {"values": [REPOSITORY]}, 1, "http_403")
        )
        client.read_metadata("repositories")
        self.assertEqual(client.runner_identities.internal_paths("workspace-runners", None), ())

    def test_budget_still_stops_before_next_request(self):
        opener = Mock()
        opener.open.side_effect = [
            Response({"values": [REPOSITORY]}),
            Response(
                {"values": [runner("one")], "next": internal("workspace-runners") + "?page=2"}
            ),
        ]
        client = BitbucketClient("lab", SECRET, Limits(max_requests=2), opener=opener)
        client.read_metadata("repositories")
        report = collect_operation(client, "workspace-runners", specs=OPERATIONS)
        self.assertEqual((report["coverage"], report["reason"]), ("partial", "request_limit"))
        self.assertEqual(opener.open.call_count, 2)

    def test_internal_route_exception_never_applies_to_other_operations(self):
        opener = Mock()
        opener.open.return_value = Response({"values": [REPOSITORY]})
        client = BitbucketClient("lab", SECRET, opener=opener)
        client.read_metadata("repositories")
        with self.assertRaises(ValueError):
            client.read_metadata("repositories", next_url=internal("workspace-runners") + "?page=2")
        self.assertEqual(opener.open.call_count, 1)
