"""The read surface and the one way a page is allowed to advance."""

from __future__ import annotations

import unittest

from cremore_github_provider.metadata.endpoints import (
    EndpointError,
    first_path,
    inventory_flags,
    next_path,
    validate_audit_page,
    validate_inventory_page,
    validate_operation,
)

from .fake import ENTERPRISE, ORG, REPO, inventory_row


class OperationTests(unittest.TestCase):
    def test_every_documented_organization_read_is_allowed(self):
        for path in (f"/orgs/{ORG}/credential-authorizations",
                     f"/orgs/{ORG}/personal-access-tokens",
                     f"/orgs/{ORG}/personal-access-token-requests/5/repositories",
                     f"/orgs/{ORG}/installations", f"/orgs/{ORG}/audit-log?phrase=created",
                     f"/orgs/{ORG}/actions/permissions/workflow", "/installation/repositories",
                     f"/repos/{ORG}/{REPO}/keys",
                     f"/repos/{ORG}/{REPO}/actions/permissions",
                     f"/repos/{ORG}/{REPO}/actions/runs",
                     f"/repos/{ORG}/{REPO}/actions/runs/7/attempts/1/jobs"):
            validate_operation("GET", path)

    def test_enterprise_reads_need_the_connection_enterprise(self):
        path = f"/enterprises/{ENTERPRISE}/credentials"
        validate_operation("GET", path, enterprise=ENTERPRISE)
        with self.assertRaises(EndpointError):
            validate_operation("GET", path)
        with self.assertRaises(EndpointError):
            validate_operation("GET", "/enterprises/another-business/credentials",
                               enterprise=ENTERPRISE)

    def test_nothing_outside_the_list_and_no_write_is_accepted(self):
        for path in (f"/orgs/{ORG}/members", "/user", f"/repos/{ORG}/{REPO}/contents/config.yml",
                     "https://api.github.com/orgs/x", f"/orgs/{ORG}/../../user",
                     f"/repos/{ORG}/{REPO}/keys#fragment"):
            with self.assertRaises(EndpointError, msg=path):
                validate_operation("GET", path)
        for method in ("PUT", "PATCH", "DELETE"):
            with self.assertRaises(EndpointError):
                validate_operation(method, f"/orgs/{ORG}/credential-authorizations")

    def test_the_only_post_is_installation_token_issuance(self):
        validate_operation("POST", "/app/installations/71/access_tokens")
        with self.assertRaises(EndpointError):
            validate_operation("POST", "/app/installations/71/access_tokens?scope=all")
        with self.assertRaises(EndpointError):
            validate_operation("POST", "/app/installations/71/access_tokens",
                               allow_token_issue=False)
        with self.assertRaises(EndpointError):
            validate_operation("POST", f"/orgs/{ORG}/credential-authorizations")


class PaginationTests(unittest.TestCase):
    def test_a_first_page_asks_for_the_configured_size_only_when_paginated(self):
        self.assertEqual(first_path("/a", page_size=50), "/a?per_page=50")
        self.assertEqual(first_path("/a?x=1", page_size=50), "/a?x=1&per_page=50")
        self.assertEqual(first_path("/a", paginated=False), "/a")

    def test_only_the_cursor_may_change(self):
        current = "/orgs/x/audit-log?phrase=created%3A1..2&per_page=100"
        link = ('<https://api.github.com/orgs/x/audit-log?phrase=created%3A1..2'
                '&per_page=100&after=abc>; rel="next"')
        following = next_path(current, link, api="https://api.github.com")
        self.assertIn("after=abc", following)
        self.assertIn("phrase=created", following)

    def test_an_audit_log_link_may_carry_after_and_before(self):
        # GitHub documents the audit log's next link as after=<cursor>&before=.
        current = ("/enterprises/acme/audit-log?include=web&order=asc"
                   "&phrase=created%3A1..2&per_page=100")
        link = ('<https://api.github.com/enterprises/acme/audit-log?include=web&order=asc'
                '&phrase=created%3A1..2&per_page=100&after=MS42NjQz&before=>; rel="next"')
        following = next_path(current, link, api="https://api.github.com")
        self.assertIn("after=MS42NjQz", following)
        self.assertIn("before=", following)
        self.assertIn("phrase=created", following)
        # The next page carries both cursors again and still advances.
        link = link.replace("MS42NjQz", "MS42NjQ0")
        self.assertIn("after=MS42NjQ0", next_path(following, link, api="https://api.github.com"))
        # Elsewhere two cursors remain ambiguous.
        base = "https://api.github.com/orgs/x/installations?per_page=100"
        with self.assertRaises(EndpointError):
            next_path("/orgs/x/installations?per_page=100", f'<{base}&after=a&before=b>; rel="next"',
                      api="https://api.github.com")

    def test_a_link_that_changes_scope_host_or_nothing_is_refused(self):
        current = "/orgs/x/audit-log?phrase=created%3A1..2&per_page=100"
        for link in (
            '<https://api.github.com/orgs/y/audit-log?phrase=created%3A1..2&after=a>; rel="next"',
            '<https://api.github.com/orgs/x/audit-log?phrase=other&after=a>; rel="next"',
            '<https://evil.test/orgs/x/audit-log?after=a>; rel="next"',
            ('<https://api.github.com/orgs/x/audit-log?phrase=created%3A1..2&per_page=100>;'
             ' rel="next"'),
            'garbage',
        ):
            with self.assertRaises(EndpointError, msg=link):
                next_path(current, link, api="https://api.github.com")

    def test_two_next_links_are_ambiguous_and_none_ends_the_list(self):
        current = "/orgs/x/installations?per_page=100"
        base = "https://api.github.com/orgs/x/installations?per_page=100"
        with self.assertRaises(EndpointError):
            next_path(current, f'<{base}&page=2>; rel="next", <{base}&page=3>; rel="next"',
                      api="https://api.github.com")
        self.assertIsNone(next_path(current, f'<{base}&page=9>; rel="last"',
                                    api="https://api.github.com"))
        self.assertIsNone(next_path(current, "", api="https://api.github.com"))

    def test_a_ghes_link_on_the_same_path_is_accepted(self):
        current = "/orgs/x/installations?per_page=100"
        link = ('<https://ghes.example.com/api/v3/orgs/x/installations?per_page=100&page=2>;'
                ' rel="next"')
        self.assertIn("page=2", next_path(current, link,
                                          api="https://ghes.example.com/api/v3"))

    def test_a_link_naming_the_same_scope_by_numeric_id_moves_only_the_cursor(self):
        # docs.github.com: /enterprises/avocado-corp/audit-log answers with
        # /enterprises/13827/audit-log; /repos/o/r/... with /repositories/1300192/...
        cases = (
            ("/enterprises/acme/audit-log?phrase=created%3A1..2&per_page=100",
             ("https://api.github.com/enterprises/13827/audit-log?phrase=created%3A1..2"
              "&per_page=100&after=MS4y&before=")),
            ("/orgs/x/personal-access-tokens?per_page=100",
             "https://api.github.com/organizations/123/personal-access-tokens?per_page=100&page=2"),
            ("/repos/x/r/actions/runs?per_page=100",
             "https://api.github.com/repositories/1300192/actions/runs?per_page=100&page=2"),
        )
        for current, link in cases:
            following = next_path(current, f'<{link}>; rel="next"', api="https://api.github.com")
            self.assertEqual(following.split("?")[0], current.split("?")[0])
        ghes = '<https://ghes.example.com/api/v3/organizations/7/installations?per_page=100&page=2>; rel="next"'
        self.assertIn("page=2", next_path("/orgs/x/installations?per_page=100", ghes,
                                          api="https://ghes.example.com/api/v3"))
        for link in (
            "https://api.github.com/organizations/123/audit-log?per_page=100&page=2",  # other resource
            "https://api.github.com/enterprises/123/personal-access-tokens?per_page=100&page=2",
            "https://api.github.com/organizations/x/personal-access-tokens?per_page=100&page=2",
            "https://api.github.com/api/v3/organizations/1/personal-access-tokens?per_page=100&page=2",
        ):
            with self.assertRaises(EndpointError, msg=link):
                next_path("/orgs/x/personal-access-tokens?per_page=100", f'<{link}>; rel="next"',
                          api="https://api.github.com")


class PayloadTests(unittest.TestCase):
    def test_an_inventory_row_must_carry_its_documented_states(self):
        validate_inventory_page([inventory_row()])
        for change in ({"item_type": "something"}, {"credential_state": "unknown"},
                       {"authorization_state": "maybe"}, {"effective_access_state": "yes"},
                       {"enterprise_authorized": "true"}, {"authorization_count": -1},
                       {"authorized_organizations": [{"id": 0, "login": ORG}]},
                       {"inventory_id": ""}):
            with self.assertRaises(EndpointError, msg=str(change)):
                validate_inventory_page([inventory_row(**change)])

    def test_an_audit_row_from_another_business_or_org_is_refused(self):
        validate_audit_page([{"action": "personal_access_token.access_granted",
                              "business": ENTERPRISE, "org": ORG}], ENTERPRISE, ORG)
        with self.assertRaises(EndpointError):
            validate_audit_page([{"action": "x.y", "business": "other"}], ENTERPRISE)
        with self.assertRaises(EndpointError):
            validate_audit_page([{"action": "x.y", "org": "other"}], ENTERPRISE, ORG)
        with self.assertRaises(EndpointError):
            validate_audit_page([{"action": "not a valid action!"}], ENTERPRISE)

    def test_inventory_completeness_headers_become_warnings(self):
        flags, generated = inventory_flags({
            "x-github-enterprise-credentials-truncated": "true",
            "x-github-enterprise-credentials-incomplete-results": "false",
            "x-github-enterprise-credentials-generated-at": "2026-03-02T00:00:00Z"})
        self.assertEqual(flags, ["truncated:true"])
        self.assertTrue(generated.startswith("2026-03-02"))
        flags, generated = inventory_flags({
            "x-github-enterprise-credentials-generated-at": "not a date"})
        self.assertEqual(flags, ["generated-at:invalid"])
        self.assertIsNone(generated)


if __name__ == "__main__":
    unittest.main()
