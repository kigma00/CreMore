"""The eight collectors' field selection, scope checks and shape refusals."""

from __future__ import annotations

import unittest

from cremore_github_provider.metadata import pages
from cremore_github_provider.metadata.endpoints import EndpointError
from cremore_github_provider.metadata.projection import (
    ACTIONS_POLICY,
    WORKFLOW_POLICY,
    deploy_key_metadata,
    installation_info,
    job_metadata,
    policy_metadata,
    project_installation,
    project_pat,
    public_key_metadata,
    repository_metadata,
    run_metadata,
)

from .fake import ENTERPRISE, ORG, REPO, SSH_KEY, repository


class FieldTests(unittest.TestCase):
    def test_a_missing_field_and_an_explicit_null_stay_distinct(self):
        row = {"id": 1, "token_id": 2, "token_name": None, "owner": None}
        result = project_pat(row, ("id", "token_id", "token_name", "token_expires_at"))
        self.assertEqual(result, {"id": 1, "token_id": 2, "token_name": None, "owner": None})
        self.assertNotIn("token_expires_at", result)

    def test_an_owner_that_is_not_an_object_is_refused(self):
        with self.assertRaises(ValueError):
            project_pat({"owner": "octocat"}, ("id",))

    def test_a_repository_from_another_organization_is_refused(self):
        repository_metadata(repository(), ORG)
        with self.assertRaises(ValueError):
            repository_metadata(repository(org="Other-Org"), ORG)
        with self.assertRaises(ValueError):
            repository_metadata({**repository(), "full_name": f"{ORG}/elsewhere"}, ORG)
        for name in ("..", ".", "a/b", ""):
            with self.assertRaises(ValueError):
                repository_metadata({**repository(), "name": name}, ORG)

    def test_a_shallow_repository_skips_only_the_owner_check(self):
        row = {"id": 5, "name": REPO, "full_name": f"{ORG}/{REPO}"}
        self.assertEqual(repository_metadata(row, ORG, shallow=True)["id"], 5)
        with self.assertRaises(ValueError):
            repository_metadata(row, ORG)

    def test_an_installation_keeps_events_and_refuses_unknown_permission_levels(self):
        row = {"id": 7, "app_id": 5, "permissions": {"contents": "read"}, "events": ["push"],
               "account": {"login": ORG, "id": 9, "type": "Organization"},
               "token": "ghs_secret", "temp_clone_token": "x"}
        result = project_installation(row, "installations", ORG)
        self.assertEqual(result["events"], ["push"])
        self.assertNotIn("token", result)
        self.assertNotIn("temp_clone_token", result)
        with self.assertRaises(ValueError):
            project_installation({**row, "permissions": {"contents": "superuser"}},
                                 "installations", ORG)

    def test_a_public_key_is_fingerprinted_from_its_wire_format(self):
        result = public_key_metadata(SSH_KEY)
        self.assertTrue(result["fingerprint"].startswith("SHA256:"))
        self.assertEqual(result["key_algorithm"], "ssh-ed25519")
        self.assertIsNone(result["key_metadata_error"])
        self.assertEqual(public_key_metadata("not a key")["key_metadata_error"],
                         "invalid_ssh_public_key_format")
        self.assertEqual(public_key_metadata(None)["key_metadata_error"],
                         "public_key_unavailable")

    def test_a_deploy_key_keeps_its_repository_and_never_a_private_key(self):
        repo = repository()
        result = deploy_key_metadata({"id": 3, "title": "deploy", "key": SSH_KEY,
                                      "read_only": True}, repo)
        self.assertEqual(result["credential_type"], "Deploy key")
        self.assertEqual(result["repository"]["full_name"], repo["full_name"])
        with self.assertRaises(ValueError):
            deploy_key_metadata({"id": 3, "read_only": "yes"}, repo)

    def test_a_policy_keeps_only_its_schema_and_refuses_a_wrong_type(self):
        self.assertEqual(
            policy_metadata({"default_workflow_permissions": "read", "extra": 1}, WORKFLOW_POLICY),
            {"default_workflow_permissions": "read"})
        with self.assertRaises(ValueError):
            policy_metadata({"enabled": "yes"}, ACTIONS_POLICY)
        with self.assertRaises(ValueError):
            policy_metadata({"unrelated": 1}, ACTIONS_POLICY)

    def test_a_run_or_job_from_another_repository_or_run_is_refused(self):
        repo = repository()
        run = {"id": 7, "run_attempt": 1, "repository": {"id": repo["id"],
                                                         "full_name": repo["full_name"]}}
        self.assertEqual(run_metadata(run, repo)["id"], 7)
        with self.assertRaises(ValueError):
            run_metadata({**run, "repository": {"id": 999, "full_name": "x/y"}}, repo)
        projected = run_metadata(run, repo)
        self.assertEqual(job_metadata({"id": 8, "run_id": 7, "run_attempt": 1}, projected)["id"], 8)
        with self.assertRaises(ValueError):
            job_metadata({"id": 8, "run_id": 9}, projected)

    def test_an_installation_response_must_name_its_account_and_permissions(self):
        info = installation_info({"id": 3, "app_id": 5, "target_type": "Organization",
                                  "permissions": {}, "account": {"login": ORG}})
        self.assertEqual(info["account_login"], ORG)
        with self.assertRaises(ValueError):
            installation_info({"id": 3, "account": {"login": ORG}})
        with self.assertRaises(ValueError):
            installation_info({"id": 0, "permissions": {}, "account": {"login": ORG}})


class PageTests(unittest.TestCase):
    def org_task(self, kind, **overrides):
        seeds = {item["kind"]: item for item in pages.seed_org_tasks("", ORG)}
        return {**seeds[kind], **overrides}

    def test_sso_rows_split_by_credential_type_and_keep_the_rest_as_context(self):
        rows = [
            {"credential_type": "personal access token", "credential_id": 1},
            {"credential_type": "SSH key", "credential_id": 2, "fingerprint": "SHA256:x"},
            {"credential_type": "deploy key legacy", "credential_id": 3},
        ]
        output = pages.handle_page(self.org_task("org_sso"), rows)
        results = output["reports"][0]["results"]
        self.assertEqual(len(results["classic_pat"]["classic_pats"]), 1)
        self.assertEqual(len(results["user_ssh_key"]["user_ssh_keys"]), 1)
        self.assertEqual(output["contexts"][0]["kind"], "unclassified_sso_authorization")

    def test_a_fine_grained_pat_seeds_exactly_its_repositories_task(self):
        output = pages.handle_page(self.org_task("org_fgpat"),
                                   [{"id": 31, "token_id": 41, "token_name": "x"}])
        self.assertEqual([item["kind"] for item in output["tasks"]], ["org_fgpat_repositories"])
        self.assertEqual(output["tasks"][0]["path"],
                         f"/orgs/{ORG}/personal-access-tokens/31/repositories")

    def test_a_task_whose_endpoint_does_not_match_its_kind_is_refused(self):
        forged = self.org_task("org_fgpat", path=f"/orgs/{ORG}/credential-authorizations")
        with self.assertRaises(EndpointError):
            pages.handle_page(forged, [])
        stolen = self.org_task("org_sso", org="Other-Org")
        with self.assertRaises(EndpointError):
            pages.handle_page(stolen, [])

    def test_a_repository_page_seeds_its_policy_and_key_tasks(self):
        output = pages.handle_page(self.org_task("org_repositories"),
                                   {"repositories": [repository()]})
        kinds = sorted(item["kind"] for item in output["tasks"])
        self.assertEqual(kinds, ["repo_actions_policy", "repo_deploy_keys", "repo_fork_policy",
                                 "repo_workflow_policy"])

    def test_a_public_repository_is_not_asked_for_the_private_fork_policy(self):
        output = pages.handle_page(self.org_task("org_repositories"),
                                   {"repositories": [repository(visibility="public")]})
        self.assertNotIn("repo_fork_policy", {item["kind"] for item in output["tasks"]})

    def test_a_missing_collection_key_is_never_an_empty_list(self):
        with self.assertRaises(EndpointError):
            pages.handle_page(self.org_task("org_repositories"), {"other": []})

    def test_enterprise_organizations_seed_every_source_for_each_organization(self):
        current = {"kind": "organizations", "path": "/enterprises/x/apps/installable_organizations"}
        output = pages.handle_enterprise_page(
            current, [{"id": 9, "login": ORG}], {}, enterprise=ENTERPRISE,
            window=["2026-01-01T00:00:00", "2026-03-01T00:00:00"], include_audit=True)
        kinds = {item["kind"] for item in output["tasks"]}
        self.assertIn("enterprise_org_installations", kinds)
        self.assertIn("org_sso", kinds)
        self.assertIn("org_audit", kinds)
        self.assertEqual(output["contexts"][0]["kind"], "enterprise_organizations")

    def test_only_the_requested_sources_are_seeded(self):
        current = {"kind": "organizations", "path": "/enterprises/x/apps/installable_organizations"}
        output = pages.handle_enterprise_page(
            current, [{"id": 9, "login": ORG}], {}, enterprise=ENTERPRISE,
            window=["2026-01-01T00:00:00", "2026-03-01T00:00:00"], include_audit=False,
            sources=("org_sso",))
        self.assertEqual({item["kind"] for item in output["tasks"]}, {"org_sso"})


if __name__ == "__main__":
    unittest.main()
