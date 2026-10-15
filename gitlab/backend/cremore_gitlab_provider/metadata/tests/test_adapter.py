"""Offline proofs for the shared lease adapter, with synthetic GitLab responses."""

import json
import tempfile
import unittest
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from cremore.coverage.metadata_models import MetadataConnectionSpec, MetadataFact
from cremore_gitlab_provider.metadata.adapter import (
    _config,
    collect_pages,
    compare_records,
    export_records,
    validate_machine_record,
    validate_record,
    validate_spec,
)
from cremore_gitlab_provider.metadata.collector import Collector
from cremore_gitlab_provider.metadata.http import CollectionError, Response
from cremore_gitlab_provider.metadata.model import identity as native_identity
from cremore_gitlab_provider.metadata.model import stable_id
from cremore_gitlab_provider.metadata.normalization import FactWriter, record, unpack_facts
from cremore_gitlab_provider.metadata.storage import Store

from ._qa_storage import Store as NativeQAStore
from ._responses import inventory_client
from .test_audit import AuditClient, creation


def spec_for(*, audit=False, options=None, **overrides):
    settings = {
        "include_enterprise_pat": True,
        "include_audit_events": audit,
        "audit_created_after": "2026-09-01T00:00:00Z",
        **(options or {}),
    }
    return MetadataConnectionSpec.model_validate(
        {
            "name": "Synthetic GitLab",
            "provider": "gitlab",
            "origin": "https://gitlab.com",
            "edition": "cloud",
            "scopes": [{"kind": "group", "id": "10"}],
            "capabilities": ["inventory", "audit", "relations"],
            "secret_refs": {"token": "vault://synthetic/gitlab"},
            "options": settings,
            **overrides,
        }
    )


def run(spec, *, client=None, checkpoint=None, previous=None, check=lambda: None):
    return list(
        collect_pages(
            spec,
            secrets={"token": "SYNTHETIC_OPERATOR_AUTH"},
            checkpoint=checkpoint,
            check=check,
            read_records=(lambda: iter(previous)) if previous is not None else None,
            client=client
            or (AuditClient if spec.options.include_audit_events else inventory_client)(_config(spec)),
        )
    )


def records(pages):
    return [item.model_dump() for page in pages for item in page.records]


def without_times(value):
    ignored = {"observed_at", "first_seen_at_this_run", "last_seen_at_this_run"}
    if isinstance(value, dict):
        return {key: without_times(item) for key, item in value.items() if key not in ignored}
    if isinstance(value, list):
        return [without_times(item) for item in value]
    return value


class AdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = spec_for(audit=True)
        cls.pages = run(cls.spec)
        cls.records = records(cls.pages)
        cls.export = export_records(cls.records, spec=cls.spec)

    def test_all_ten_native_families_and_common_counts(self):
        self.assertEqual(self.pages[-1].status, "COMPLETE")
        self.assertEqual(len(self.export["inventory"]), 12)
        self.assertEqual(
            len({family for row in self.export["inventory"] for family in row["credential_types"]}),
            10,
        )
        self.assertEqual(self.pages[-1].checkpoint["emitted"], len(self.records))
        self.assertTrue(self.export["manifest"]["all_scheduled_tasks_complete"])
        for page in self.pages:
            for item in page.records:
                self.assertTrue(validate_record(self.spec, item), item.provenance.operation)
        serialized = json.dumps(self.records)
        self.assertNotIn("SYNTHETIC_DO_NOT_PERSIST", serialized)
        self.assertNotIn("SYNTHETIC_OPERATOR_AUTH", serialized)
        self.assertFalse('"name": "hasTokenExposed"' in serialized)

    def test_native_snapshot_equivalence_after_shared_field_policy(self):
        config = _config(self.spec)
        with tempfile.TemporaryDirectory() as directory:
            native = NativeQAStore(Path(directory) / "native", config.fingerprint())
            try:
                native.set_setting("started_at", self.pages[0].checkpoint["settings"]["started_at"])
                Collector(config, AuditClient(config), native).run()
                native_rows = [
                    unpack_facts([fact.model_dump() for fact in FactWriter().facts(row)])
                    for row in native.inventory()
                ]
            finally:
                native.close()
        # The preserved v0.6 QA snapshot proves unchanged token semantics.
        # Schema 1.4 adds audit coverage, tested separately below.
        actual = deepcopy(self.export["inventory"])
        for row in actual:
            row["schema_version"] = "1.2"
            row.get("audit", {}).pop("creation_evidence", None)
        self.assertEqual(without_times(native_rows), without_times(actual))

    def test_creation_events_are_linked_and_owner_is_separate(self):
        final_events = [
            item
            for item in self.records
            if item["record_type"] == "provider_event" and item["target"]
        ]
        self.assertEqual(len(final_events), 2)
        self.assertTrue(
            all(
                item["confidence"] == "EXACT" and item["match_basis"] == "AUDIT_REFERENCE"
                for item in final_events
            )
        )
        deploy = next(row for row in self.export["inventory"] if row["token_id"] == 302)
        self.assertEqual(deploy["summary"]["issuer"]["id"], 2)
        self.assertEqual(deploy["summary"]["owner"]["status"], "not_provided")
        relations = [item for item in self.records if item["record_type"] == "relation"]
        self.assertTrue(
            any(
                item["relation"] == "created_by" and item["target"]["object_id"] == "user:2"
                for item in relations
            )
        )
        self.assertFalse(
            any(
                item["provenance"]["operation"] == "gitlab.native.inventory"
                and item.get("state_basis") == "OBSERVED"
                for item in self.records
            )
        )

    def test_ambiguous_audit_reference_never_creates_a_target(self):
        client = AuditClient(_config(self.spec))
        event = creation()
        event["details"]["target_id"] = 999
        client.events["/projects/100/audit_events"] = [event]
        pages = run(self.spec, client=client)
        events = [item for item in records(pages) if item["record_type"] == "provider_event"]
        project_events = [
            item for item in events if unpack_facts(item["facts"])["scope"]["kind"] == "project"
        ]
        self.assertTrue(project_events)
        self.assertTrue(
            all(
                item["target"] is None and item["confidence"] == "UNKNOWN"
                for item in project_events
            )
        )

    def test_restart_at_collection_and_finalization_boundaries(self):
        boundaries = [
            0,
            12,
            next(
                i for i, page in enumerate(self.pages) if page.checkpoint.get("phase") == "finalize"
            ),
            len(self.pages) - 3,
        ]
        for boundary in boundaries:
            with self.subTest(boundary=boundary):
                prior = records(self.pages[: boundary + 1])
                checkpoint = self.pages[boundary].checkpoint
                reads = []
                resumed = list(
                    collect_pages(
                        self.spec,
                        secrets={"token": "SYNTHETIC_OPERATOR_AUTH"},
                        checkpoint=checkpoint,
                        check=lambda: None,
                        read_records=lambda reads=reads, prior=prior: (
                            reads.append(True) or iter(prior)
                        ),
                        client=AuditClient(_config(self.spec)),
                    )
                )
                self.assertEqual(reads, [True])
                self.assertEqual(resumed[-1].status, "COMPLETE")
                if checkpoint["phase"] == "finalize":
                    self.assertEqual(
                        resumed[0].checkpoint["final_cursor"], checkpoint["final_cursor"]
                    )
                combined = prior + records(resumed)
                self.assertEqual(resumed[-1].checkpoint["emitted"], len(combined))
                result = export_records(combined, spec=self.spec)
                self.assertEqual(
                    without_times(result["inventory"]), without_times(self.export["inventory"])
                )

    def test_completed_restart_only_rechecks_operator_identity(self):
        client = AuditClient(_config(self.spec))
        pages = run(
            self.spec, checkpoint=self.pages[-1].checkpoint, previous=self.records, client=client
        )
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(records(pages), [])
        self.assertEqual(pages[-1].status, "COMPLETE")

    def test_principal_change_and_bad_principal_shape_fail_without_overwriting_evidence(self):
        for identifier in (999, "malformed"):
            with self.subTest(identifier=identifier):
                client = AuditClient(_config(self.spec))
                client.routes["/user"]["id"] = identifier
                pages = run(
                    self.spec,
                    client=client,
                    checkpoint=self.pages[8].checkpoint,
                    previous=records(self.pages[:9]),
                )
                self.assertEqual(pages[-1].status, "FAILED")
                self.assertEqual(pages[-1].checkpoint["settings"]["principal_id"], 1)
                self.assertFalse(
                    any(item["record_type"] == "entity_observation" for item in records(pages))
                )

    def test_failed_source_retry_keeps_history_and_completes(self):
        spec = spec_for()
        client = inventory_client(_config(spec))
        client.failures[("/projects/100/access_tokens", 1)] = 403
        first = run(spec, client=client)
        self.assertEqual(first[-1].status, "PARTIAL")
        second = run(spec, checkpoint=first[-1].checkpoint, previous=records(first))
        result = export_records(records(first) + records(second), spec=spec)
        self.assertEqual(second[-1].status, "COMPLETE")
        self.assertGreater(result["manifest"]["historical_error_events"], 0)
        self.assertTrue(result["manifest"]["all_scheduled_tasks_complete"])

    def test_uncommitted_malformed_page_rolls_back_observations_and_followups(self):
        spec = spec_for(
            scopes=[{"kind": "user", "id": "self"}], options={"include_enterprise_pat": False}
        )
        client = inventory_client(_config(spec))
        client.routes["/personal_access_tokens"][1] = {"id": "invalid"}
        pages = run(spec, client=client)
        result = export_records(records(pages), spec=spec)
        self.assertEqual(result["inventory"], [])
        self.assertFalse(any("/personal_access_tokens/101" in url for url in client.calls))
        self.assertEqual(pages[-1].status, "PARTIAL")

    def test_single_object_id_mismatch_preserves_list_evidence(self):
        spec = spec_for()
        client = inventory_client(_config(spec))
        client.routes["/projects/100/deploy_tokens/302"]["id"] = 999
        # The synthetic list and detail normally share a dict; isolate the list again.
        client.routes["/projects/100/deploy_tokens"] = [
            {"id": 302, "name": "project-deploy", "scopes": ["read_registry"]}
        ]
        pages = run(spec, client=client)
        result = export_records(records(pages), spec=spec)
        self.assertIn("RESPONSE_ID_MISMATCH", pages[-1].reasons)
        self.assertIn(302, {row["token_id"] for row in result["inventory"]})
        self.assertNotIn(999, {row["token_id"] for row in result["inventory"]})

    def test_pagination_cannot_change_own_pat_user_filter(self):
        spec = spec_for(
            scopes=[{"kind": "user", "id": "self"}], options={"include_enterprise_pat": False}
        )
        client = inventory_client(_config(spec))
        original = client.request

        def request(url, query=None, variables=None):
            response = original(url, query, variables)
            if urlsplit(url).path == "/api/v4/personal_access_tokens":
                response = Response(
                    response.body,
                    {
                        "link": '<https://gitlab.com/api/v4/personal_access_tokens?user_id=999&page=2>; rel="next"'
                    },
                )
            return response

        client.request = request
        pages = run(spec, client=client)
        self.assertIn("PAGINATION_SCOPE_CHANGED", pages[-1].reasons)
        self.assertEqual(export_records(records(pages), spec=spec)["inventory"], [])

    def test_graphql_schema_failure_keeps_rest_trigger_evidence(self):
        spec = spec_for()
        client = inventory_client(_config(spec))
        client.graphql_body = {"data": []}
        pages = run(spec, client=client)
        self.assertIn("INVALID_GRAPHQL_RESPONSE", pages[-1].reasons)
        trigger = next(
            row
            for row in export_records(records(pages), spec=spec)["inventory"]
            if row["token_id"] == 501
        )
        self.assertTrue(trigger["observations"])
        self.assertFalse(
            any(row["handler"] == "graphql_triggers" for row in trigger["observations"])
        )

    def test_record_and_page_and_target_bounds_never_report_complete(self):
        for spec in (
            spec_for(max_records=4),
            spec_for(max_pages=1),
            spec_for(options={"max_targets": 1}),
        ):
            with self.subTest(
                records=spec.max_records, pages=spec.max_pages, targets=spec.options.max_targets
            ):
                pages = run(spec)
                self.assertEqual(pages[-1].status, "PARTIAL")
                self.assertLessEqual(len(records(pages)), spec.max_records)
                self.assertFalse(
                    export_records(records(pages), spec=spec)["manifest"][
                        "all_scheduled_tasks_complete"
                    ]
                )

    @patch("cremore_gitlab_provider.metadata.model.datetime")
    def test_target_overflow_commits_fitting_projects_and_finishes_scope(self, clock):
        clock.now.return_value = datetime(2026, 10, 13, tzinfo=UTC)
        spec = spec_for(options={"include_resource_access_tokens": False,
                                 "sources": ["ci_variables"]},
                        capabilities=["inventory", "relations", "vault_metadata"])
        client = inventory_client(_config(spec))
        client.routes["/groups/10/subgroups"] = []
        client.routes["/groups/10/projects"] = [{"id": ident} for ident in range(100, 160)]
        client.routes["/groups/10/variables"] = []
        for ident in range(101, 149):
            client.routes[f"/projects/{ident}"] = {"id": ident, "path_with_namespace": f"test/p{ident}"}
            for suffix in ("access_tokens", "deploy_tokens", "triggers", "error_tracking/client_keys",
                           "cluster_agents", "service_accounts"):
                client.routes[f"/projects/{ident}/{suffix}"] = []
        pages = run(spec, client=client)
        discovery = next(page for page in pages if any(
            task["spec"]["path"] == "/groups/10/projects" and task["pages"] == 1
            for task in page.checkpoint.get("tasks", {}).values()))
        assert len(discovery.checkpoint["roots"]) == 50
        assert pages[-1].status == "PARTIAL"
        assert "GITLAB_TARGET_LIMIT" in pages[-1].reasons
        paths = {urlsplit(url).path.removeprefix("/api/v4") for url in client.calls}
        assert {"/groups/10/access_tokens", "/groups/10/deploy_tokens"} <= paths
        assert "/projects/148/access_tokens" in paths
        assert "/projects/149" not in paths
        assert any(item.provenance.operation == "gitlab.native.inventory"
                   for page in pages for item in page.records)
        assert any(item.provenance.operation == "gitlab.ext.ci_variables"
                   and item.record_type == "operation_report" for page in pages for item in page.records)
        assert any(item.record_type == "relation" for page in pages for item in page.records)
        assert any(item.provenance.operation == "gitlab.run" for item in pages[-1].records)
        cut = pages.index(discovery) + 1
        resumed_client = inventory_client(_config(spec))
        resumed_client.routes = deepcopy(client.routes)
        resumed = run(spec, client=resumed_client, checkpoint=discovery.checkpoint,
                      previous=records(pages[:cut]))
        assert resumed[-1].status == "PARTIAL"
        assert "GITLAB_TARGET_LIMIT" in resumed[-1].reasons
        assert not any("/groups/10/projects?" in url for url in resumed_client.calls)
        assert any("/groups/10/access_tokens?" in url for url in resumed_client.calls)
        assert not export_records(records(pages[:cut]) + records(resumed), spec=spec)[
            "manifest"]["all_scheduled_tasks_complete"]
        assert next(task for task in resumed[-1].checkpoint["tasks"].values()
                    if task["spec"]["path"] == "/groups/10/projects")["status"] == "failed"

    @patch("cremore_gitlab_provider.metadata.model.datetime")
    def test_resource_target_overflow_preserves_own_tokens_without_claiming_absence(self, clock):
        clock.now.return_value = datetime(2026, 10, 13, tzinfo=UTC)
        spec = spec_for(options={"max_targets": 1})
        client = inventory_client(_config(spec))
        client.routes["/groups/10/subgroups"] = []
        client.routes["/groups/10/projects"] = []
        pages = run(spec, client=client)
        assert pages[-1].status == "PARTIAL"
        assert pages[-1].reasons == ["GITLAB_TARGET_LIMIT"]
        assert list(pages[-1].checkpoint["roots"]) == ["group:10"]
        source = next(task for task in pages[-1].checkpoint["tasks"].values()
                      if task["spec"]["handler"] == "resource_list")
        assert source["status"] == "failed" and source["pages"] == 1
        assert not any("/projects/100/" in url for url in client.calls)
        result = export_records(records(pages), spec=spec)
        assert any(row["token_id"] == 201 for row in result["inventory"])
        assert not any(row["token_id"] == 203 for row in result["inventory"])
        assert not result["manifest"]["all_scheduled_tasks_complete"]

    def test_rate_limit_defers_with_cursor_and_respects_long_server_wait(self):
        spec = spec_for()
        client = inventory_client(_config(spec))
        original = client.request

        def limited(url, query=None, variables=None):
            if urlsplit(url).path == "/api/v4/groups/10":
                raise CollectionError(
                    "RETRY_LATER", "Synthetic wait", 429, {"retry_after_seconds": 7200}
                )
            return original(url, query, variables)

        client.request = limited
        pages = run(spec, client=client)
        self.assertEqual(pages[-1].status, "WAITING")
        self.assertEqual(pages[-1].retry_after_seconds, 3600)
        checkpoint = deepcopy(pages[-1].checkpoint)
        early_client = inventory_client(_config(spec))
        waiting = run(spec, client=early_client, checkpoint=checkpoint, previous=records(pages))
        self.assertEqual(waiting[-1].status, "WAITING")
        self.assertEqual(early_client.calls, [])
        checkpoint["retry_not_before"] = 0  # Advance the synthetic scheduler, without sleeping.
        resumed = run(spec, checkpoint=checkpoint, previous=records(pages))
        self.assertEqual(resumed[-1].status, "COMPLETE")

    def test_unverified_bootstrap_rate_limit_defers_without_publishing_metadata(self):
        spec = spec_for()
        client = inventory_client(_config(spec))
        client.request = lambda *args, **kwargs: (_ for _ in ()).throw(
            CollectionError(
                "RATE_LIMIT_CIRCUIT_OPEN", "Synthetic wait", 429, {"retry_after_seconds": 90}
            )
        )
        pages = run(spec, client=client)
        self.assertEqual(pages[-1].status, "WAITING")
        self.assertIsNone(pages[-1].principal_id)
        self.assertFalse(pages[-1].principal_verified)
        self.assertEqual(records(pages), [])
        waiting = run(spec, checkpoint=pages[-1].checkpoint)
        self.assertEqual(waiting[-1].status, "WAITING")
        checkpoint = deepcopy(pages[-1].checkpoint)
        checkpoint["retry_not_before"] = 0
        self.assertEqual(run(spec, checkpoint=checkpoint)[-1].status, "COMPLETE")

    def test_operator_auth_requires_exact_token_secret_reference_slot(self):
        for refs in (
            {},
            {"password": "vault://synthetic/password"},
            {"token": "vault://synthetic/token", "password": "vault://synthetic/password"},
        ):
            with (
                self.subTest(roles=sorted(refs)),
                self.assertRaisesRegex(ValueError, "TOKEN_REFERENCE"),
            ):
                validate_spec(spec_for(secret_refs=refs))

    def test_cancel_callback_propagates_and_does_not_start_another_source(self):
        spec = spec_for()
        client = inventory_client(_config(spec))
        checks = []

        def check():
            checks.append(True)
            if len(checks) == 2:
                raise RuntimeError("SYNTHETIC_CANCELLED")

        with self.assertRaisesRegex(RuntimeError, "SYNTHETIC_CANCELLED"):
            run(spec, client=client, check=check)
        self.assertEqual(len(client.calls), 1)

    def test_runtime_never_opens_a_sidecar_database(self):
        with patch("sqlite3.connect", side_effect=AssertionError("runtime sidecar DB")):
            self.assertEqual(run(spec_for())[-1].status, "COMPLETE")

    def test_machine_root_label_cannot_authorize_descendants(self):
        observations = [
            item
            for page in self.pages
            for item in page.records
            if item.provenance.operation == "gitlab.native.observation"
        ]
        root = next(
            item
            for item in observations
            if unpack_facts([f.model_dump() for f in item.facts])["family"] == "group_deploy_token"
        )
        descendant = next(
            item
            for item in observations
            if unpack_facts([f.model_dump() for f in item.facts])["family"]
            == "project_deploy_token"
        )
        self.assertEqual(root.scope, descendant.scope)
        self.assertTrue(validate_machine_record(self.spec, root))
        self.assertFalse(validate_machine_record(self.spec, descendant))
        explicit = spec_for(
            audit=True, scopes=[{"kind": "group", "id": "10"}, {"kind": "project", "id": "100"}]
        )
        self.assertTrue(validate_machine_record(explicit, descendant))
        asset = next(
            item
            for page in self.pages
            for item in page.records
            if item.provenance.operation == "gitlab.native.asset"
            and item.identity.object_id == "project:100"
        )
        self.assertFalse(validate_machine_record(self.spec, asset))
        self.assertTrue(validate_machine_record(explicit, asset))

    def test_machine_self_requires_an_approved_numeric_principal(self):
        item = next(
            item
            for page in self.pages
            for item in page.records
            if item.provenance.operation == "gitlab.native.observation"
            and unpack_facts([f.model_dump() for f in item.facts])["observation"]["endpoint"]
            == "/personal_access_tokens"
        )
        unpinned = spec_for(scopes=[{"kind": "group", "id": "10"}, {"kind": "user", "id": "self"}])
        self.assertFalse(validate_machine_record(unpinned, item))
        pinned = unpinned.model_copy(update={"principal_pin": "1"})
        self.assertTrue(validate_machine_record(pinned, item))

    def test_machine_relation_checks_native_scope_as_well_as_observed_scopes(self):
        def relation_for(family, scope):
            native = native_identity(self.spec.origin, family, 7, scope)
            return record(self.spec, self.spec.scopes[0], "relation", {
                "identity": native, "inventory_id": stable_id(native),
                "observed_scopes": [{"kind": "group", "id": 10}],
                "user_id": 1, "relationship": "owns", "state": "observed",
            })

        allowed = relation_for("group_deploy_token", {"kind": "group", "id": 10})
        foreign = relation_for("project_deploy_token", {"kind": "project", "id": 100})
        pat = relation_for("personal_access_token", {"kind": "group", "id": 10})
        self.assertTrue(validate_machine_record(self.spec, allowed))
        self.assertTrue(validate_machine_record(self.spec, pat))
        self.assertTrue(validate_record(self.spec, foreign))  # worker discovery stays valid
        self.assertFalse(validate_machine_record(self.spec, foreign))
        explicit = spec_for(scopes=[{"kind": "group", "id": "10"}, {"kind": "project", "id": "100"}])
        self.assertTrue(validate_machine_record(explicit, foreign))

    def test_foreign_origin_or_changed_provider_status_is_rejected(self):
        item = next(
            item
            for page in self.pages
            for item in page.records
            if item.provenance.operation == "gitlab.native.observation"
            and item.normalized_state == "ACTIVE"
        )
        wrong = item.model_copy(update={"normalized_state": "REVOKED"})
        self.assertFalse(validate_record(self.spec, wrong))
        foreign = item.model_copy(
            update={
                "identity": item.identity.model_copy(update={"origin": "https://other.example"})
            }
        )
        self.assertFalse(validate_record(self.spec, foreign))

    def test_self_managed_cloud_api_is_explicitly_unsupported(self):
        spec = spec_for(
            origin="https://gitlab.example",
            edition="self_managed",
            options={"include_enterprise_pat": False},
        )
        client = inventory_client(_config(spec))
        pages = run(spec, client=client)
        self.assertIn("GITLAB_CLOUD_MANAGED_API_ONLY", pages[-1].reasons)
        self.assertFalse(any("/manage/" in url for url in client.calls))
        self.assertTrue(
            any(
                item["record_type"] == "operation_report" and item["status"] == "UNSUPPORTED"
                for item in records(pages)
            )
        )
        with self.assertRaisesRegex(ValueError, "CLOUD"):
            validate_spec(
                spec.model_copy(
                    update={
                        "options": spec.options.model_copy(update={"include_enterprise_pat": True})
                    }
                )
            )

    def test_export_compare_legacy_versions_and_jsonl(self):
        for version in ("1.0", "1.1", "1.2", "1.3", "1.4"):
            previous = deepcopy(self.export["inventory"])
            for row in previous:
                row["schema_version"] = version
            self.assertEqual(compare_records(self.records, previous, spec=self.spec), [])
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "previous.jsonl"
            file.write_text("\n".join(json.dumps(row) for row in previous), encoding="utf-8")
            self.assertEqual(compare_records(self.records, file, spec=self.spec), [])
        self.assertEqual(previous, self.export["inventory"])

    def test_compare_null_missing_and_audit_meaning_without_secret_values(self):
        previous = deepcopy(self.export["inventory"])
        trigger = next(row for row in previous if row["token_id"] == 501)
        trigger["metadata"].pop("last_used", None)
        trigger["metadata"]["token"] = "SYNTHETIC_DO_NOT_PERSIST_PREVIOUS"
        changes = compare_records(self.records, previous, spec=self.spec)
        changed = next(row for row in changes if row["inventory_id"] == trigger["inventory_id"])
        self.assertIn("last_used", changed["fields"])
        self.assertNotIn("token", changed["fields"])
        deploy = next(row for row in previous if row["token_id"] == 302)
        deploy["summary"]["issuer"]["id"] = 99
        changes = compare_records(self.records, previous, spec=self.spec)
        self.assertTrue(any(row["change"] == "audit_enrichment_changed" for row in changes))
        self.assertNotIn("SYNTHETIC_DO_NOT_PERSIST", json.dumps(changes))

    def test_absence_after_detail_only_is_unknown_and_never_revoked(self):
        config = _config(self.spec)
        store = Store(config.fingerprint())
        old = deepcopy(self.export["inventory"])
        previous = next(row for row in old if row["token_id"] == 302)
        detail = next(row for row in previous["observations"] if row["handler"] == "token_detail")
        task_id = store.add_task("token_detail", detail["endpoint"], detail["context"])
        store.page_done(store.state["tasks"][task_id], "synthetic-page", 1)
        change = next(iter(store.compare([previous])))
        self.assertEqual(change["change"], "observation_unknown")
        self.assertFalse(change["revocation_inferred"])

    def test_fact_states_and_omissions_do_not_retain_rejected_values(self):
        writer = FactWriter()
        facts = writer.facts(
            {
                "name": None,
                "metadata": {"name": "glpat-SYNTHETIC_NOT_A_REAL_KEY", "unapproved_extension": "x"},
                "permissions": [],
                "scope": {},
            }
        )
        values = {fact.name: fact for fact in facts}
        self.assertEqual(values["name"].state, "NULL")
        self.assertEqual(values["metadata"].children[0].state, "INVALID")
        self.assertEqual(values["scope"].container, "object")
        self.assertNotIn("glpat-", json.dumps([fact.model_dump() for fact in facts]))
        self.assertEqual(
            {item.reason for item in writer.omissions},
            {"INVALID_METADATA_VALUE", "UNAPPROVED_METADATA_FIELD"},
        )
        missing = MetadataFact(name="name", state="MISSING")
        self.assertNotIn("name", unpack_facts([missing.model_dump()]))


if __name__ == "__main__":
    unittest.main()
