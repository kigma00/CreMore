"""Common storage, recovery and authentication boundaries over synthetic transport."""

import base64
import json
import unittest
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

from cremore.coverage.metadata_models import (
    MetadataConnectionSpec,
    MetadataFact,
    MetadataRelation,
    MetadataScope,
)
from cremore_atlassian_provider.metadata.adapter import (
    allowed_operations,
    collect_pages,
    current_record_status,
    validate_record,
    validate_spec,
)
from cremore_atlassian_provider.metadata.bitbucket import BitbucketClient
from cremore_atlassian_provider.metadata.discovery import iter_operation
from cremore_atlassian_provider.metadata.http import CloudClient, Limits
from cremore_atlassian_provider.metadata.projection import record_facts
from cremore_atlassian_provider.metadata.replay import (
    compare_records,
    native_snapshots,
    plan_recollection,
)
from cremore_atlassian_provider.metadata.steps import CollectionInterrupted

from .output_samples import AUTH, ORG, T0, T1, WORKSPACE, response
from .test_bitbucket import PGP_PUBLIC, PUBLIC_KEY
from .test_collector import token
from .test_collector_cli import Response
from .test_collector_http import Clock
from .test_collector_http import Response as HttpResponse


def spec(mode="inventory", **changes):
    cloud = mode in {"inventory", "discovery", "accounts"}
    values = {
        "name": "Synthetic metadata",
        "provider": "atlassian" if cloud else "bitbucket",
        "origin": "https://api.atlassian.com" if cloud else "https://api.bitbucket.org",
        "scopes": [
            {"kind": "organization" if cloud else "workspace", "id": ORG if cloud else WORKSPACE}
        ],
        "capabilities": ["inventory"],
        "secret_refs": {"token": "vault://test/token"},
        "options": {"mode": mode, "max_retries": 0},
        "max_requests": 200,
    }
    values.update(changes)
    return MetadataConnectionSpec.model_validate(values)


def factory(opener):
    def create(config, scope, secrets, limits, check):
        if config.provider == "atlassian":
            return CloudClient(scope.id, secrets["token"], limits, opener=opener, check=check)
        return BitbucketClient(scope.id, secrets["token"], limits, opener=opener, check=check)

    return create


def collect(config, opener, *, checkpoint=None, records=(), time=T0):
    pages = list(
        collect_pages(
            config,
            secrets={"token": AUTH},
            checkpoint=checkpoint or {},
            check=lambda: None,
            read_records=lambda: iter(records),
            client_factory=factory(opener),
            now=lambda: time,
        )
    )
    return pages, [item for page in pages for item in page.records]


class CommonAdapterTests(unittest.TestCase):
    def test_six_modes_round_trip_typed_records_without_local_files(self):
        for mode in (
            "inventory",
            "discovery",
            "accounts",
            "bitbucket",
            "runners",
            "branch_restrictions",
        ):
            with self.subTest(mode=mode):
                config = spec(mode)
                opener = Mock()
                opener.open.side_effect = response
                pages, records = collect(config, opener)
                self.assertTrue(all(validate_record(config, item) for item in records))
                self.assertTrue(
                    all(page.principal_id is None and not page.principal_verified for page in pages)
                )
                self.assertNotIn(AUTH, json.dumps([r.model_dump() for r in records]))
                snapshot = native_snapshots(records)[0]
                self.assertFalse(snapshot["inventory_complete"])
                self.assertEqual(snapshot["started_at"], T0)
                self.assertTrue(snapshot["collections"])
                self.assertTrue(opener.open.call_count)

    def test_latest_branch_exposes_17_cloud_and_28_bitbucket_reads(self):
        cloud = allowed_operations(spec("discovery"))
        bitbucket = set().union(
            *(
                allowed_operations(spec(mode))
                for mode in ("bitbucket", "runners", "branch_restrictions")
            )
        )
        self.assertEqual((len(cloud), len(bitbucket)), (17, 28))
        self.assertIn("repository-branch-restrictions", bitbucket)

    def test_page_published_before_next_read_and_cancel_does_not_return_failed_report(self):
        opener = Mock()
        opener.open.side_effect = [Response({"data": [{"id": "one"}], "links": {"next": "second"}})]
        cancelled = False

        def check():
            if cancelled:
                raise RuntimeError("LEASE_LOST")

        client = CloudClient(ORG, AUTH, opener=opener, check=check)
        iterator = iter_operation(client, "org-api-tokens")
        page = next(iterator)
        self.assertEqual(page.page["saved_records"], 1)
        self.assertEqual(opener.open.call_count, 1)
        cancelled = True
        with self.assertRaises(CollectionInterrupted):
            next(iterator)
        self.assertEqual(opener.open.call_count, 1)

    def test_resume_restarts_interrupted_operation_without_mixing_abandoned_rows(self):
        config = spec(
            options={"mode": "inventory", "sources": ["org-api-tokens"], "max_retries": 0}
        )
        opener = Mock()
        opener.open.side_effect = [
            Response({"data": [token("abandoned")], "links": {"next": "old-cursor"}})
        ]
        iterator = collect_pages(
            config,
            secrets={"token": AUTH},
            checkpoint={},
            check=lambda: None,
            read_records=lambda: iter(()),
            client_factory=factory(opener),
            now=lambda: T0,
        )
        committed = next(iterator)
        iterator.close()
        self.assertEqual(opener.open.call_count, 1)
        opener2 = Mock()
        opener2.open.side_effect = [
            Response({"data": [token("one")], "links": {"next": "fresh-cursor"}}),
            Response({"data": [token("two")], "links": {"next": None}}),
        ]
        pages, resumed = collect(
            config,
            opener2,
            checkpoint=committed.checkpoint,
            records=[r.model_dump() for r in committed.records],
            time=T1,
        )
        requests = [call.args[0].full_url for call in opener2.open.call_args_list]
        self.assertNotIn("cursor", parse_qs(urlsplit(requests[0]).query))
        self.assertEqual(parse_qs(urlsplit(requests[1]).query)["cursor"], ["fresh-cursor"])
        history = [*committed.records, *resumed]
        snapshot = native_snapshots(history)[0]
        self.assertEqual({entry["provider_id"] for entry in snapshot["inventory"]}, {"one", "two"})
        self.assertEqual(snapshot["collections"]["org-api-tokens"]["pages"], 2)
        self.assertEqual(len([r for r in history if r.record_type == "entity_observation"]), 3)
        self.assertEqual(pages[-1].status, "COMPLETE")
        reports = [r.model_dump() for r in history if r.record_type == "operation_report"]
        statuses = [
            (
                record_facts(r)["metadata"]["fields"][0]["metadata"]["value"],
                current_record_status(config, r.model_dump(), reports),
            )
            for r in history
            if r.record_type == "entity_observation"
        ]
        self.assertEqual(statuses, [("abandoned", None), ("one", "COMPLETE"), ("two", "COMPLETE")])

    def test_resume_skips_committed_complete_operation(self):
        config = spec(
            options={"mode": "inventory", "sources": ["org-api-tokens"], "max_retries": 0}
        )
        opener = Mock()
        opener.open.return_value = Response({"data": [token("one")], "links": {"next": None}})
        iterator = collect_pages(
            config,
            secrets={"token": AUTH},
            checkpoint={},
            check=lambda: None,
            read_records=lambda: iter(()),
            client_factory=factory(opener),
            now=lambda: T0,
        )
        first, terminal = next(iterator), next(iterator)
        iterator.close()
        opener2 = Mock()
        opener2.open.side_effect = AssertionError("Completed operation was requested again")
        _, records = collect(
            config,
            opener2,
            checkpoint=terminal.checkpoint,
            records=[r.model_dump() for p in (first, terminal) for r in p.records],
            time=T1,
        )
        self.assertEqual(opener2.open.call_count, 0)
        snapshot = native_snapshots([*first.records, *terminal.records, *records])[0]
        self.assertEqual(len(snapshot["inventory"]), 1)

    def test_a_page_checkpoint_in_a_resumed_scope_keeps_an_earlier_scopes_partial(self):
        from cremore_atlassian_provider.metadata.adapter import configuration_hash

        second = "22222222-3333-4444-8555-666666666666"
        config = spec(scopes=[{"kind": "organization", "id": ORG}, {"kind": "organization", "id": second}])
        # The first scope ended PARTIAL; the run was interrupted and resumes in the second.
        checkpoint = {"version": 1, "provider": "atlassian", "config_hash": configuration_hash(config),
                      "attempt": 1, "started_at": T0, "scope_index": 1, "requests": 0,
                      "recollection_hash": None, "status": "PARTIAL", "seen_success": True}
        opener = Mock()
        opener.open.side_effect = response
        pages, _ = collect(config, opener, checkpoint=checkpoint)
        inside = [p.checkpoint for p in pages if p.checkpoint.get("scope_index") == 1]
        # A second interruption inside that scope resumes from one of these: each must still say PARTIAL.
        self.assertTrue(inside)
        self.assertEqual({(c.get("status"), c.get("seen_success")) for c in inside}, {("PARTIAL", True)})
        self.assertEqual(pages[-1].status, "PARTIAL")

    def test_unknown_metadata_is_explicit_and_never_silently_complete(self):
        config = spec("accounts")
        opener = Mock()
        opener.open.side_effect = [
            Response({"data": [], "links": {}, "futurePrivateData": "DO_NOT_PUBLISH"})
        ]
        pages, records = collect(config, opener)
        self.assertNotIn("DO_NOT_PUBLISH", json.dumps([r.model_dump() for r in records]))
        self.assertTrue(any(r.omissions for r in records))
        self.assertEqual(pages[-1].status, "PARTIAL")
        snapshot = native_snapshots(records)[0]
        self.assertEqual(snapshot["collections"][0]["coverage"], "unverified")

    def test_repository_slug_used_for_fan_out_is_an_approved_field(self):
        def reply(request, **kwargs):
            if urlsplit(request.full_url).path.endswith("/repositories/" + WORKSPACE):
                return Response({"values": [{"type": "repository", "slug": "example-repo",
                                             "name": "Example", "full_name": WORKSPACE + "/example-repo"}]})
            if urlsplit(request.full_url).path.endswith("/repositories/" + WORKSPACE + "/example-repo"):
                return Response({"type": "repository", "slug": "example-repo", "name": "Example"})
            return response(request, **kwargs)

        opener = Mock()
        opener.open.side_effect = reply
        _, records = collect(spec("bitbucket"), opener)
        repository = [r for r in records if r.provenance.operation in {"repositories", "repository-detail"}]
        self.assertEqual({r.provenance.operation for r in repository}, {"repositories", "repository-detail"})
        self.assertFalse(any(r.omissions for r in repository))

    def test_denied_and_empty_are_distinct_and_counts_do_not_invent_credentials(self):
        config = spec("accounts")
        opener = Mock()
        opener.open.return_value = Response({}, status=403)
        pages, records = collect(config, opener)
        snapshot = native_snapshots(records)[0]
        self.assertEqual(snapshot["collections"][0]["reason"], "http_403")
        self.assertEqual(pages[-1].status, "FAILED")
        self.assertFalse(any(r.record_type == "entity_observation" for r in records))
        self.assertEqual(plan_recollection(records)["selected_count"], 1)

    def test_compare_and_recollect_use_typed_history_and_preserve_absence_uncertainty(self):
        config = spec(
            options={"mode": "inventory", "sources": ["org-api-tokens"], "max_retries": 0}
        )
        first, second = Mock(), Mock()
        first.open.return_value = Response({"data": [token("one")], "links": {"next": None}})
        second.open.return_value = Response({"data": [], "links": {"next": None}})
        _, before = collect(config, first)
        _, after = collect(config, second, time=T1)
        comparison = compare_records(before, after)
        self.assertNotIn("revoked", json.dumps(comparison).lower())
        self.assertIn("not_observed", json.dumps(comparison))
        self.assertEqual(plan_recollection(after)["selected_count"], 0)

    def test_scope_mode_origin_and_unproven_principal_pin_fail_before_requests(self):
        for changes in (
            {"origin": "https://unapproved.invalid"},
            {"edition": "data_center"},
            {"scopes": [{"kind": "organization", "id": "not-uuid"}]},
            {"provider": "bitbucket"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_spec(spec(**changes))
        opener = Mock()
        with self.assertRaisesRegex(ValueError, "PRINCIPAL_PIN"):
            collect(spec(principal_pin="not-inferred-from-org"), opener)
        opener.open.assert_not_called()

    def test_basic_is_explicit_public_oidc_is_unauthenticated_and_public_keys_survive(self):
        opener = Mock()
        opener.open.side_effect = [
            Response({"account_id": "one"}),
            Response({"issuer": "https://example.invalid"}),
        ]
        client = BitbucketClient(
            WORKSPACE, AUTH, auth_type="basic", email="person@example.invalid", opener=opener
        )
        client.read_metadata("current-user")
        client.read_metadata("workspace-oidc-configuration")
        encoded = base64.b64encode(("person@example.invalid:" + AUTH).encode()).decode()
        self.assertEqual(
            opener.open.call_args_list[0].args[0].get_header("Authorization"), "Basic " + encoded
        )
        self.assertIsNone(opener.open.call_args_list[1].args[0].get_header("Authorization"))
        snapshot, _ = client.snapshot(
            {"key": PUBLIC_KEY, "label": encoded, "public_key": PGP_PUBLIC}
        )
        self.assertEqual(snapshot["key"], PUBLIC_KEY)
        self.assertNotIn(encoded, json.dumps(snapshot))

    def test_cancel_during_retry_wait_prevents_second_request(self):
        clock = Clock()
        opener = Mock()
        opener.open.return_value = HttpResponse(b"{}", status=429, headers={"Retry-After": "3"})

        def check():
            if clock.value >= 1:
                raise RuntimeError("CANCELLED")

        client = CloudClient(
            ORG, AUTH, Limits(), opener=opener, clock=clock.now, sleep=clock.sleep, check=check
        )
        with self.assertRaises(CollectionInterrupted):
            client.read_metadata("managed-accounts")
        self.assertEqual(opener.open.call_count, 1)
        self.assertEqual(clock.waits, [1])

    def test_machine_submission_cannot_change_root_or_operation_or_entity_identity(self):
        config = spec(
            options={"mode": "inventory", "sources": ["org-api-tokens"], "max_retries": 0}
        )
        opener = Mock()
        opener.open.return_value = Response({"data": [token("one")], "links": {"next": None}})
        _, records = collect(config, opener)
        entity = next(r for r in records if r.record_type == "entity_observation")
        self.assertTrue(validate_record(config, entity))
        changed = entity.model_copy(
            update={
                "scope": MetadataScope(
                    kind="organization", id="00000000-0000-0000-0000-000000000099"
                )
            }
        )
        self.assertFalse(validate_record(config, changed))
        changed = entity.model_copy(
            update={"identity": entity.identity.model_copy(update={"object_id": "fabricated"})}
        )
        self.assertFalse(validate_record(config, changed))
        self.assertEqual(record_facts(entity)["context"]["operation"], "org-api-tokens")
        unsupported = MetadataRelation(
            scope=entity.scope, provenance=entity.provenance, facts=entity.facts,
            subject=entity.identity, target=entity.identity, relation="owns",
            match_basis="PROVIDER_EXPLICIT", confidence="EXACT",
        )
        self.assertFalse(validate_record(config, unsupported))

    def test_machine_submission_rejects_other_operation_fields_and_nested_report_payload(self):
        config = spec("accounts")
        opener = Mock()
        opener.open.side_effect = response
        _, records = collect(config, opener)
        entity = next(r for r in records if r.record_type == "entity_observation")
        injected = entity.model_copy(deep=True)
        next(f for f in injected.facts if f.name == "metadata").children.append(
            MetadataFact(
                name="details",
                container="object",
                children=[MetadataFact(name="entry", value="unapproved")],
            )
        )
        self.assertFalse(validate_record(config, injected))
        report = next(
            r
            for r in records
            if r.record_type == "operation_report"
            and record_facts(r)["context"]["stage"] == "operation_complete"
        )
        injected = report.model_copy(deep=True)
        metadata = next(f for f in injected.facts if f.name == "metadata")
        redactions = next(f for f in metadata.children if f.name == "redactions")
        redactions.children.append(MetadataFact(name="details", value="unapproved"))
        self.assertFalse(validate_record(config, injected))

    def test_branch_rule_references_survive_but_unknown_secret_metadata_does_not(self):
        config = spec("branch_restrictions")
        rule = {
            "id": 1,
            "kind": "push",
            "pattern": "release/*",
            "users": [],
            "groups": [],
            "access_tokens": [
                {"id": "reference-only", "name": "deployment", "secret": "MUST_NOT_LEAVE_MEMORY"}
            ],
            "details": {"entry": "NOT_IN_BRANCH_RESPONSE"},
        }
        opener = Mock()
        opener.open.side_effect = [
            Response({"values": [{"slug": "repo", "uuid": "repo-id"}]}),
            Response({"values": [rule]}),
            Response(rule),
        ]
        pages, records = collect(config, opener)
        exported = json.dumps([r.model_dump() for r in records])
        self.assertIn("reference-only", exported)
        self.assertNotIn("MUST_NOT_LEAVE_MEMORY", exported)
        self.assertNotIn("NOT_IN_BRANCH_RESPONSE", exported)
        self.assertEqual(pages[-1].status, "PARTIAL")
        self.assertTrue(all(validate_record(config, r) for r in records))
        policies = [
            r
            for r in records
            if r.record_type == "entity_observation" and r.identity.kind == "policy"
        ]
        reports = [r.model_dump() for r in records if r.record_type == "operation_report"]
        self.assertTrue(policies)
        self.assertEqual(
            {current_record_status(config, r.model_dump(), reports) for r in policies}, {"PARTIAL"}
        )

    def test_selected_recollection_preserves_normalized_inventory_and_uses_fresh_page_one(self):
        config = spec(
            options={"mode": "inventory", "sources": ["org-api-tokens"], "max_retries": 0}
        )
        first = Mock()
        first.open.return_value = Response({}, status=403)
        _, history = collect(config, first)
        plan = plan_recollection(history)
        self.assertEqual([task["operation"] for task in plan["tasks"]], ["org-api-tokens"])
        second = Mock()
        second.open.return_value = Response({"data": [token("recovered")], "links": {"next": None}})
        pages = list(
            collect_pages(
                config,
                secrets={"token": AUTH},
                checkpoint={},
                check=lambda: None,
                read_records=lambda: iter(()),
                client_factory=factory(second),
                now=lambda: T1,
                recollection_plan=plan,
            )
        )
        snapshot = native_snapshots([r for p in pages for r in p.records])[0]
        self.assertEqual([row["provider_id"] for row in snapshot["inventory"]], ["recovered"])
        self.assertIn("SELECTED_READS_ONLY", snapshot["source_reasons"])
        self.assertEqual(second.open.call_count, 1)
        self.assertNotIn("cursor", parse_qs(urlsplit(second.open.call_args.args[0].full_url).query))
        self.assertEqual(pages[-1].status, "PARTIAL")

    def test_public_gpg_and_empty_array_remain_distinct_typed_values(self):
        config = spec("bitbucket")
        opener = Mock()

        def reply(request, **kwargs):
            if request.full_url.endswith("/settings/gpg/public-key"):
                return HttpResponse(PGP_PUBLIC.encode())
            return response(request, **kwargs)

        opener.open.side_effect = reply
        _, records = collect(config, opener)
        snapshot = native_snapshots(records)[0]
        gpg = next(r for r in snapshot["collections"] if r["operation"] == "workspace-gpg-key")
        self.assertEqual(gpg["pages"][0]["metadata"], PGP_PUBLIC)
        projects = next(r for r in snapshot["collections"] if r["operation"] == "projects")
        self.assertEqual(projects["pages"][0]["metadata"]["values"], [])

    def test_url_userinfo_and_named_auth_parameters_are_omitted_and_machine_rejected(self):
        for url in (
            "https://name:UNSAFE_USERINFO@example.invalid/profile",
            "ssh://name:UNSAFE_OTHER_SCHEME@example.invalid/profile",
            "//name:UNSAFE_RELATIVE_AUTHORITY@example.invalid/profile",
            "https://example.invalid/profile?api_key=UNSAFE_QUERY",
            "https://example.invalid/profile?X-Amz-Signature=UNSAFE_SIGNATURE",
            "https://example.invalid/profile#access_token=UNSAFE_FRAGMENT",
        ):
            with self.subTest(url_kind=url.split("UNSAFE")[0]):
                config = spec("accounts")
                opener = Mock()
                opener.open.side_effect = [
                    Response(
                        {"data": [{"account_id": "one", "links": {"self": url}}], "links": {}}
                    ),
                    Response({}),
                    Response({}),
                    Response([]),
                ]
                pages, records = collect(config, opener)
                self.assertNotIn("UNSAFE_", json.dumps([r.model_dump() for r in records]))
                self.assertEqual(pages[-1].status, "PARTIAL")
                self.assertTrue(all(validate_record(config, r) for r in records))
                entity = next(r for r in records if r.record_type == "entity_observation")
                forged = entity.model_copy(deep=True)
                metadata = next(f for f in forged.facts if f.name == "metadata")
                links = next(f for f in metadata.children if f.name == "links")
                links.children = [MetadataFact(name="self", value=url)]
                self.assertFalse(validate_record(config, forged))
