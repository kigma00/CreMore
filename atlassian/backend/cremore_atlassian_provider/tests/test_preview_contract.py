"""ECOHELP-167001 contracts, using synthetic accounts and credentials only."""

import json
from functools import partial
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import urlsplit

import pytest

from cremore.coverage import METADATA_JOB_KIND
from cremore.coverage.metadata_store import MetadataStore
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import ScanJob
from cremore.worker import JobWorker
from cremore_atlassian_provider.metadata import adapter
from cremore_atlassian_provider.metadata.discovery import collect_discovery, count_comparisons
from cremore_atlassian_provider.metadata.http import CloudClient, Limits
from cremore_atlassian_provider.metadata.read_operations import ACCOUNT_COUNT_OPERATIONS
from cremore_atlassian_provider.metadata.recollect import build_plan
from cremore_atlassian_provider.metadata.replay import native_snapshots

from .output_samples import AUTH, ORG, response
from .test_collector_cli import Response
from .test_common_adapter import factory, spec
from .test_discovery import Client, empty_baseline, ok
from .test_recollect import failed, source


def counts(ids, count=2):
    return {
        "validServiceAccountIds": [
            {"serviceAccountId": account, "credentialsCount": count} for account in ids
        ],
        "invalidServiceAccountIds": [],
    }


def oauth(client_id, account="service-1"):
    return {
        "clientId": client_id,
        "clientName": "Synthetic OAuth client",
        "serviceAccount": {"id": account, "name": "Synthetic service account"},
        "createdBy": {"id": "person-1"},
        "scopes": ["read:jira-user"],
        "createdAt": "2026-09-23T00:00:00Z",
        "expiresAt": "2026-09-27T00:00:00Z",
        "disabled": False,
        "tokenEndpointAuthMethod": None,
        "clientRevokerId": None,
        "clientRevocationTime": None,
    }


def preview_response(request, **kwargs):
    path = urlsplit(request.full_url).path
    if path.endswith("/oauth-clients/count"):
        assert request.get_method() == "POST"
        return Response(counts(json.loads(request.data)))
    if path.endswith("/oauth-clients"):
        return Response([oauth("client-1"), oauth("client-2")])
    if "/oauth-clients/client-" in path:
        return Response(oauth(path.rsplit("/", 1)[1]))
    if path.endswith("/api-tokens") and "/service-accounts/" not in path:
        body = json.loads(response(request, **kwargs).read())
        for row in body["data"]:
            row["createdBy"] = {
                "id": "issuer-1",
                "appType": None,
                "orgId": None,
                "userStatus": "active",
            }
            row["user"].update(appType="jira", userStatus=None)
        return Response(body)
    return response(request, **kwargs)


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_preview_metadata_survives_worker_storage_and_native_replay(backend, monkeypatch):
    engine = make_engine("sqlite:///:memory:") if backend == "sqlite" else None
    if engine is not None:
        create_all(engine)
    repo = SqlRepository(engine) if engine is not None else InMemoryRepository()
    config = spec(
        "discovery", options={"mode": "discovery", "include_account_reads": False, "max_retries": 0}
    )
    opener = Mock()
    opener.open.side_effect = preview_response
    monkeypatch.setattr(
        adapter, "collect_pages", partial(adapter.collect_pages, client_factory=factory(opener))
    )
    store = MetadataStore(repo)
    connection, _ = store.create(config, "test")
    job = repo.enqueue_job(
        ScanJob(
            kind=METADATA_JOB_KIND,
            payload={
                "provider": "atlassian",
                "coverage_connection_id": str(connection["id"]),
                "coverage_revision": connection["revision"],
            },
        )
    )
    try:
        resolver = SimpleNamespace(resolve=lambda ref: {"token": AUTH})
        assert JobWorker(repo, metadata_secret_resolver=resolver).process_next()
        done = repo.get_job(job.id)
        assert done.status == "SUCCEEDED", done.error
        run = store.connection_runs(connection["id"])["items"][0]
        records = list(store.iter_records(run["id"]))
        snapshot = native_snapshots(records)[0]
        reports = {r["operation"]: r for r in snapshot["collections"]}
        count_report = reports["org-oauth-client-count"]
        assert count_report["coverage"] == "complete"
        assert count_report["requested_account_ids"] == ["service-1"]
        assert count_report["pages"][0]["metadata"] == counts(["service-1"])
        tokens = reports["org-api-tokens"]
        assert tokens["coverage"] == "complete"
        token = tokens["pages"][0]["metadata"]["data"][0]
        assert token["createdBy"]["id"] == "issuer-1"
        assert token["createdBy"]["userStatus"] == "active"
        assert token["user"]["appType"] == "jira"
        listing = reports["org-oauth-clients"]
        assert listing["coverage"] == "unverified"
        assert listing["reason"] == "pagination_contract_unverified"
        assert listing["pages"][0]["metadata"] == [oauth("client-1"), oauth("client-2")]
        details = [r for r in snapshot["collections"] if r["operation"] == "oauth-client-detail"]
        assert len(details) == 2
        assert all(r["coverage"] == "complete" for r in details)
        assert {r["pages"][0]["metadata"]["createdAt"] for r in details} == {"2026-09-23T00:00:00Z"}
        comparison = count_comparisons(snapshot["collections"])[-1]
        assert snapshot["count_comparisons"][-1] == comparison
        assert comparison["reported_count"] == comparison["listed_unique_ids"] == 2
        assert comparison["equal_at_observation"] is True
        assert comparison["comparison_scope"] == "requested_service_accounts"
        assert comparison["proves_completeness"] is False
        inventory = store.inventory(connection_id=connection["id"], object_kind="credential")
        ids = {row["object_id"].rsplit("/", 1)[-1] for row in inventory["items"]}
        assert {"client-1", "client-2"} <= ids
        assert store.inventory(connection_id=connection["id"], object_kind="principal")["total"]
        assert AUTH not in json.dumps(records, default=str)
        calls = [call.args[0].full_url for call in opener.open.call_args_list]
        assert next(i for i, url in enumerate(calls) if url.endswith("/service-accounts")) < next(
            i for i, url in enumerate(calls) if url.endswith("/oauth-clients/count")
        )
    finally:
        if engine is not None:
            engine.dispose()


def test_count_batches_use_only_discovered_accounts_and_never_an_empty_post():
    ids = [f"service-{i:03d}" for i in range(101)]
    pages = empty_baseline()
    pages["service-accounts"] = [
        ok(
            {
                "items": [
                    {"atlassianId": account, "id": "different-internal-id"} for account in ids
                ],
                "links": {},
                "total": 101,
            }
        )
    ]
    for operation in ACCOUNT_COUNT_OPERATIONS:
        pages[operation] = [ok(counts(ids[:100], 1)), ok(counts(ids[100:], 1))]
    for operation in (
        "service-account-api-tokens-by-account",
        "service-account-oauth-clients-by-account",
    ):
        pages[operation] = [ok([]) for _ in ids]
    client = Client(pages)
    result = collect_discovery(client, max_targets=101, include_account_reads=False)
    for operation in ACCOUNT_COUNT_OPERATIONS:
        batches = [kwargs["body"] for name, kwargs in client.calls if name == operation]
        assert batches == [ids[:100], ids[100:]]
    comparison = result["count_comparisons"][-1]
    assert comparison["requested_account_count"] == 101
    assert comparison["reported_count"] == 101 and comparison["equal_at_observation"] is False
    client = Client(empty_baseline())
    result = collect_discovery(client, include_account_reads=False)
    assert not any(name in ACCOUNT_COUNT_OPERATIONS for name, _ in client.calls)
    assert set(ACCOUNT_COUNT_OPERATIONS) <= set(result["not_requested_no_observed_targets"])


@pytest.mark.parametrize("body", [None, [], {}, ["same", "same"], ["x"] * 101, ["x" * 101]])
@pytest.mark.parametrize("operation", ACCOUNT_COUNT_OPERATIONS)
def test_both_count_routes_reject_invalid_batches_before_transport(operation, body):
    opener = Mock()
    client = CloudClient(ORG, AUTH, Limits(retries=0), opener=opener)
    with pytest.raises(ValueError):
        client.read_metadata(operation, body=body)
    opener.open.assert_not_called()


@pytest.mark.parametrize("variant", ["missing", "invalid", "unexpected", "duplicate", "failed"])
def test_incomplete_count_response_never_becomes_zero_or_a_match(variant):
    body = counts(["service-1"])
    if variant == "missing":
        body["validServiceAccountIds"] = []
    elif variant == "invalid":
        body = {"validServiceAccountIds": [], "invalidServiceAccountIds": ["service-1"]}
    elif variant == "unexpected":
        body = counts(["unrequested-account"])
    elif variant == "duplicate":
        body["validServiceAccountIds"] *= 2
    reports = [
        {"operation": "org-oauth-clients", "pages": [{"metadata": [oauth("client-1")]}]},
        {
            "operation": "org-oauth-client-count",
            "requested_account_ids": ["service-1"],
            "coverage": "failed" if variant == "failed" else "complete",
            "pages": [] if variant == "failed" else [{"metadata": body}],
        },
    ]
    comparison = count_comparisons(reports)[0]
    assert comparison["reported_count"] is None
    assert comparison["equal_at_observation"] is None
    assert comparison["proves_completeness"] is False


def test_oauth_count_recollection_preserves_batch_and_rejects_old_bodyless_request():
    report = failed("org-oauth-client-count")
    report["requested_account_ids"] = ["service-1", "service-2"]
    plan = build_plan(source(report))
    assert plan["tasks"][0]["requested_account_ids"] == ["service-1", "service-2"]
    with pytest.raises(ValueError):
        build_plan(source(failed("org-oauth-client-count")))


@pytest.mark.parametrize("unattributed", [False, True])
def test_count_comparison_is_limited_to_requested_accounts(unattributed):
    extra = (
        {"clientId": "unknown-client"} if unattributed else oauth("other-client", "other-account")
    )
    reports = [
        {"operation": "org-oauth-clients", "pages": [{"metadata": [oauth("client-1"), extra]}]},
        {
            "operation": "org-oauth-client-count",
            "requested_account_ids": ["service-1"],
            "coverage": "complete",
            "pages": [{"metadata": counts(["service-1"], 1)}],
        },
    ]
    comparison = count_comparisons(reports)[0]
    assert comparison["listed_unique_ids"] == comparison["reported_count"] == 1
    assert comparison["equal_at_observation"] is (None if unattributed else True)
    reports.append(
        {
            "operation": "org-oauth-client-count",
            "requested_account_ids": ["service-2"],
            "coverage": "failed",
            "pages": [],
        }
    )
    assert count_comparisons(reports)[0]["reported_count"] is None


def test_a_batch_answering_for_another_batchs_accounts_is_not_a_count():
    # Together the answers cover every requested account; each batch alone does not.
    reports = [
        {
            "operation": "org-oauth-clients",
            "pages": [{"metadata": [oauth("client-1"), oauth("client-2", "service-2")]}],
        },
        *(
            {
                "operation": "org-oauth-client-count",
                "requested_account_ids": [asked],
                "coverage": "complete",
                "pages": [{"metadata": counts([answered], 1)}],
            }
            for asked, answered in (("service-1", "service-2"), ("service-2", "service-1"))
        ),
    ]
    comparison = count_comparisons(reports)[0]
    assert comparison["reported_count"] is None
    assert comparison["equal_at_observation"] is None
