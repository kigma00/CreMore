"""Small fake responses for collector tests; generated artifacts stay in temporary directories."""

import json
import tempfile
from copy import deepcopy
from pathlib import Path
from unittest.mock import Mock
from urllib.parse import urlsplit

from cremore_atlassian_provider.metadata.bitbucket import BitbucketClient
from cremore_atlassian_provider.metadata.compare import compare_snapshots
from cremore_atlassian_provider.metadata.discovery import collect_operation
from cremore_atlassian_provider.metadata.http import CloudClient, Limits
from cremore_atlassian_provider.metadata.jobs import collect_job, diagnostics, run_jobs
from cremore_atlassian_provider.metadata.recollect import build_plan, execute_plan

from .test_collector_cli import Response

ORG = "00000000-0000-0000-0000-000000000009"
WORKSPACE = "example-workspace"
WS_UUID = "{00000000-0000-0000-0000-000000000009}"
REPO_UUID = "{00000000-0000-0000-0000-000000000010}"
AUTH = "EXAMPLE_ONLY_NOT_A_REAL_CREDENTIAL"
T0 = "2026-09-21T00:00:00+00:00"
T1 = "2026-09-21T01:00:00+00:00"


def response(request, **kwargs):
    path = urlsplit(request.full_url).path
    if urlsplit(request.full_url).scheme == "https" and urlsplit(request.full_url).hostname == "api.atlassian.com":
        if path.endswith("/service-accounts/count"):
            return Response(
                {
                    "validServiceAccountIds": [
                        {"serviceAccountId": "service-1", "credentialsCount": 0}
                    ],
                    "invalidServiceAccountIds": [],
                }
            )
        if path.endswith("/oauth-clients/count"):
            return Response({
                "validServiceAccountIds": [
                    {"serviceAccountId": account, "credentialsCount": 0}
                    for account in json.loads(request.data)
                ],
                "invalidServiceAccountIds": [],
            })
        if path.endswith(("/api-keys/count", "/api-tokens/count")):
            return Response(1)
        if path.endswith("/api-keys"):
            return Response(
                {
                    "data": [{"id": "example-key-1", "label": "Example admin key"}],
                    "links": {"next": None},
                }
            )
        if path.endswith("/service-accounts"):
            return Response(
                {"items": [{"id": "service-1", "atlassianId": "service-1"}], "links": {}}
            )
        if path.endswith("/oauth-clients"):
            return Response(
                {"data": [], "links": {"next": None}} if "/service-accounts/" not in path else []
            )
        if path.endswith("/users"):
            return Response({"data": [{"account_id": "person-1"}], "links": {}})
        if path.endswith("/api-tokens"):
            rows = [
                {
                    "id": "example-token-1",
                    "label": "Example Jira token",
                    "status": "ALLOWED",
                    "scopes": ["read:jira-user"],
                    "user": {"id": "person-1", "email": "person@example.invalid"},
                }
            ]
            return Response(
                {"data": rows, "links": {"next": None}}
                if "/orgs/" in path and "/service-accounts/" not in path
                else rows
                if "/manage/" in path
                else []
            )
        return Response({"account_id": "person-1"})
    if path.endswith("/user"):
        return Response({"account_id": "person-1", "uuid": WS_UUID})
    if path.endswith("/workspaces/" + WORKSPACE):
        return Response({"slug": WORKSPACE, "uuid": WS_UUID})
    if path.endswith("/openid-configuration"):
        return Response({"issuer": "https://example.invalid/issuer"})
    if path.endswith("/keys.json"):
        return Response(
            {"keys": [{"kid": "public-key-1", "kty": "RSA", "n": "example", "e": "AQAB"}]}
        )
    if path.endswith("/repositories/" + WORKSPACE):
        return Response(
            {
                "values": [
                    {
                        "slug": "example-repo",
                        "uuid": REPO_UUID,
                        "workspace": {"slug": WORKSPACE, "uuid": WS_UUID},
                    }
                ]
            }
        )
    if path.endswith(
        (
            "/members",
            "/projects",
            "/ssh-keys",
            "/gpg-keys",
            "/deploy-keys",
            "/known_hosts",
            "/runners",
            "/branch-restrictions",
            "/public-key",
        )
    ):
        return Response({"values": []})
    return Response({"type": "example_metadata", "description": "Synthetic integration fixture"})


def job(mode, name=None):
    return {
        "name": name or mode,
        "mode": mode,
        "profile": "example",
        "expected_scope": ORG if mode.startswith("cloud-") else WORKSPACE,
        "limits": {"max_requests": 80, "retries": 0},
        "max_targets": 5,
    }


def client_factory(item, directory, limits):
    opener = Mock()
    opener.open.side_effect = response
    if item["mode"].startswith("cloud-"):
        return CloudClient(ORG, AUTH, limits, opener=opener)
    return BitbucketClient(WORKSPACE, AUTH, limits, opener=opener)


def generate():
    samples = {}
    modes = (
        "cloud-inventory",
        "cloud-discovery",
        "cloud-accounts",
        "bitbucket-core",
        "bitbucket-runners",
        "bitbucket-branches",
    )
    for mode in modes:
        item = job(mode)
        samples[mode] = collect_job(
            item, client_factory(item, None, Limits(retries=0)), now=lambda: T0
        )
    item = job("cloud-discovery")
    partial = deepcopy(samples["cloud-discovery"])
    limited = CloudClient(ORG, AUTH, Limits(max_pages=1, retries=0), opener=Mock())
    limited._opener.open.return_value = Response(
        {"data": [{"id": "example-key-1"}], "links": {"next": "opaque-example-cursor"}}
    )
    partial["collections"][0] = collect_operation(limited, "admin-api-keys", now=lambda: T0)
    partial["run_status"] = "partial"
    samples["partial"] = partial
    denied = deepcopy(samples["cloud-accounts"])
    rejected = CloudClient(ORG, AUTH, Limits(retries=0), opener=Mock())
    rejected._opener.open.return_value = Response({}, 403)
    denied["collections"] = [collect_operation(rejected, "managed-accounts", now=lambda: T0)]
    denied["run_status"] = "failed"
    denied["target_discovery"]["user_ids"] = []
    denied["not_requested_no_observed_targets"] = [
        "user-management-permissions",
        "user-profile",
        "user-api-tokens",
    ]
    samples["access-denied"] = denied
    samples["diagnostic"] = diagnostics(denied, job("cloud-accounts"))
    after = deepcopy(samples["cloud-accounts"])
    after["started_at"] = after["finished_at"] = T1
    # Same observed token, changed provider label; no invented revocation event.
    for report in after["collections"]:
        if report["operation"] == "user-api-tokens":
            report["pages"][0]["metadata"][0]["label"] = "Example updated label"
    samples["comparison"] = compare_snapshots(samples["cloud-accounts"], after)
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        manifest, _ = run_jobs(
            {"schema_version": 1, "jobs": [job("cloud-accounts")]},
            directory,
            client_factory=client_factory,
            now=lambda: T0,
        )
        samples["manifest"] = manifest
        plan = build_plan(partial, operations=["admin-api-keys"])
        samples["recollection-plan"] = plan
        result, _ = execute_plan(plan, directory, client_factory=client_factory, now=lambda: T1)
        samples["recollection"] = result
        for file in directory.glob("recollection-*.json"):
            value = json.loads(file.read_text())
            if value.get("checkpoint_kind") == "references":
                samples["recollection-checkpoint"] = value
            elif value.get("report_type") == "metadata_recollection_part":
                samples["recollection-part"] = value
        # Recovery tests need the referenced artifacts after this temporary directory closes.
        artifacts = {path.name: json.loads(path.read_text()) for path in directory.glob("*.json")}
    return samples, artifacts
