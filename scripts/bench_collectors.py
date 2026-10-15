"""Offline collector timing and output digests for every provider library.

Each scenario runs a real provider collection against the synthetic transports
the provider tests already use (no network, no database). The report keeps the
median wall time and a digest of the normalized output, so running the same
script on two source trees shows whether a refactor changed what a collector
produces or how fast it produces it:

    python scripts/bench_collectors.py --root <tree> --repeat 15 --output before.json

What the digest covers (review 2026-09-26): every page's status, records,
checkpoint, reasons and retry wait, plus the order of provider requests where
the scenario's fake transport records them. Every sample is hashed outside the
timed interval and ``stable`` means all samples produced the same digest. Only
timestamps in the wall-clock fields a run stamps (WALL_CLOCK_FIELDS, measured
by diffing two unmasked runs) and within two hours of the run become "<now>";
fixture timestamps and every other time value are compared as they are.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import io
import json
import re
import statistics
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

VENDOR_PATHS = ("aws/backend", "gcp/backend", "github/backend", "gitlab/backend", "notion/backend",
                "atlassian/backend", "azure/backend", "vault/backend", "okta/backend", "keycloak/backend",
                "slack/backend", "website/backend", "gcp/standalone")
_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
STARTED = datetime.now(UTC)


CODE_FACTS = {"code_commit", "code_digest"}
# Keys and fact names whose values are the run's own clock (found by diffing two runs 1 s apart).
WALL_CLOCK_FIELDS = frozenset({"observed_at", "read_at", "started_at", "finished_at", "completed_at",
                               "first_seen", "last_seen", "first_seen_at_this_run", "last_seen_at_this_run"})


def _now_stamp(value):
    """True for an ISO timestamp within two hours of this run's start."""
    if isinstance(value, datetime):
        value = value.isoformat()
    if not (isinstance(value, str) and _ISO.match(value)):
        return False
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return False
    moment = moment if moment.tzinfo else moment.replace(tzinfo=UTC)
    return abs(moment - STARTED) < timedelta(hours=2)


def _mask_code_provenance(facts):
    """Collector records may carry the code version that produced them (git commit,
    per-file source digests). A refactor legitimately changes those, so they are
    compared as '<code>' and the digest covers only what the collector collected."""
    names = {fact.get("name"): fact for fact in facts if isinstance(fact, dict)}
    source_file = str((names.get("name") or {}).get("value") or "").endswith(".py")
    for fact in facts:
        if isinstance(fact, dict) and (fact.get("name") in CODE_FACTS
                                       or (source_file and fact.get("name") == "digest")):
            fact["value"] = "<code>"
        elif isinstance(fact, dict) and fact.get("name") in WALL_CLOCK_FIELDS and _now_stamp(fact.get("value")):
            fact["value"] = "<now>"
    return facts


def _normalize(value):
    """JSON-ready structure; timestamps taken from the wall clock become '<now>'."""
    if hasattr(value, "model_dump"):
        return _normalize(value.model_dump(mode="json"))
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _normalize(dataclasses.asdict(value))
    if isinstance(value, dict):
        return {str(key): "<now>" if key in WALL_CLOCK_FIELDS and _now_stamp(item) else _normalize(item)
                for key, item in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, list | tuple | set | frozenset):
        items = [_normalize(item) for item in value]
        if items and all(isinstance(item, dict) and "name" in item and "value" in item for item in items):
            items = _mask_code_provenance(items)
        return sorted(items, key=json.dumps) if isinstance(value, set | frozenset) else items
    if isinstance(value, bytes):
        return "sha256:" + hashlib.sha256(value).hexdigest()
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _pages(pages, requests=None):
    """Every page's outcome and resume state, and the provider requests in the order they were made."""
    output = [{"status": page.status, "records": page.records, "checkpoint": getattr(page, "checkpoint", None),
               "reasons": getattr(page, "reasons", None), "retry_after_seconds": getattr(page, "retry_after_seconds", None)}
              for page in pages]
    return output if requests is None else {"pages": output, "requests": requests}


def _request(request):
    """A request's method, host and path, with the query items sorted (no headers, no bodies)."""
    return [request.method, request.url.host, request.url.path, sorted(request.url.params.multi_items())]


# --- metadata scenarios ------------------------------------------------------------------


def _github(enterprise):
    from cremore_github_provider.metadata import adapter
    from cremore_github_provider.metadata.tests import fake
    spec = fake.enterprise_spec() if enterprise else fake.spec()
    responses = fake.enterprise_responses() if enterprise else fake.org_responses()
    client = fake.FakeTransport(responses, enterprise=fake.ENTERPRISE if enterprise else "")
    pages = list(adapter.collect_pages(spec, secrets=fake.SECRETS, checkpoint={}, check=lambda: None,
                                       transport=client, broker=fake.FakeBroker(),
                                       now=lambda: datetime(2026, 3, 5, tzinfo=UTC)))
    return _pages(pages, client.calls)


def _gcp(values):
    from types import SimpleNamespace

    from cremore_gcp_provider.metadata import adapter
    from cremore_gcp_provider.metadata.tests import fake

    class Results(list):
        complete = True

    class Engine:
        config = SimpleNamespace(fingerprint_key=b"k" * 32)

        def scan(self, item):
            return Results()

    spec = fake.spec(capabilities=["inventory", "vault_metadata", "issuer_value"] if values
                     else ["inventory", "vault_metadata"],
                     options={"locations": ["europe-west4"], "include_values": values})
    responses = fake.inventory_responses()
    responses[f"https://apikeys.googleapis.com/v2/{fake.API_KEY_NAME}/keyString"] = {"keyString": "synthetic-value-only"}
    context = ({"engine": Engine(), "key_id": "a" * 64, "engine_digest": "b" * 64, "policy_digest": "c" * 64}
               if values else None)
    transport = fake.FakeTransport(responses)
    pages = list(adapter.collect_pages(spec, secrets={}, checkpoint={}, check=lambda: None, transport=transport,
                                       now=datetime(2026, 9, 23, tzinfo=UTC), value_context=context))
    return _pages(pages, transport.calls)


def azure_key_vault_metadata():
    from cremore_azure_provider.metadata import adapter

    from cremore.coverage.metadata_models import MetadataConnectionSpec
    spec = MetadataConnectionSpec(name="offline", provider="azure_key_vault",
                                  origin="https://acme-prod.vault.azure.net", edition="cloud",
                                  scopes=[{"kind": "vault", "id": "acme-prod"}], capabilities=["vault_metadata"],
                                  auth_type="workload_identity")

    calls = []

    class Transport:
        requests = 0
        options = spec.options

        def get(self, path, params=None):
            calls.append([path, sorted((params or {}).items())])
            return ({"value": [{"id": spec.origin + "/secrets/example", "attributes": {"enabled": True}}]}
                    if path == "/secrets" else {"value": []})

    pages = list(adapter.collect_pages(spec, secrets={}, checkpoint={}, check=lambda: None, transport=Transport(),
                                       now=datetime(2026, 9, 26, tzinfo=UTC)))
    return _pages(pages, calls)


def _atlassian(mode):
    from unittest.mock import Mock

    from cremore_atlassian_provider.metadata import adapter
    from cremore_atlassian_provider.metadata.bitbucket import BitbucketClient
    from cremore_atlassian_provider.metadata.http import CloudClient

    from cremore.coverage.metadata_models import MetadataConnectionSpec

    class Response(io.BytesIO):
        code = status = 200
        headers: dict = {}  # noqa: RUF012 -- read-only stand-in for a response

        def __init__(self):
            super().__init__(json.dumps({"data": [], "values": [], "items": [], "links": {}}).encode())

        def getcode(self):
            return self.status

    cloud = mode in ("inventory", "discovery", "accounts")
    spec = MetadataConnectionSpec(
        name="offline", provider="atlassian" if cloud else "bitbucket",
        origin="https://api.atlassian.com" if cloud else "https://api.bitbucket.org",
        scopes=[{"kind": "organization" if cloud else "workspace",
                 "id": "00000000-0000-0000-0000-000000000009" if cloud else "example-workspace"}],
        capabilities=["inventory"], secret_refs={"token": "vault://synthetic/token"},
        options={"mode": mode, "max_retries": 0}, max_requests=200)
    opener, calls = Mock(), []
    opener.open.side_effect = lambda request, *a, **k: (calls.append(getattr(request, "full_url", str(request))),
                                                        Response())[1]

    def factory(config, scope, secrets, limits, check):
        return (CloudClient if cloud else BitbucketClient)(scope.id, secrets["token"], limits, opener=opener,
                                                           check=check)

    pages = list(adapter.collect_pages(spec, secrets={"token": "SYNTHETIC_OPERATOR_AUTH"}, checkpoint={},
                                       check=lambda: None, read_records=lambda: iter(()), client_factory=factory,
                                       now=lambda: "2026-09-24T00:00:00+00:00"))
    return _pages(pages, calls)


def azure_devops_tokens():
    import httpx
    from cremore_azure_provider.devops_tokens import adapter
    from cremore_azure_provider.devops_tokens import devops_tokens_test as fixtures
    devops = fixtures.DevOps({fixtures.ALICE: [fixtures.token("aaaaaaaa-0000-4000-8000-000000000001")],
                              fixtures.BOB: [fixtures.token("bbbbbbbb-0000-4000-8000-000000000002", valid=False)]})
    with httpx.Client(transport=httpx.MockTransport(devops)) as client:
        pages = list(adapter.collect_pages(fixtures.spec(), secrets={"token": fixtures.SECRET}, checkpoint=None,
                                           check=lambda: None, client=client, now=fixtures.NOW))
    return _pages(pages, [_request(request) for request in devops.calls])


def notion_metadata():
    from cremore_notion_provider.metadata.tests import test_adapter as fixtures
    pages, requests = fixtures.run([fixtures.payload(fixtures.pat(),
                                                     fixtures.pat(id="00000000-0000-4000-8000-000000000011",
                                                                  status="revoked"))])
    return _pages(pages, [_request(request) if hasattr(request, "url") else request for request in requests])


# --- content scenarios -------------------------------------------------------------------


def _objects(collector, requests=None):
    output = [{"resource": obj.resource, "data": obj.read()} for obj in collector.collect()] + [
        {"failed_objects": collector.failed_objects}]
    return output if requests is None else {"objects": output, "requests": requests}


def azure_devops_content():
    from cremore_azure_provider import devops_content
    from cremore_azure_provider import devops_content_test as fixtures
    handle, calls = fixtures.repository()
    output = _objects(devops_content.build(fixtures.payload(repository="api"), fixtures.http(handle)))
    return {"objects": output, "requests": [_request(request) for request in calls]}


def gitlab_content():
    import httpx
    from cremore_gitlab_provider import content

    calls = []

    def answer(request):
        calls.append(_request(request))
        route = request.url.path
        if route.endswith("/projects/7"):
            return httpx.Response(200, json={"path_with_namespace": "team/example"})
        if "/commits/" in route:
            return httpx.Response(200, json={"id": "a" * 40})
        if route.endswith("/repository/tree"):
            return httpx.Response(200, json=[{"type": "blob", "path": "src/example.txt", "id": "b" * 40},
                                             {"type": "blob", "path": "src/config.env", "id": "c" * 40}])
        if route.endswith("/raw"):
            return httpx.Response(200, content=b"Synthetic example content " + route.encode())
        raise AssertionError(route)

    payload = {"base_url": "https://gitlab.example.test", "project": "7", "token": "synthetic", "paths": ["src"]}
    with httpx.Client(transport=httpx.MockTransport(answer), trust_env=False) as client:
        return _objects(content.build(payload, client), calls)


SCENARIOS = {
    "github.metadata.org": lambda: _github(False),
    "github.metadata.enterprise": lambda: _github(True),
    "gcp.metadata.inventory": lambda: _gcp(False),
    "gcp.metadata.values": lambda: _gcp(True),
    "azure.key_vault.metadata": azure_key_vault_metadata,
    **{f"atlassian.metadata.{mode}": (lambda mode=mode: _atlassian(mode))
       for mode in ("inventory", "discovery", "accounts", "bitbucket", "runners", "branch_restrictions")},
    "azure.devops_tokens.metadata": azure_devops_tokens,
    "notion.metadata": notion_metadata,
    "azure.devops.content": azure_devops_content,
    "gitlab.content": gitlab_content,
}


def _digest(output):
    return hashlib.sha256(json.dumps(_normalize(output), sort_keys=True, default=str).encode()).hexdigest()


def run(name, repeat):
    scenario = SCENARIOS[name]
    try:
        first = scenario()  # warm-up; imports are measured separately by bench_imports.py
    except Exception as exc:  # noqa: BLE001 -- a broken scenario is reported, not fatal
        return {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}
    digests, samples = [_digest(first)], []
    for _ in range(repeat):
        start = time.perf_counter()
        again = scenario()
        samples.append(time.perf_counter() - start)
        digests.append(_digest(again))  # hashed outside the timed interval
    pages = first.get("pages") or first.get("objects") if isinstance(first, dict) else first
    records = sum(len(page.get("records", [])) for page in pages if isinstance(page, dict))
    requests = len(first.get("requests") or []) if isinstance(first, dict) else None
    return {"median_ms": round(statistics.median(samples) * 1000, 3), "min_ms": round(min(samples) * 1000, 3),
            "digest": digests[0], "stable": len(set(digests)) == 1, "distinct_digests": len(set(digests)),
            "items": records or len(pages), "requests": requests}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--repeat", type=int, default=15)
    parser.add_argument("--output", type=Path)
    parser.add_argument("scenarios", nargs="*")
    args = parser.parse_args()
    root = args.root.resolve()
    # The tree under test must shadow any installed copy of the same packages.
    sys.path[:0] = [str(root)] + [str(root / path) for path in VENDOR_PATHS]
    import cremore
    report = {"root": str(root), "cremore": str(Path(cremore.__file__).resolve()), "repeat": args.repeat,
              "python": sys.version.split()[0], "scenarios": {}}
    for name in args.scenarios or SCENARIOS:
        row = report["scenarios"][name] = run(name, args.repeat)
        print(f"{name:40s} " + (f"{row['median_ms']:9.2f} ms  items={row['items']:4d}  stable={row['stable']}  "
                                f"digest={row['digest'][:12]}" if "error" not in row else "ERROR " + row["error"]),
              flush=True)
    if args.output:
        args.output.write_text(json.dumps(report, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
