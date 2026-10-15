"""Exercise each real public factory's scope and retirement-state obligations.

No shared collector is constructed directly here: owner replacements must pass
these cases through the same build_collector entrypoint used by the Worker.

Ported from refactor/saas-libraries (cremore/worker/content_contract_test.py) in the
review of the SaaS-structure integration, 2026-09-26: the base ContentCollector.object()
does not apply the approved scope itself, so every provider must call selected() before
reading. The Azure Blob and Azure DevOps collectors, which that branch did not have, are
added to the same matrix; before this, no test failed if Azure Blob skipped the scope.
"""

import base64
from urllib.parse import unquote

import httpx
import pytest
from cremore_azure_provider import blob_source, devops_source

from cremore.collectors.base import CollectorError
from cremore.domain.models import ScanJob
from cremore.worker.factory import build_collector

LITERAL_PATH_PROVIDERS = ("gcp", "azure_blob")  # object stores scope by key prefix, not path


class ContentAPI:
    """Small offline provider with in-scope and out-of-scope content to distinguish."""

    def __init__(self, provider):
        self.provider = provider
        self.options, self.resource_type, self.identifier = {
            "gitlab": ({"project": "7", "base_url": "https://gitlab.example.test"},
                       "GITLAB_REPOSITORY", "7"),
            "gcp": ({"bucket": "synthetic-bucket"}, "GCS_BUCKET", "synthetic-bucket"),
            "confluence": ({"page_id": "123", "space": "99", "edition": "cloud",
                            "base_url": "https://synthetic.atlassian.net/wiki"},
                           "CONFLUENCE_PAGE", "123"),
            "bitbucket": ({"workspace": "team", "repo": "repo", "edition": "cloud",
                           "base_url": "https://api.bitbucket.org"},
                          "BITBUCKET_REPOSITORY", "team/repo"),
            "azure_blob": (blob_source.job_payload({"account": "synthacct", "container": "data"}),
                           "AZURE_BLOB_CONTAINER", "synthacct/data"),
            "azure_devops": (devops_source.job_payload({"organization": "acme", "project": "Platform",
                                                        "repository": "api"}),
                             "AZURE_DEVOPS_REPOSITORY", "acme/Platform/api"),
        }[provider]
        self.keys = (["attachments/1", "attachments/2", "body"] if provider == "confluence"
                     else ["allowed/keep.txt", "allowed/other.txt", "blocked/secret.txt"])
        self.blobs = {f"{i + 1:040x}": key for i, key in enumerate(self.keys)}
        self.prefix = "attachments" if provider == "confluence" else "allowed"
        literal = provider in LITERAL_PATH_PROVIDERS
        self.include = "prefixes" if literal else "paths"
        self.exclude = "excluded_prefixes" if literal else "excluded_paths"
        self.exact = "exact_keys" if literal else "exact_paths"
        self.reads = []
        self.failure = None

    def content(self, key):
        """Record actual content reads, not metadata/list requests or emitted objects."""
        self.reads.append(key)
        if self.failure == "read" and key == self.keys[0]:
            return httpx.Response(403)
        data = b"x" * 64 if self.failure == "size" and key == self.keys[0] else b"ok"
        return httpx.Response(200, content=data)

    def listing(self, value):
        """A failed listing must not masquerade as a successful empty inventory."""
        return httpx.Response(403) if self.failure == "list" else httpx.Response(200, json=value)

    def handle(self, request):
        """Serve only declared synthetic routes; unexpected HTTP requests fail closed."""
        expected = ("Basic " + base64.b64encode(b":synthetic-scanner").decode() if self.provider == "azure_devops"
                    else "Bearer synthetic-scanner")
        assert request.headers["Authorization"] == expected
        route = request.url.path
        if self.provider == "gitlab":
            if route.endswith("/projects/7"):
                return httpx.Response(200, json={"id": 7, "path_with_namespace": "org/project"})
            if "/commits/" in route:
                return httpx.Response(200, json={"id": "a" * 40})
            if route.endswith("/repository/tree"):
                return self.listing([{"type": "blob", "path": key, "id": blob}
                                     for blob, key in self.blobs.items()])
            if route.endswith("/raw"):
                return self.content(self.blobs[route.split("/")[-2]])
        elif self.provider == "gcp":
            prefix = "/storage/v1/b/synthetic-bucket/o"
            if route == prefix:
                # Include all fixture rows even with a prefix query: verify that
                # the returned collector itself enforces the platform's scope.
                return self.listing({"items": [
                    {"name": key, "generation": "7",
                     "size": "64" if self.failure == "size" and key == self.keys[0] else "2"}
                    for key in self.keys]})
            if route.startswith(prefix + "/"):
                assert request.url.params["generation"] == "7"
                assert request.url.params["ifGenerationMatch"] == "7"
                return self.content(route.removeprefix(prefix + "/"))
        elif self.provider == "bitbucket":
            prefix = "/2.0/repositories/team/repo"
            if route == prefix:
                return httpx.Response(200, json={"mainbranch": {"name": "main"}})
            if "/commit/" in route:
                return httpx.Response(200, json={"hash": "a" * 40})
            tree = prefix + "/src/" + "a" * 40 + "/"
            if route == tree:
                return self.listing({"values": [{"type": "commit_file", "path": key}
                                                for key in self.keys]})
            if route.startswith(tree):
                return self.content(route.removeprefix(tree))
        elif self.provider == "azure_blob":
            assert request.url.host == "synthacct.blob.core.windows.net"
            if request.url.params.get("comp") == "list":
                assert route == "/data" and request.url.params["restype"] == "container"
                if self.failure == "list":
                    return httpx.Response(403)
                # Every fixture blob is returned even for a prefix query: the collector must scope.
                rows = "".join(
                    f"<Blob><Name>{key}</Name><Properties><Etag>&quot;0x{index}&quot;</Etag>"
                    f"<Content-Length>{64 if self.failure == 'size' and key == self.keys[0] else 2}"
                    "</Content-Length></Properties></Blob>" for index, key in enumerate(self.keys))
                return httpx.Response(200, content=("<?xml version=\"1.0\" encoding=\"utf-8\"?><EnumerationResults>"
                                                    f"<Blobs>{rows}</Blobs><NextMarker></NextMarker>"
                                                    "</EnumerationResults>").encode())
            assert request.headers["If-Match"].startswith('"0x')
            return self.content(unquote(route.removeprefix("/data/")))
        elif self.provider == "azure_devops":
            assert request.url.host == "dev.azure.com" and request.url.params["api-version"] == "7.1"
            repo = "/acme/Platform/_apis/git/repositories/api"
            if route == repo:
                return httpx.Response(200, json={"name": "api", "defaultBranch": "refs/heads/main"})
            if route == repo + "/refs":
                return httpx.Response(200, json={"value": [{"name": "refs/heads/main", "objectId": "a" * 40}]})
            if route == repo + "/items":
                assert request.url.params["recursionLevel"] == "Full"
                return self.listing({"value": [{"path": "/" + key, "gitObjectType": "blob", "objectId": blob}
                                               for blob, key in self.blobs.items()]})
            if route.startswith(repo + "/blobs/"):
                return self.content(self.blobs[route.rsplit("/", 1)[1]])
        else:
            if route == "/wiki/api/v2/pages/123":
                body = {"id": "123", "spaceId": "99", "version": {"number": 2}}
                # An excluded page body must not even be requested alongside metadata.
                if request.url.params.get("body-format") == "storage":
                    self.reads.append("body")
                    body["body"] = {"storage": {"value": "ok"}}
                return httpx.Response(200, json=body)
            if route.endswith("/pages/123/attachments"):
                return self.listing({"results": [
                    {"id": str(i), "downloadLink": f"/download/attachments/123/{i}"} for i in (1, 2)]})
            if route.startswith("/wiki/rest/api/content/123/child/attachment/") and route.endswith("/download"):
                # The REST download redirects; a same-site Location keeps the token (this fake checks it).
                return httpx.Response(302, headers={"location": "/wiki/files/" + route.split("/")[-2]})
            if route.startswith("/wiki/files/"):
                return self.content("attachments/" + route.rsplit("/", 1)[1])
        raise AssertionError(f"Unexpected synthetic route: {route}")

    def build(self, client, *, scoped=True, root_scope=None, connection_scope=None, **limits):
        """Construct real ordinary/scoped jobs; public owner factories stay unpatched."""
        payload = {"token": "synthetic-scanner", **self.options, **(connection_scope or {})}
        payload.update(limits)
        if scoped:
            payload["roots"] = [{"resource_type": self.resource_type,
                                 "provider_resource_id": self.identifier,
                                 "all_current_objects": False, **(root_scope or {})}]
        else:
            payload.update(root_scope or {})
        return build_collector(ScanJob(kind="scope" if scoped else self.provider, payload=payload),
                               http_client_factory=lambda: client,
                               max_object_bytes=8 if self.failure == "size" else 1024)


@pytest.fixture(params=["gitlab", "gcp", "confluence", "bitbucket", "azure_blob", "azure_devops"])
def api(request):
    """Every owner is held to the same behavior through its public entrypoint."""
    return ContentAPI(request.param)


@pytest.mark.parametrize("restriction", ["include", "exclude", "exact", "empty_exact", "intersection"])
def test_public_factory_enforces_approved_root_scope_before_content_reads(api, restriction):
    """Forwarded root restrictions must affect both output and actual HTTP reads."""
    keep, other, outside = api.keys
    connection_scope = {}
    if restriction == "include":
        root_scope, expected = {api.include: [api.prefix]}, {keep, other}
    elif restriction == "exclude":
        root_scope, expected = {api.exclude: [other]}, {keep, outside}
    elif restriction == "exact":
        root_scope, expected = {api.exact: [keep]}, {keep}
    elif restriction == "empty_exact":
        root_scope, expected = {api.exact: []}, set()
    else:
        # A broad root is still constrained by the connection include/exclude set.
        root_scope, expected = {api.include: [""]}, {keep}
        connection_scope = {api.include: [api.prefix], api.exclude: [other]}
    with httpx.Client(transport=httpx.MockTransport(api.handle)) as client:
        collector = api.build(client, root_scope=root_scope, connection_scope=connection_scope)
        objects = list(collector.collect())
    assert {obj.resource.location for obj in objects} == expected
    assert set(api.reads) == expected
    assert len(api.reads) == len(expected)
    part = collector.parts[0]
    assert part.listing_complete is True and part.listed_paths == expected
    assert part.failed_objects == 0
    assert collector.authoritative_listing is False  # Approved roots are not a whole connection.


@pytest.mark.parametrize("scoped", [False, True], ids=["ordinary", "approved-root"])
@pytest.mark.parametrize("failure", [None, "read", "size", "list", "limit"],
                         ids=["complete", "read-failure", "oversized", "listing-failure", "object-limit"])
def test_public_factory_preserves_listing_state_and_object_limit(api, scoped, failure):
    """Incomplete reads retain inventory presence; incomplete listings cannot retire it."""
    api.failure = failure
    with httpx.Client(transport=httpx.MockTransport(api.handle)) as client:
        collector = api.build(client, scoped=scoped, max_objects=1 if failure == "limit" else 10)
        part = collector.parts[0] if scoped else collector
        assert part.listing_complete is False and part.listed_paths == set()
        if failure in ("list", "limit"):
            code = "SOURCE_HTTP_FAILED" if failure == "list" else "SOURCE_OBJECT_LIMIT"
            with pytest.raises(CollectorError, match=code):
                list(collector.collect())
            assert part.listing_complete is False and part.authoritative_listing is False
            if failure == "limit":
                assert len(part.listed_paths) == 1
                assert len(api.reads) == 1
        else:
            objects = list(collector.collect())
            assert part.listing_complete is True
            assert part.listed_paths == set(api.keys)
            assert part.authoritative_listing is True
            assert part.failed_objects == (0 if failure is None else 1)
            # The failed/oversized object still exists. It must stay listed even
            # if there is no readable object for the scanner to consume.
            readable = {obj.resource.location for obj in objects if obj.data is not None}
            assert readable == set(api.keys) - ({api.keys[0]} if failure else set())
        if scoped:
            assert collector.authoritative_listing is False
