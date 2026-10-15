"""Shared bounded HTTP and collection lifecycle; providers own API operations."""
from __future__ import annotations

from cremore.collectors.base import (
    CollectedObject,
    CollectorError,
    RequestBudget,
    run_on_owner,
    run_stop,
)
from cremore.detection import ResourceRef
from cremore.http_client import HTTPResponseTooLarge, bounded_request

# The pure helper, not the cremore.source_config compatibility module: that one
# imports the content registry and with it every provider's source module.
from cremore.sources.validation import path


class ContentHTTP:
    # A change feed polled on the worker's control loop sets base.NO_WAIT here: a rate limit or a busy
    # server then ends its request at once (SOURCE_RATE_LIMITED, SOURCE_UNAVAILABLE) instead of being
    # slept on. Scans keep None.
    pacer = None

    def __init__(self, payload, client, *, budget=None, max_bytes=50 << 20):
        self.payload, self.client = payload, client
        self.budget = budget or RequestBudget(payload.get("max_requests", 10000))
        self.max_bytes = max_bytes
        self.token = payload.get("token", "")

    def authorization(self, token):
        return "Bearer " + token

    def get(self, route, *, params=None, raw=False, max_bytes=None, headers=None):
        token = self.token() if callable(self.token) else self.token
        if not token:
            raise CollectorError("NO_CREDENTIAL")
        authorization = self.authorization(token)
        try:
            response = bounded_request(self.client, "GET", self.base + route, params=params,
                headers={**(headers or {}), "Authorization": authorization}, follow_redirects=False, retry_429=True,
                before_attempt=self.budget.consume, max_response_bytes=max_bytes or (self.max_bytes if raw else 8 << 20),
                pacer=self.pacer)
        except CollectorError:
            raise
        except HTTPResponseTooLarge:
            raise CollectorError("SOURCE_RESPONSE_TOO_LARGE") from None
        except Exception:  # noqa: BLE001 -- Untrusted provider failures must become bounded safe collection failures.
            raise CollectorError("SOURCE_REQUEST_FAILED") from None
        if response.status_code != 200:
            raise CollectorError("SOURCE_HTTP_FAILED", str(response.status_code))
        if raw:
            return response.content
        try:
            return response.json(), response.headers
        except (TypeError, ValueError):
            raise CollectorError("SOURCE_RESPONSE_MALFORMED") from None


class ContentCollector:
    LITERAL_PATHS = False
    # Lazy reads overlap on the scan's read-ahead threads; listing stays on the owner.
    read_concurrency = 8
    counts_read_failures = True

    @property
    def request_budget(self):
        return self.http.budget

    @request_budget.setter
    def request_budget(self, value):
        self.http.budget = value

    @property
    def max_object_bytes(self):
        return self.http.max_bytes

    @max_object_bytes.setter
    def max_object_bytes(self, value):
        # The worker shrinks this to what the byte budget has left: a larger object then
        # fails alone, as S3's do, instead of stopping the root at it on every run.
        self.http.max_bytes = value

    def path_comparison(self, value):
        return value

    def __init__(self, payload, client, *, request_budget=None, max_object_bytes=50 << 20):
        self.provider, self.p = self.PROVIDER, payload
        self.http = self.HTTP(payload, client, budget=request_budget, max_bytes=max_object_bytes)
        self.failed_objects = 0
        self.authoritative_listing = True
        self.listing_complete = False
        self.listed_paths = set()
        self.max_objects = payload.get("max_objects", 50000)
        self._count = 0

    def selected(self, key):
        key = self.path_comparison(path(key, literal=self.LITERAL_PATHS))
        exact = self.p.get("exact_keys" if self.LITERAL_PATHS else "exact_paths")
        if exact is not None and key not in map(self.path_comparison, exact):
            return False
        def under(prefix):
            prefix = self.path_comparison(prefix)
            return key.startswith(prefix) if self.LITERAL_PATHS else not prefix or key == prefix.rstrip("/") or key.startswith(prefix.rstrip("/") + "/")
        for scope in (self.p, self.p.get("_connection_scope") or {}):
            include = scope.get("prefixes" if self.LITERAL_PATHS else "paths") or []
            exclude = scope.get("excluded_prefixes" if self.LITERAL_PATHS else "excluded_paths") or []
            if include and not any(under(p) for p in include) or any(under(p) for p in exclude):
                return False
        return True

    def listed(self, key):
        if self._count >= self.max_objects:
            raise CollectorError("SOURCE_OBJECT_LIMIT")
        self._count += 1
        self.listed_paths.add(key)

    def object(self, name, key, version, load, *, revision=None, **metadata):
        """One listed object. With a ``revision`` (a git blob id, a GCS generation, a blob
        ETag) a worker scan (``_lazy``, as GitHub's) defers the read: the scan reuses the
        result it already has for that revision and never downloads it; only a new or
        changed object is read."""
        if key not in self.listed_paths:
            self.listed(key)
        metadata.update(self.resource_metadata())
        resource = ResourceRef(source_type=self.provider, resource=name, location=key, version_id=str(version),
                               revision=str(revision or ""), metadata={"exposure": "unknown", **metadata})
        if revision and self.p.get("_lazy"):
            def deferred():
                try:
                    data = load()
                except CollectorError as exc:
                    if run_stop(exc):
                        raise
                    data = None
                if data is None:
                    # Provider listing code counts on the owner thread without a lock,
                    # so a read-ahead thread's count is made there too.
                    run_on_owner(self._read_failed)
                    return None
                resource.size = len(data)
                return data
            return CollectedObject(resource, None, loader=deferred)
        try:
            data = load()
        except CollectorError as exc:
            if run_stop(exc):
                raise
            data = None
        if data is None:
            self.failed_objects += 1
            return CollectedObject(resource, None, complete=False, failure_counted=True)
        resource.size = len(data)
        return CollectedObject(resource, data)

    def _read_failed(self):
        self.failed_objects += 1

    def resource_metadata(self):
        return {}

    def collect(self):
        try:
            yield from self.objects()
            self.listing_complete = True
        except CollectorError:
            self.authoritative_listing = False
            raise
        except Exception:  # noqa: BLE001 -- Untrusted provider failures must become bounded safe collection failures.
            self.authoritative_listing = False
            raise CollectorError("SOURCE_COLLECTION_MALFORMED") from None

    @classmethod
    def root_payload(cls, payload, identifier):
        return {**payload, cls.ROOT_FIELD: identifier}


def build_roots(collector, roots, payload, client, *, request_budget=None, max_object_bytes=50 << 20):
    from cremore.collectors.scoped import ScopedCollector
    budget = request_budget or RequestBudget(payload.get("max_requests", 10000))
    if payload.get(collector.ROOT_FIELD):
        return collector(payload, client, request_budget=budget, max_object_bytes=max_object_bytes)
    parts = []
    for _, identifier, _ in roots(payload, client, budget):
        if len(parts) >= payload.get("max_objects", 50000):
            raise CollectorError("SOURCE_ROOT_LIMIT")
        parts.append(collector(collector.root_payload(payload, identifier), client,
            request_budget=budget, max_object_bytes=max_object_bytes))
    return ScopedCollector(parts)
