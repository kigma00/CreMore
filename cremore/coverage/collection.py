"""Shared budgets, observations and hashing for provider inventory reads."""
from __future__ import annotations

import json
from datetime import datetime

from cremore.coverage.hasher import hash_value
from cremore.coverage.models import ConnectionSpec, Observation, in_scope


class CollectionLimit(ValueError):
    pass


class Collection:
    def __init__(self, spec: ConnectionSpec, *, checkpoint=None):
        self.spec = spec
        self.items: list[Observation] = []
        self.reasons: set[str] = set()
        self.requests = 0
        self.checkpoint = checkpoint or (lambda: None)

    def charge(self):
        self.checkpoint()
        if self.requests >= self.spec.max_requests:
            raise CollectionLimit("REQUEST_LIMIT")
        self.requests += 1

    def call(self, fn, **kwargs):
        self.charge()
        return fn(**kwargs)

    def add(self, item):
        if len(self.items) >= self.spec.max_records:
            raise CollectionLimit("RECORD_LIMIT")
        if not in_scope(self.spec, item):
            self.reasons.add("PROVIDER_SCOPE_MISMATCH")
            return
        self.items.append(item)
        if item.evidence == "UNRESOLVED":
            self.reasons.add(item.reason)

    def unresolved(self, location, reason):
        self.reasons.add(reason)
        self.add(Observation(**location, evidence="UNRESOLVED", reason=reason))

    def value(self, engine, value, location):
        if not isinstance(value, bytes):
            value = value.encode() if isinstance(value, str) else json.dumps(value, ensure_ascii=False).encode()
        for item in hash_value(engine, value, location, max_bytes=self.spec.max_value_bytes):
            self.add(item)

    @property
    def status(self):
        data = any(item.evidence != "OPERATION" for item in self.items)
        return ("PARTIAL" if data else "FAILED") if self.reasons else "COMPLETE"

    def pages(self, fn, field, *, token_in="Marker", token_out="Marker", **kwargs):
        seen = set()
        while True:
            response = self.call(fn, **kwargs)
            yield from response.get(field, [])
            token = response.get(token_out)
            if not token:
                if response.get("IsTruncated"):
                    raise CollectionLimit("PAGINATION_INCOMPLETE")
                return
            if token in seen:
                raise CollectionLimit("PAGINATION_LOOP")
            seen.add(token)
            kwargs[token_in] = token


def iso(value):
    return value.isoformat() if isinstance(value, datetime) else value or ""
