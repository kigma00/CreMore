"""Azure Blob Storage content API operations; shared lifecycle stays in the platform."""
from __future__ import annotations

import re
from urllib.parse import quote
from xml.etree import ElementTree

from cremore.collectors.base import CollectorError, CursorHistory
from cremore.collectors.content import ContentCollector, ContentHTTP, build_roots

# Bearer (Entra ID) authorization needs x-ms-version 2017-11-09 or later.
VERSION = "2023-11-03"
SCOPE = "https://storage.azure.com/.default"
ACCOUNT = re.compile(r"[a-z0-9]{3,24}")
CONTAINER = re.compile(r"\$(?:root|web|logs)|[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){2,62}")


class SourceHTTP(ContentHTTP):
    def __init__(self, payload, client, **kwargs):
        super().__init__(payload, client, **kwargs)
        self.base = "https://" + payload["account"] + ".blob.core.windows.net"
        self._cursors = CursorHistory()
        if not self.token:
            # The worker's own Azure identity (workload identity, managed identity, CLI).
            from cremore_azure_provider.metadata.transport import default_token
            self.token = default_token(SCOPE)

    def get(self, route, *, headers=None, **kwargs):
        return super().get(route, headers={"x-ms-version": VERSION, **(headers or {})}, **kwargs)

    def pages(self, route, tag, params=None):
        """An XML listing, following NextMarker exactly as the service returns it."""
        marker, seen = "", self._cursors.fork()
        while True:
            raw = self.get(route, params={**(params or {}), "comp": "list", "maxresults": 1000,
                                          **({"marker": marker} if marker else {})}, raw=True, max_bytes=8 << 20)
            try:
                root = ElementTree.fromstring(raw)
            except ElementTree.ParseError:
                raise CollectorError("SOURCE_LIST_MALFORMED") from None
            items = root.find(tag + "s")
            if root.tag != "EnumerationResults" or items is None:
                raise CollectorError("SOURCE_LIST_MALFORMED")
            yield from items.findall(tag)
            marker = root.findtext("NextMarker") or ""
            if not marker:
                return
            seen.add(marker)


def roots(payload, client, budget=None):
    """Discovery does not approve content reads."""
    http = SourceHTTP(payload, client, budget=budget)
    account = payload["account"]
    if payload.get("container"):
        # Get Container Properties: proves the container exists and is readable by this identity.
        http.get("/" + quote(payload["container"], safe="$"), params={"restype": "container"}, raw=True, max_bytes=1 << 16)
        names = [payload["container"]]
    else:
        names = (row.findtext("Name") or "" for row in http.pages("/", "Container"))
    for name in names:
        if not CONTAINER.fullmatch(name):
            raise CollectorError("AZURE_BLOB_CONTAINER_MALFORMED")
        yield "AZURE_BLOB_CONTAINER", account + "/" + name, account + "/" + name


class Collector(ContentCollector):
    PROVIDER = "azure_blob"
    ROOT_FIELD = "container"
    HTTP = SourceHTTP
    LITERAL_PATHS = True

    @classmethod
    def root_payload(cls, payload, identifier):
        return {**payload, cls.ROOT_FIELD: identifier.split("/", 1)[1]}

    def objects(self):
        account, container = self.p["account"], self.p["container"]
        resource = account + "/" + container
        route = "/" + quote(container, safe="$")
        seen = set()
        for prefix in self.p.get("prefixes") or [""]:
            # Current blobs only; snapshots and older versions are not listed.
            for row in self.http.pages(route, "Blob", {"restype": "container", "prefix": prefix}):
                key = row.findtext("Name") or ""
                if key in seen:
                    continue
                if len(seen) >= self.max_objects:
                    raise CollectorError("SOURCE_OBJECT_LIMIT")
                seen.add(key)
                if not key or not self.selected(key):
                    continue
                etag, size = row.findtext("Properties/Etag"), row.findtext("Properties/Content-Length")
                if not etag or not size or not size.isdigit():
                    raise CollectorError("AZURE_BLOB_MALFORMED")
                self.listed(key)
                if int(size) > self.http.max_bytes:
                    self.failed_objects += 1
                    continue
                # If-Match pins the read to the listed version; a changed blob fails instead of drifting.
                yield self.object(resource, key, etag.strip('"'), lambda key=key, etag=etag: self.http.get(
                    route + "/" + quote(key, safe="/"), raw=True, headers={"If-Match": etag}), revision=etag.strip('"'))

    azure_blob = objects


def build(payload, client, **kwargs):
    return build_roots(Collector, roots, payload, client, **kwargs)
