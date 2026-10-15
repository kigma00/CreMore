"""gcp content API operations; shared lifecycle stays in the platform."""
from __future__ import annotations

from urllib.parse import quote

from cremore.collectors.base import CollectorError, CursorHistory
from cremore.collectors.content import ContentCollector, ContentHTTP, build_roots
from cremore_gcp_provider.gcp_auth import adc_token

# Objects per listing page (the API's maximum), each reduced to the fields the scan reads so a
# page of objects with large custom metadata stays far below the response limit.
OBJECT_PAGE = 1000
OBJECT_FIELDS = "nextPageToken,items(name,bucket,generation,size)"


class SourceHTTP(ContentHTTP):
    def __init__(self, payload, client, **kwargs):
        super().__init__(payload, client, **kwargs)
        self.base = "https://storage.googleapis.com/storage/v1"
        self.token = payload.get("token") or adc_token()
        self._cursors = CursorHistory()

    def gcs_pages(self, route, field, params=None):
        token, seen = "", self._cursors.fork()
        while True:
            body, _ = self.get(route, params={"maxResults": 100, **(params or {}), "pageToken": token})
            if not isinstance(body, dict) or not isinstance(body.get(field, []), list):
                raise CollectorError("SOURCE_LIST_MALFORMED")
            yield from body.get(field, [])
            token = body.get("nextPageToken")
            if not token:
                return
            seen.add(token)


def roots(payload, client, budget=None):
    """Discovery does not approve content reads."""
    http = SourceHTTP(payload, client, budget=budget)
    if payload.get("bucket"):
        row, _ = http.get("/b/" + quote(payload["bucket"], safe=""), params={"projection": "noAcl"})
        if row.get("name") != payload["bucket"]:
            raise CollectorError("GCS_BUCKET_MISMATCH")
        yield "GCS_BUCKET", row["name"], row["name"]
    else:
        for row in http.gcs_pages("/b", "items", {"project": payload["project"], "projection": "noAcl"}):
            yield "GCS_BUCKET", row["name"], row["name"]


class Collector(ContentCollector):
    PROVIDER = "gcp"
    ROOT_FIELD = "bucket"
    HTTP = SourceHTTP
    LITERAL_PATHS = True

    def objects(self):
        bucket = self.p["bucket"]
        route = "/b/" + quote(bucket, safe="") + "/o"
        prefixes = self.p.get("prefixes") or [""]
        seen = set()
        def records():
            for prefix in prefixes:
                yield from self.http.gcs_pages(route, "items", {"prefix": prefix, "maxResults": OBJECT_PAGE,
                                                                "fields": OBJECT_FIELDS})
        for row in records():
            key = row["name"]
            if key in seen:
                continue
            if len(seen) >= self.max_objects:
                raise CollectorError("SOURCE_OBJECT_LIMIT")
            seen.add(key)
            if not self.selected(key):
                continue
            generation = str(row["generation"])
            if not generation.isdigit() or row.get("bucket", bucket) != bucket:
                raise CollectorError("GCS_OBJECT_MISMATCH")
            self.listed(key)
            if int(row.get("size", 0)) > self.http.max_bytes:
                self.failed_objects += 1
                continue
            yield self.object(bucket, key, generation, lambda key=key, generation=generation: self.http.get(route + "/" + quote(key, safe=""), raw=True,
                params={"alt": "media", "generation": generation, "ifGenerationMatch": generation}), revision=generation)

    gcs = objects


def build(payload, client, **kwargs):
    return build_roots(Collector, roots, payload, client, **kwargs)
