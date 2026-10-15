"""Cloud Storage lists 1000 objects per page, each reduced to the fields the scan reads."""

import httpx

from cremore_gcp_provider.content import OBJECT_FIELDS, OBJECT_PAGE, Collector, roots


class Bucket:
    def __init__(self, count):
        self.names = [f"data/{i:05d}.txt" for i in range(count)]
        self.listings = []

    def handle(self, request):
        params = request.url.params
        if request.url.path == "/storage/v1/b/synthetic/o":
            self.listings.append(dict(params))
            size = int(params["maxResults"])
            start = int(params.get("pageToken") or 0)
            rows = [{"name": name, "bucket": "synthetic", "generation": "7", "size": "12"}
                    for name in self.names[start:start + size]]
            more = {"nextPageToken": str(start + size)} if start + size < len(self.names) else {}
            return httpx.Response(200, json={"items": rows, **more})
        if request.url.path == "/storage/v1/b":
            self.listings.append(dict(params))
            return httpx.Response(200, json={"items": [{"name": "synthetic"}]})
        raise AssertionError(request.url)

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self.handle))


def test_objects_are_listed_a_thousand_per_page_with_only_the_fields_read():
    bucket = Bucket(2500)
    collector = Collector({"bucket": "synthetic", "token": "synthetic", "_lazy": True}, bucket.client())
    objects = list(collector.collect())
    assert [obj.resource.location for obj in objects] == bucket.names and collector.listing_complete
    assert all(obj.resource.revision == "7" and obj.data is None for obj in objects)  # nothing downloaded
    assert OBJECT_PAGE == 1000
    assert [(page["maxResults"], page["fields"]) for page in bucket.listings] == [("1000", OBJECT_FIELDS)] * 3
    assert [page["pageToken"] for page in bucket.listings] == ["", "1000", "2000"]
    # 2,500 objects take 3 listing requests; at 100 per page they took 25.


def test_each_approved_prefix_is_listed_at_the_same_page_size():
    bucket = Bucket(10)
    collector = Collector({"bucket": "synthetic", "token": "synthetic", "_lazy": True, "prefixes": ["data/0000", "logs/"]},
                          bucket.client())
    assert len(list(collector.collect())) == 10
    assert [(page["prefix"], page["maxResults"]) for page in bucket.listings] == [("data/0000", "1000"), ("logs/", "1000")]


def test_project_bucket_discovery_keeps_its_page_size():
    bucket = Bucket(0)
    assert [row[1] for row in roots({"project": "demo-project", "token": "synthetic"}, bucket.client())] == ["synthetic"]
    assert bucket.listings[0]["maxResults"] == "100" and "fields" not in bucket.listings[0]
