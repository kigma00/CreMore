import uuid

from cremore.scanning.catalog import list_resources


def test_s3_bucket_catalog_follows_provider_pagination_past_five_thousand_roots():
    class Client:
        def __init__(self):
            self.calls = 0

        def list_buckets(self, **kwargs):
            self.calls += 1
            assert kwargs["MaxBuckets"] == 1000
            page = int(kwargs.get("ContinuationToken", "0"))
            result = {"Buckets": [{"Name": f"bucket-{page}-{i}"} for i in range(1000)]}
            if page < 5:
                result["ContinuationToken"] = str(page + 1)
            return result
    client = Client()
    items, complete = list_resources({"provider": "aws", "connection_kind": "aws", "connection_id": str(uuid.uuid4())},
                                     s3_client=lambda: client)
    assert len(items) == 6000 and complete == "COMPLETE" and client.calls == 6


def test_notion_missing_search_cursor_is_partial_not_complete():
    class Response:
        status_code = 200
        def json(self):
            return {"results": [], "has_more": True}
    class Client:
        def post(self, *_args, **_kwargs):
            return Response()
    items, complete = list_resources({"provider": "notion", "connection_kind": "source", "connection_id": str(uuid.uuid4())},
                                     http_client=lambda: Client())
    assert items == [] and complete == "PARTIAL"
