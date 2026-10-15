import httpx
import pytest

from cremore.collectors import base
from cremore.collectors.base import CollectorError
from cremore_gcp_provider.content import Collector, SourceHTTP


@pytest.mark.parametrize("cursor,code", [("x" * 17, "SOURCE_CURSOR_LIMIT"), ({"bad": True}, "SOURCE_CURSOR_INVALID")])
def test_gcs_rejects_invalid_cursors_before_sending_another_request(monkeypatch, cursor, code):
    monkeypatch.setattr(base, "MAX_CURSOR_BYTES", 16)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"items": [], "nextPageToken": cursor})

    collector = Collector({"bucket": "synthetic", "token": "synthetic"},
                          httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(CollectorError) as caught:
        list(collector.collect())
    assert str(caught.value) == code
    assert len(calls) == 1 and not collector.listing_complete


def test_gcs_detects_cycles_and_caps_cursor_admissions_across_prefixes(monkeypatch):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"items": [], **(
            {} if request.url.params.get("pageToken") else {"nextPageToken": "same"})})

    monkeypatch.setattr(base, "MAX_CURSOR_HISTORY", 1)
    source = SourceHTTP({"token": "synthetic"}, httpx.Client(transport=httpx.MockTransport(handler)))
    assert list(source.gcs_pages("/b/b/o", "items", {"prefix": "a"})) == []
    with pytest.raises(CollectorError, match="SOURCE_CURSOR_LIMIT"):
        list(source.gcs_pages("/b/b/o", "items", {"prefix": "b"}))
    assert len(calls) == 3
    source = SourceHTTP({"token": "synthetic"}, httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json={"items": [], "nextPageToken": "same"}))))
    with pytest.raises(CollectorError, match="SOURCE_PAGINATION_LOOP"):
        list(source.gcs_pages("/b/b/o", "items"))
