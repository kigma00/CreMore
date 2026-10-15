from xml.sax.saxutils import escape

import httpx
import pytest

from cremore.collectors import base
from cremore.collectors.base import CollectorError
from cremore_azure_provider.blob_content import Collector, SourceHTTP


def page(marker):
    return httpx.Response(200, content=("<EnumerationResults><Blobs/><NextMarker>" + escape(marker)
                                       + "</NextMarker></EnumerationResults>").encode())


def test_blob_rejects_an_oversized_marker_before_sending_another_request(monkeypatch):
    monkeypatch.setattr(base, "MAX_CURSOR_BYTES", 16)
    calls = []

    def handler(request):
        calls.append(request)
        return page("x" * 17)

    collector = Collector({"account": "synthetic", "container": "data", "token": "synthetic"},
                          httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(CollectorError) as caught:
        list(collector.collect())
    assert str(caught.value) == "SOURCE_CURSOR_LIMIT"
    assert len(calls) == 1 and not collector.listing_complete


def test_blob_detects_cycles_and_caps_cursor_admissions_across_prefixes(monkeypatch):
    calls = []

    def handler(request):
        calls.append(request)
        return page("" if request.url.params.get("marker") else "same")

    monkeypatch.setattr(base, "MAX_CURSOR_HISTORY", 1)
    source = SourceHTTP({"account": "synthetic", "token": "synthetic"},
                        httpx.Client(transport=httpx.MockTransport(handler)))
    assert list(source.pages("/data", "Blob", {"prefix": "a"})) == []
    with pytest.raises(CollectorError, match="SOURCE_CURSOR_LIMIT"):
        list(source.pages("/data", "Blob", {"prefix": "b"}))
    assert len(calls) == 3
    source = SourceHTTP({"account": "synthetic", "token": "synthetic"},
                        httpx.Client(transport=httpx.MockTransport(lambda request: page("same"))))
    with pytest.raises(CollectorError, match="SOURCE_PAGINATION_LOOP"):
        list(source.pages("/data", "Blob"))
