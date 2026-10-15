"""Azure Blob Storage listing and reads through synthetic XML responses only."""

import httpx
import pytest

from cremore.collectors.base import CollectorError
from cremore_azure_provider import blob_content, blob_source

TOKEN = "synthetic-storage-token"


def listing(tag, rows, marker=""):
    items = "".join(
        f"<{tag}><Name>{name}</Name><Properties><Etag>&quot;{etag}&quot;</Etag>"
        f"<Content-Length>{size}</Content-Length></Properties></{tag}>" for name, etag, size in rows)
    return httpx.Response(200, content=(f'﻿<?xml version="1.0" encoding="utf-8"?><EnumerationResults>'
                                        f"<{tag}s>{items}</{tag}s><NextMarker>{marker}</NextMarker>"
                                        "</EnumerationResults>").encode())


def http(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def payload(**config):
    return blob_source.job_payload({"account": "acmeprod", **config}) | {"token": TOKEN}


def test_blobs_are_listed_by_marker_and_read_pinned_to_the_listed_etag():
    calls = []

    def handle(request):
        calls.append(request)
        assert request.headers["authorization"] == "Bearer " + TOKEN
        assert request.headers["x-ms-version"] == blob_content.VERSION
        assert request.url.host == "acmeprod.blob.core.windows.net"
        if request.url.params.get("comp") == "list":
            assert request.url.path == "/deploy" and request.url.params["restype"] == "container"
            if request.url.params.get("marker") == "next-page":
                return listing("Blob", [(".env", "0x2", 12)])
            return listing("Blob", [("config/app.env", "0x1", 16), ("dump.bin", "0x3", 4096)], marker="next-page")
        assert request.headers["if-match"] in ('"0x1"', '"0x2"')
        return httpx.Response(200, content=b"SYNTHETIC=value")

    collector = blob_content.build(payload(container="deploy"), http(handle), max_object_bytes=1024)
    objects = list(collector.collect())
    assert [(item.resource.resource, item.resource.location, item.resource.version_id) for item in objects] == [
        ("acmeprod/deploy", "config/app.env", "0x1"), ("acmeprod/deploy", ".env", "0x2")]
    assert all(item.data == b"SYNTHETIC=value" for item in objects)
    assert collector.failed_objects == 1 and collector.listing_complete  # the oversized blob is counted, not read
    assert not any(request.url.path == "/deploy/dump.bin" for request in calls)


def test_an_account_catalog_lists_containers_including_the_static_website():
    def handle(request):
        assert request.url.path == "/" and request.url.params["comp"] == "list"
        return listing("Container", [("$web", "0x1", 0), ("deploy", "0x2", 0)])

    assert [row[1] for row in blob_content.roots(payload(), http(handle))] == ["acmeprod/$web", "acmeprod/deploy"]
    assert blob_content.Collector.root_payload(payload(), "acmeprod/deploy")["container"] == "deploy"


@pytest.mark.parametrize("response,code", [
    (httpx.Response(200, content=b"<not-xml"), "SOURCE_LIST_MALFORMED"),
    (httpx.Response(200, content=b"<Error><Code>Nope</Code></Error>"), "SOURCE_LIST_MALFORMED"),
    (listing("Container", [("Bad_Name", "0x1", 0)]), "AZURE_BLOB_CONTAINER_MALFORMED"),
    (listing("Container", [("deploy", "0x1", 0)], marker="same"), "SOURCE_PAGINATION_LOOP"),
])
def test_malformed_or_looping_listings_fail_instead_of_looking_empty(response, code):
    with pytest.raises(CollectorError) as caught:
        list(blob_content.roots(payload(), http(lambda request: response)))
    assert caught.value.code == code


@pytest.mark.parametrize("config", [{"account": "Acme"}, {"account": "acmeprod", "container": "a"},
                                    {"account": "acmeprod", "container": "bad--name"}, {}])
def test_account_and_container_names_follow_azure_rules(config):
    with pytest.raises(ValueError):
        blob_source.validate_config(config)


def test_scope_round_trip_and_credential_check_codes():
    assert blob_source.config_from_scope("acmeprod/deploy") == {"account": "acmeprod", "container": "deploy"}
    assert blob_source.scope_ref({"account": "acmeprod"}) == "acmeprod"
    ok = blob_source.check_credential(payload(), http_client_factory=lambda: http(
        lambda request: listing("Container", [("deploy", "0x1", 0)])))
    assert ok.status == "ACTIVE"
    denied = blob_source.check_credential(payload(), http_client_factory=lambda: http(lambda request: httpx.Response(403)))
    assert (denied.status, denied.error) == ("INDETERMINATE", "AZURE_STORAGE_PERMISSION_DENIED")
    rejected = blob_source.check_credential(payload(), http_client_factory=lambda: http(lambda request: httpx.Response(401)))
    assert (rejected.status, rejected.error) == ("REJECTED", "AZURE_AUTHENTICATION_FAILED")


@pytest.mark.parametrize("selection", [{"excluded_prefixes": ["skip/"]}, {"exact_keys": ["wanted"]}])
def test_filtered_names_still_consume_the_scan_listing_limit(selection):
    def handle(request):
        assert request.url.params.get("comp") == "list"
        if request.url.params.get("marker"):
            return listing("Blob", [("skip/second", "two", 1)])
        return listing("Blob", [("skip/first", "one", 1)], marker="next")

    collector = blob_content.Collector({**payload(container="deploy", max_objects=1), **selection}, http(handle))
    with pytest.raises(CollectorError, match="SOURCE_OBJECT_LIMIT"):
        list(collector.collect())
    assert not collector.listing_complete and not collector.authoritative_listing


def test_blob_path_selection_remains_case_sensitive():
    collector = blob_content.Collector(payload(container="deploy", excluded_prefixes=["private/"]), http(lambda _: None))
    assert collector.selected("PRIVATE/file") and not collector.selected("private/file")
