"""The Service Bus peek-lock reader and Event Grid blob events against synthetic answers."""

import json

import httpx
import pytest

from cremore.collectors.base import CollectorError
from cremore_azure_provider import servicebus

BUS = "https://acme-events.servicebus.windows.net/cremore-only"
LOCK = BUS + "/messages/31907572-1647-43c3-8741-631acd554d6f/7da9cfd5-40d5-4bb1-8d64-ec5a52e1c547"
TOPIC = "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct"
ROOTS = [{"resource_id": "r1", "resource_type": "AZURE_BLOB_CONTAINER", "provider_resource_id": "acct/box"}]


def serve(bodies, seen, location=LOCK):
    bodies = list(bodies)

    def handler(request):
        seen.append((request.method, str(request.url), request.headers["authorization"]))
        if request.method == "DELETE":
            return httpx.Response(200)
        if not bodies:
            return httpx.Response(204)
        return httpx.Response(201, content=bodies.pop(0), headers={
            "BrokerProperties": json.dumps({"MessageId": "event-1", "LockToken": "7da9", "DeliveryCount": 1}),
            "Location": location})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_peek_lock_reads_until_empty_and_completes_by_the_lock_url():
    seen = []
    queue = servicebus.ServiceBusQueue(BUS, lambda: "synthetic-token", client=serve([b'{"a": 1}'], seen))
    [message] = queue.receive()
    assert message == {"id": "event-1", "body": '{"a": 1}', "attributes": {}, "handle": LOCK}
    queue.ack(message)
    assert [(method, url.split("?")[0]) for method, url, _auth in seen] == [
        ("POST", BUS + "/messages/head"), ("POST", BUS + "/messages/head"), ("DELETE", LOCK)]
    assert "timeout=1" in seen[0][1] and {auth for *_rest, auth in seen} == {"Bearer synthetic-token"}


@pytest.mark.parametrize("location", [
    "https://attacker.test/cremore-only/messages/1/2",
    "http://acme-events.servicebus.windows.net/cremore-only/messages/1/2",
    "https://acme-events.servicebus.windows.net/other-queue/messages/1/2",
])
def test_a_lock_url_that_is_not_this_entitys_own_never_receives_the_token(location):
    seen = []
    queue = servicebus.ServiceBusQueue(BUS, lambda: "t", client=serve([b"{}"], seen, location=location))
    with pytest.raises(servicebus.ServiceBusError, match="SERVICEBUS_LOCK_LOCATION_UNEXPECTED"):
        queue.receive()
    assert [method for method, _url, _auth in seen] == ["POST"]


def test_a_mixed_case_entity_accepts_the_lower_case_lock_url_service_bus_returns():
    # Entity names are case-insensitive; Peek-Lock answers with the lower-case path.
    seen = []
    address = "https://acme-events.servicebus.windows.net/Cremore-Only"
    queue = servicebus.ServiceBusQueue(address, lambda: "t", client=serve([b"{}"], seen))
    [message] = queue.receive()
    assert message["handle"] == LOCK



def test_an_oversized_or_binary_body_is_handed_over_empty_for_the_trigger_to_refuse():
    queue = servicebus.ServiceBusQueue(BUS, lambda: "t", client=serve(
        [b"x" * (servicebus.MAX_BODY_BYTES + 1), b"\xff\xfe"], []))
    assert [message["body"] for message in queue.receive()] == [None, None]


def event(kind, subject="/blobServices/default/containers/box/blobs/approved/app.env", schema="eventgrid", **data):
    if schema == "eventgrid":
        return {"topic": TOPIC, "subject": subject, "eventType": kind, "id": "1", "data": data}
    return {"source": TOPIC, "subject": subject, "type": kind, "id": "1", "specversion": "1.0", "data": data}


@pytest.mark.parametrize("schema", ["eventgrid", "cloudevents"])
def test_blob_events_in_either_schema_name_the_blob(schema):
    created = servicebus.blob_changes(event("Microsoft.Storage.BlobCreated", schema=schema), {}, ROOTS)["r1"]
    assert (created.paths, created.removals) == (["approved/app.env"], False)


def test_a_rename_names_both_blobs_and_several_events_in_one_message_are_merged():
    renamed = event("Microsoft.Storage.BlobRenamed", subject="/blobServices/default/containers/box/blobs/approved/new.env",
                    sourceUrl="https://acct.dfs.core.windows.net/box/approved/old%20name.env")
    both = servicebus.blob_changes([event("Microsoft.Storage.BlobCreated"), renamed], {}, ROOTS)["r1"]
    assert both.paths == ["approved/app.env", "approved/new.env", "approved/old name.env"] and both.removals


def test_a_folder_rename_reads_the_container_and_tier_changes_ask_for_nothing():
    assert servicebus.blob_changes(event("Microsoft.Storage.DirectoryRenamed",
                                         subject="/blobServices/default/containers/box/blobs/dir"), {}, ROOTS)["r1"].paths is None
    assert servicebus.blob_changes(event("Microsoft.Storage.BlobTierChanged"), {}, ROOTS) == {}


def test_other_events_are_not_blob_events_and_other_containers_are_out_of_scope():
    assert servicebus.blob_changes({"eventType": "git.push"}, {}, ROOTS) is None
    assert servicebus.blob_changes([], {}, ROOTS) is None
    with pytest.raises(CollectorError, match="EVENT_OUT_OF_SCOPE"):
        servicebus.blob_changes(event("Microsoft.Storage.BlobCreated",
                                      subject="/blobServices/default/containers/other/blobs/a"), {}, ROOTS)
    with pytest.raises(CollectorError, match="EVENT_INVALID_PAYLOAD"):
        servicebus.blob_changes({**event("Microsoft.Storage.BlobCreated"), "topic": "/not/a/storage/account"}, {}, ROOTS)


@pytest.mark.parametrize("container", ["$web", "$root"])
def test_events_of_a_static_website_or_root_container_name_the_blob(container):
    roots = [{**ROOTS[0], "provider_resource_id": f"acct/{container}"}]
    changes = servicebus.blob_changes(event("Microsoft.Storage.BlobCreated",
                                            subject=f"/blobServices/default/containers/{container}/blobs/index.html"),
                                      {}, roots)["r1"]
    assert changes.paths == ["index.html"]
