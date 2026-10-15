"""The Pub/Sub reader and Cloud Storage notifications against a synthetic subscription."""

import base64
import json

import httpx
import pytest

from cremore.collectors.base import CollectorError
from cremore_gcp_provider import pubsub

SUBSCRIPTION = "projects/acme-scans/subscriptions/cremore-only"
ROOTS = [{"resource_id": "r1", "resource_type": "GCS_BUCKET", "provider_resource_id": "bucket"}]


def serve(messages, seen):
    def handler(request):
        seen.append((request.url.path, json.loads(request.content), request.headers["authorization"]))
        assert request.url.host == "pubsub.googleapis.com"
        if request.url.path.endswith(":pull"):
            return httpx.Response(200, json={"receivedMessages": messages})
        return httpx.Response(200, json={})

    return httpx.Client(transport=httpx.MockTransport(handler))


def received(ack_id, data=None, **attributes):
    message = {"messageId": "m-" + ack_id, "attributes": attributes}
    if data is not None:
        message["data"] = base64.b64encode(data.encode()).decode()
    return {"ackId": ack_id, "message": message, "deliveryAttempt": 1}


def test_pull_decodes_the_data_and_acknowledges_by_ack_id():
    seen = []
    queue = pubsub.PubSubQueue(SUBSCRIPTION, lambda: "synthetic-token",
                               client=serve([received("a1", '{"resource_id": "r1"}'), received("a2", eventType="X")], seen))
    first, second = queue.receive()
    assert first == {"id": "m-a1", "body": '{"resource_id": "r1"}', "attributes": {}, "handle": "a1"}
    assert second["body"] is None and second["attributes"] == {"eventType": "X"}
    queue.ack(first)
    assert [path for path, _body, _auth in seen] == [f"/v1/{SUBSCRIPTION}:pull", f"/v1/{SUBSCRIPTION}:acknowledge"]
    assert seen[0][1] == {"maxMessages": 10, "returnImmediately": True}
    assert seen[1][1] == {"ackIds": ["a1"]}
    assert {auth for _path, _body, auth in seen} == {"Bearer synthetic-token"}


def test_a_response_larger_than_ten_trigger_messages_is_refused_unread():
    big = received("a1", "x" * (pubsub.MAX_RESPONSE_BYTES + 1))
    queue = pubsub.PubSubQueue(SUBSCRIPTION, lambda: "t", client=serve([big], []))
    with pytest.raises(pubsub.PubSubError, match="PUBSUB_RESPONSE_TOO_LARGE"):
        queue.receive()


def test_an_http_failure_is_a_stable_code():
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(403, text="denied: secret")))
    with pytest.raises(pubsub.PubSubError) as raised:
        pubsub.PubSubQueue(SUBSCRIPTION, lambda: "t", client=client).receive()
    assert str(raised.value) == "PUBSUB_HTTP_403"


def notification(event, **extra):
    return {"notificationConfig": "projects/_/buckets/bucket/notificationConfigs/1", "eventType": event,
            "bucketId": "bucket", "objectId": "approved/app.env", "objectGeneration": "7", **extra}


def test_storage_notifications_name_the_object_and_say_whether_it_went_away():
    finalized = pubsub.storage_changes(None, notification("OBJECT_FINALIZE"), ROOTS)["r1"]
    assert (finalized.paths, finalized.removals, finalized.head) == (["approved/app.env"], False, "7")
    assert pubsub.storage_changes(None, notification("OBJECT_DELETE"), ROOTS)["r1"].removals
    assert pubsub.storage_changes(None, notification("OBJECT_ARCHIVE"), ROOTS)["r1"].removals
    assert pubsub.storage_changes(None, notification("OBJECT_METADATA_UPDATE"), ROOTS)["r1"].paths == ["approved/app.env"]


def test_a_replaced_generation_or_an_unfinished_upload_asks_for_nothing():
    assert pubsub.storage_changes(None, notification("OBJECT_ARCHIVE", overwrittenByGeneration="8"), ROOTS) == {}
    assert pubsub.storage_changes(None, notification("OBJECT_INITIALIZE"), ROOTS) == {}


def test_other_messages_are_not_storage_notifications_and_other_buckets_are_out_of_scope():
    assert pubsub.storage_changes({"eventType": "OBJECT_FINALIZE"}, {"eventType": "OBJECT_FINALIZE"}, ROOTS) is None
    with pytest.raises(CollectorError, match="EVENT_OUT_OF_SCOPE"):
        pubsub.storage_changes(None, notification("OBJECT_FINALIZE", bucketId="elsewhere"), ROOTS)
    with pytest.raises(CollectorError, match="EVENT_UNSUPPORTED_NOTIFICATION"):
        pubsub.storage_changes(None, notification("OBJECT_SOMETHING_NEW"), ROOTS)
