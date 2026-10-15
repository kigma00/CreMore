"""Read a customer's own Pub/Sub subscription for scan triggers (cremore.scanning.triggers).

CreMore only pulls, acknowledges and extends deadlines on the subscription an Admin
bound; it never creates topics, subscriptions or notification configurations. The
worker's identity needs ``roles/pubsub.subscriber`` on that subscription alone.
"""

from __future__ import annotations

import base64
import binascii
import json

import httpx

from cremore.http_client import HTTPResponseTooLarge, bounded_request

API = "https://pubsub.googleapis.com/v1/"
SCOPE = "https://www.googleapis.com/auth/pubsub"
# Ten messages of at most 128 KiB each (the trigger limit) after base64, plus attributes.
MAX_RESPONSE_BYTES = 4 << 20


class PubSubError(RuntimeError):
    """A stable code; never the response body."""


class PubSubQueue:
    def __init__(self, subscription, token, *, client=None):
        self.subscription, self.token = subscription, token
        self.client = client or httpx.Client(timeout=10.0, follow_redirects=False)

    def _post(self, verb, body):
        try:
            response = bounded_request(self.client, "POST", f"{API}{self.subscription}:{verb}", json=body,
                                       headers={"Authorization": "Bearer " + self.token()},
                                       max_response_bytes=MAX_RESPONSE_BYTES)
        except HTTPResponseTooLarge:
            raise PubSubError("PUBSUB_RESPONSE_TOO_LARGE") from None
        if response.status_code != 200:
            raise PubSubError(f"PUBSUB_HTTP_{response.status_code}")
        try:
            return json.loads(response.content) if response.content else {}
        except ValueError:
            raise PubSubError("PUBSUB_RESPONSE_MALFORMED") from None

    def receive(self):
        # returnImmediately keeps the worker's poll from waiting, as SQS WaitTimeSeconds=0
        # does; a message it misses is returned by the next poll.
        body = self._post("pull", {"maxMessages": 10, "returnImmediately": True})
        out = []
        for item in (body.get("receivedMessages") or [])[:10]:
            message = item.get("message") or {}
            try:
                text = base64.b64decode(message.get("data") or "", validate=True).decode()
            except (binascii.Error, ValueError):
                text = None  # not text: only its attributes can say what it is
            out.append({"id": message.get("messageId", ""), "body": text or None,
                        "attributes": message.get("attributes") or {}, "handle": item.get("ackId")})
        return out

    def ack(self, message):
        self._post("acknowledge", {"ackIds": [message["handle"]]})


# Cloud Storage notification events: whether each only says an object went away.
_STORAGE_EVENTS = {"OBJECT_FINALIZE": False, "OBJECT_METADATA_UPDATE": False, "OBJECT_DELETE": True,
                   "OBJECT_ARCHIVE": True}


def storage_changes(body, attributes, roots):
    """A Cloud Storage Pub/Sub notification; its attributes name the event, bucket and object
    whatever the payload format. A replaced generation is read through the new generation's
    OBJECT_FINALIZE, so the matching delete or archive asks for nothing.
    [Pub/Sub notifications](https://cloud.google.com/storage/docs/pubsub-notifications)
    """
    from cremore.collectors.base import CollectorError
    from cremore.collectors.changes import Changes

    event, bucket, key = (attributes.get(name) for name in ("eventType", "bucketId", "objectId"))
    if not (isinstance(event, str) and isinstance(bucket, str) and attributes.get("notificationConfig")):
        return None
    root = next((r for r in roots if r["provider_resource_id"] == bucket), None)
    if root is None:
        raise CollectorError("EVENT_OUT_OF_SCOPE")
    if event == "OBJECT_INITIALIZE" or (_STORAGE_EVENTS.get(event) and attributes.get("overwrittenByGeneration")):
        return {}  # an upload that has not finished, or a generation its successor replaced
    if event not in _STORAGE_EVENTS or not isinstance(key, str) or not key:
        raise CollectorError("EVENT_UNSUPPORTED_NOTIFICATION")
    return {root["resource_id"]: Changes(head=str(attributes.get("objectGeneration") or ""), paths=[key],
                                         removals=_STORAGE_EVENTS[event])}


def open_queue(subscription, *, client=None):
    """The bound subscription, read with the worker's Application Default Credentials."""
    from cremore_gcp_provider.gcp_auth import adc_token

    return PubSubQueue(subscription, adc_token(scopes=(SCOPE,)), client=client)
