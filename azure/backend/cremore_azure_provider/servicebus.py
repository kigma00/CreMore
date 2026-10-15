"""Read a customer's own Service Bus queue or topic subscription for scan triggers
(cremore.scanning.triggers), with peek-lock over the REST API.

CreMore only locks, completes and lets locks lapse on the entity an Admin bound; it
never creates namespaces, queues or Event Grid subscriptions. The worker's identity
needs the "Azure Service Bus Data Receiver" role on that entity alone.
"""

from __future__ import annotations

import json
import re
from urllib.parse import unquote, urlsplit

import httpx

SCOPE = "https://servicebus.azure.net/.default"
# A trigger message is at most 128 KiB; anything longer is refused unread.
MAX_BODY_BYTES = 128 << 10


class ServiceBusError(RuntimeError):
    """A stable code; never the response body."""


class ServiceBusQueue:
    def __init__(self, address, token, *, client=None):
        self.address, self.token = address.rstrip("/"), token
        self.client = client or httpx.Client(timeout=10.0, follow_redirects=False)

    def _headers(self):
        return {"Authorization": "Bearer " + self.token()}

    def _lock(self):
        """Lock the next message; None when the entity is empty."""
        with self.client.stream("POST", self.address + "/messages/head", params={"timeout": "1"},
                                headers=self._headers()) as response:
            if response.status_code == 204:
                return None
            if response.status_code != 201:
                raise ServiceBusError(f"SERVICEBUS_HTTP_{response.status_code}")
            try:
                properties = json.loads(response.headers.get("BrokerProperties") or "{}")
            except ValueError:
                properties = {}
            body = bytearray()
            for chunk in response.iter_bytes():
                body += chunk
                if len(body) > MAX_BODY_BYTES:
                    body = None
                    break
            location = response.headers.get("Location") or ""
        # The lock URL receives our token, so it must be this entity's own message URL. Entity names are
        # case-insensitive and Service Bus answers with the lower-case path.
        parsed, own = urlsplit(location), urlsplit(self.address)
        if (parsed.scheme != "https" or parsed.hostname != own.hostname or parsed.query or parsed.fragment
                or not parsed.path.lower().startswith(own.path.lower() + "/messages/")):
            raise ServiceBusError("SERVICEBUS_LOCK_LOCATION_UNEXPECTED")
        try:
            text = None if body is None else bytes(body).decode()
        except UnicodeDecodeError:
            text = None
        return {"id": str(properties.get("MessageId") or ""), "body": text or None, "attributes": {},
                "handle": location}

    def receive(self):
        out = []
        for _ in range(10):
            message = self._lock()
            if message is None:
                break
            out.append(message)
        return out

    def ack(self, message):
        response = self.client.delete(message["handle"], headers=self._headers())
        if response.status_code != 200:
            raise ServiceBusError(f"SERVICEBUS_HTTP_{response.status_code}")


# The containers blob_content.CONTAINER scans, $root/$web/$logs included.
_SUBJECT = re.compile(r"/blobServices/default/containers/(\$(?:root|web|logs)|[a-z0-9-]{3,63})(?:/blobs/(.+))?")
_ACCOUNT = re.compile(r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Storage/storageAccounts/([a-z0-9]{3,24})",
                      re.IGNORECASE)
# Blob events that change what a container holds, and whether each only removes names.
_BLOB_EVENTS = {"Microsoft.Storage.BlobCreated": False, "Microsoft.Storage.BlobDeleted": True,
                "Microsoft.Storage.BlobRenamed": True}
# A folder renamed or deleted (Data Lake Storage): the names under it are not listed.
_FOLDER_EVENTS = ("Microsoft.Storage.DirectoryRenamed", "Microsoft.Storage.DirectoryDeleted")


def blob_changes(body, attributes, roots):
    """Event Grid blob events (Event Grid or CloudEvents schema, one event or an array) a
    customer routes to their Service Bus queue. Tier changes, created folders and copies
    that have not finished carry no new content and ask for nothing.
    [Blob Storage events](https://learn.microsoft.com/en-us/azure/event-grid/event-schema-blob-storage)
    """
    from cremore.collectors.base import CollectorError
    from cremore.collectors.changes import Changes

    events = body if isinstance(body, list) else [body]
    kinds = [event.get("eventType") or event.get("type") if isinstance(event, dict) else None for event in events]
    if not events or not all(isinstance(kind, str) and kind.startswith("Microsoft.Storage.") for kind in kinds):
        return None
    by_name = {root["provider_resource_id"].lower(): root for root in roots}
    found = {}  # resource_id -> [names or None, removals]
    for event, kind in zip(events, kinds, strict=True):
        account = _ACCOUNT.fullmatch(event.get("topic") or event.get("source") or "")
        subject = _SUBJECT.fullmatch(event.get("subject") or "")
        if account is None or subject is None:
            raise CollectorError("EVENT_INVALID_PAYLOAD")
        root = by_name.get(f"{account.group(1).lower()}/{subject.group(1)}")
        if root is None:
            raise CollectorError("EVENT_OUT_OF_SCOPE")
        if kind in _FOLDER_EVENTS:
            names = None
        elif kind in _BLOB_EVENTS and subject.group(2):
            names = [subject.group(2)]
            source = urlsplit(str((event.get("data") or {}).get("sourceUrl") or "")).path
            if kind == "Microsoft.Storage.BlobRenamed" and source.startswith(f"/{subject.group(1)}/"):
                names.append(unquote(source.removeprefix(f"/{subject.group(1)}/")))
        else:
            continue
        entry = found.setdefault(root["resource_id"], [[], False])
        entry[0] = None if entry[0] is None or names is None else entry[0] + names
        entry[1] = entry[1] or names is None or _BLOB_EVENTS.get(kind, True)
    return {resource_id: Changes(head="", paths=None if names is None else list(dict.fromkeys(names)), removals=removals)
            for resource_id, (names, removals) in found.items()}


def open_queue(address, *, client=None):
    """The bound entity, read with the worker's ambient Azure identity."""
    from cremore_azure_provider.metadata.transport import default_token

    return ServiceBusQueue(address, default_token(SCOPE), client=client)
