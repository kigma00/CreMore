"""The customer's own Pub/Sub and Service Bus queues are read like SQS, and a provider's
notification becomes the least work that covers it (design 4.3)."""

import json
from datetime import timedelta

import pytest

from cremore.collectors.changes import Changes
from cremore.scanning import changes, scope, trigger_settings, triggers
from cremore.scanning.changes_test import Feed
from cremore.scanning.triggers_test import NOW, setup, switch_triggers

SUBSCRIPTION = "projects/acme-scans/subscriptions/cremore-only"
BUS = "https://acme-events.servicebus.windows.net/cremore-only"


class FakeQueue:
    """The queue interface poll_queue reads, recording what it was asked."""

    def __init__(self, *messages):
        self.messages, self.calls = list(messages), []

    def receive(self):
        self.calls.append("receive")
        return list(self.messages)

    def ack(self, message):
        self.calls.append(("ack", message["id"]))
        self.messages.remove(message)


def bind(repo, kind, profile, address):
    """What PUT /api/v1/settings/scan-triggers writes when an Admin binds a queue."""
    switch_triggers(repo, schedules_enabled=False, **{
        f"{kind}_enabled": True, f"{kind}_profile_id": str(profile.id),
        f"{kind}_{trigger_settings.QUEUES[kind]}": address, f"{kind}_dedicated_acknowledged": True})


def storage(event, key="approved/app.env", bucket="bucket", **attributes):
    return {"id": f"{event}:{key}:{sorted(attributes)}", "body": None, "handle": "ack-id", "attributes": {
        "notificationConfig": "projects/_/buckets/bucket/notificationConfigs/1", "eventType": event,
        "payloadFormat": "NONE", "bucketId": bucket, "objectId": key, "objectGeneration": "7", **attributes}}


def push(message_id="push-1", **fields):
    body = {"ref": "refs/heads/main", "before": "a" * 40, "after": "b" * 40, "forced": False,
            "pusher": {"name": "dev"}, "repository": {"full_name": "owner/repo", "default_branch": "main"}, **fields}
    return {"id": message_id, "body": json.dumps(body), "handle": "lock-url"}


def poll(repo, settings, kind, queue):
    return triggers.poll_queue(repo, settings, kind, lambda address: queue, now=NOW)


def jobs(repo):
    return sorted(repo.jobs.values(), key=lambda job: job.created_at)


def finish(repo):
    for job in repo.jobs.values():
        job.status = "SUCCEEDED"


def test_each_queue_is_off_until_bound_acknowledged_and_allowed_by_the_installation():
    repo, _conn, profile, _item, settings = setup("gcp")
    view = trigger_settings.config(settings, repo)
    assert view["pubsub"]["enabled"] is view["servicebus"]["enabled"] is False
    switch_triggers(repo, pubsub_enabled=True, pubsub_profile_id=str(profile.id), pubsub_subscription=SUBSCRIPTION)
    assert trigger_settings.config(settings, repo)["pubsub"]["blocked_by"] == "PUBSUB_NOT_ACKNOWLEDGED"
    switch_triggers(repo, pubsub_dedicated_acknowledged=True, pubsub_subscription="")
    assert trigger_settings.config(settings, repo)["pubsub"]["blocked_by"] == "PUBSUB_SUBSCRIPTION_MISSING"
    switch_triggers(repo, pubsub_subscription=SUBSCRIPTION)
    assert trigger_settings.queue_binding(settings, repo, "pubsub") == {"profile_id": str(profile.id),
                                                                       "queue": SUBSCRIPTION}
    assert trigger_settings.event_profiles(settings, repo) == {str(profile.id)}
    locked = settings.model_copy(update={"scan_pubsub_mode": "disabled"})
    queue = FakeQueue(storage("OBJECT_FINALIZE"))
    assert poll(repo, locked, "pubsub", queue) == {"acknowledged": 0, "failed": 0} and not queue.calls
    assert trigger_settings.config(locked, repo)["pubsub"]["installation_allows"] is False


@pytest.mark.parametrize("name, value", [
    ("pubsub_subscription", "projects/acme-scans/topics/cremore-only"),
    ("pubsub_subscription", "projects/acme-scans/subscriptions/goog-reserved"),
    ("pubsub_subscription", "https://pubsub.googleapis.com/v1/" + SUBSCRIPTION),
    ("servicebus_queue", "http://acme-events.servicebus.windows.net/cremore-only"),
    ("servicebus_queue", "https://acme-events.servicebus.windows.net.attacker.test/cremore-only"),
    ("servicebus_queue", BUS + "?timeout=60"),
    ("servicebus_queue", "https://user@acme-events.servicebus.windows.net/cremore-only"),
    ("servicebus_queue", "https://acme-events.servicebus.windows.net/"),
])
def test_a_queue_address_is_exactly_a_subscription_or_a_service_bus_entity(name, value):
    with pytest.raises(trigger_settings.TriggerSettingError):
        trigger_settings.normalize({name: value})


def test_a_topic_subscription_is_a_service_bus_entity_too():
    topic = "https://acme-events.servicebus.windows.net/storage-events/subscriptions/cremore"
    assert trigger_settings.normalize({"servicebus_queue": topic, "pubsub_subscription": SUBSCRIPTION}) == {
        "servicebus_queue": topic, "pubsub_subscription": SUBSCRIPTION}


def test_a_storage_notification_scans_the_object_and_a_delete_reads_the_bucket_again():
    repo, _conn, profile, _item, settings = setup("gcp")
    bind(repo, "pubsub", profile, SUBSCRIPTION)
    queue = FakeQueue(storage("OBJECT_FINALIZE"))
    assert poll(repo, settings, "pubsub", queue) == {"acknowledged": 1, "failed": 0}
    [job] = jobs(repo)
    assert job.payload["mode"] == "EVENT" and job.payload["roots"][0]["exact_keys"] == ["approved/app.env"]
    assert job.payload["requested_by"] == "queue"
    assert queue.calls == ["receive", ("ack", storage("OBJECT_FINALIZE")["id"])]
    finish(repo)
    # A delete is not proof by itself: the bucket's complete listing settles what is gone.
    poll(repo, settings, "pubsub", FakeQueue(storage("OBJECT_DELETE")))
    deleted = jobs(repo)[-1]
    assert deleted.payload["mode"] == "DELTA" and "exact_keys" not in deleted.payload["roots"][0]


@pytest.mark.parametrize("message", [
    storage("OBJECT_FINALIZE", key="docs/readme.md"),
    storage("OBJECT_FINALIZE", key="approved/private/key.pem"),
    storage("OBJECT_INITIALIZE"),
    storage("OBJECT_DELETE", overwrittenByGeneration="8"),
])
def test_a_notification_outside_the_approved_prefixes_or_without_new_content_is_acknowledged_idle(message):
    repo, _conn, profile, _item, settings = setup("gcp")
    bind(repo, "pubsub", profile, SUBSCRIPTION)
    queue = FakeQueue(message)
    assert poll(repo, settings, "pubsub", queue) == {"acknowledged": 1, "failed": 0}
    assert not repo.jobs


@pytest.mark.parametrize("message", [
    storage("OBJECT_FINALIZE", bucket="someone-elses-bucket"),
    {"id": "garbage", "body": "not json", "handle": "h"},
    {"id": "unknown", "body": json.dumps({"hello": "world"}), "handle": "h"},
    {"id": "", "body": json.dumps({"resource_id": "x"}), "handle": "h"},
    {"id": "big", "body": " " * (triggers.MAX_EVENT_BYTES + 1), "handle": "h"},
])
def test_a_notification_for_another_resource_or_in_no_known_shape_stays_on_the_queue(message):
    repo, _conn, profile, _item, settings = setup("gcp")
    bind(repo, "pubsub", profile, SUBSCRIPTION)
    queue = FakeQueue(message)
    assert poll(repo, settings, "pubsub", queue) == {"acknowledged": 0, "failed": 1}
    assert queue.calls == ["receive"] and not repo.jobs


def test_messages_for_a_busy_connection_are_acknowledged_only_after_durable_enqueue():
    repo, _conn, profile, _item, settings = setup("gcp")
    bind(repo, "pubsub", profile, SUBSCRIPTION)
    first, second = storage("OBJECT_FINALIZE"), storage("OBJECT_FINALIZE", key="approved/other.env")
    queue = FakeQueue(first, second)
    assert poll(repo, settings, "pubsub", queue) == {"acknowledged": 2, "failed": 0}
    queued = jobs(repo)
    assert len(queued) == 2 and all(job.status == "QUEUED" for job in queued)
    assert {job.payload["roots"][0]["exact_keys"][0] for job in queued} == {"approved/app.env", "approved/other.env"}
    assert queue.calls == ["receive", ("ack", first["id"]), ("ack", second["id"])]
    assert not queue.messages
    assert poll(repo, settings, "pubsub", FakeQueue(first, second)) == {"acknowledged": 2, "failed": 0}
    assert {job.id for job in jobs(repo)} == {job.id for job in queued}


def test_a_push_rereads_the_repository_and_a_forced_push_reads_it_from_scratch():
    repo, _conn, profile, _item, settings = setup("github")
    bind(repo, "servicebus", profile, BUS)
    assert poll(repo, settings, "servicebus", FakeQueue(push()))["acknowledged"] == 1
    assert jobs(repo)[-1].payload["mode"] == "DELTA"
    finish(repo)
    assert poll(repo, settings, "servicebus", FakeQueue(push("push-2", forced=True)))["acknowledged"] == 1
    assert jobs(repo)[-1].payload["mode"] == "BASELINE"


@pytest.mark.parametrize("fields, acknowledged", [
    ({"ref": "refs/heads/feature"}, True),
    ({"ref": "refs/tags/v1.0"}, True),
    ({"deleted": True, "after": "0" * 40}, True),
    ({"repository": {"full_name": "owner/elsewhere", "default_branch": "main"}}, False),
])
def test_a_push_to_another_branch_is_idle_and_one_to_another_repository_is_refused(fields, acknowledged):
    repo, _conn, profile, _item, settings = setup("github")
    bind(repo, "servicebus", profile, BUS)
    result = poll(repo, settings, "servicebus", FakeQueue(push(**fields)))
    assert result == ({"acknowledged": 1, "failed": 0} if acknowledged else {"acknowledged": 0, "failed": 1})
    assert not repo.jobs


def test_a_push_wakes_a_change_feed_that_has_a_cursor_instead_of_queueing_a_scan():
    repo, _conn, profile, _item, settings = setup("github")
    bind(repo, "servicebus", profile, BUS)
    switch_triggers(repo, change_feeds_enabled=True)
    _profile, plan, _target, _base, _source = triggers.prepare_trigger_plan(repo, settings, profile.id, "EVENT", now=NOW)
    [root] = plan.roots
    root_id = scope.root_identity(profile.connection_id, root)
    changes.CursorStore(repo).put(root_id, profile.id, profile.connection_id, {"cursor": "a" * 40}, NOW)
    assert poll(repo, settings, "servicebus", FakeQueue(push()))["acknowledged"] == 1
    assert not repo.jobs
    # The feed reads the woken root on the next poll although its five minutes have not passed,
    # and its compare names the one changed file.
    feed = Feed(Changes(head="b" * 40, paths=["approved/app.env"]))
    assert changes.poll_change_feeds(repo, settings, feed, now=NOW + timedelta(minutes=1))["enqueued"] == 1
    [job] = jobs(repo)
    assert job.payload["mode"] == "EVENT" and job.payload["roots"][0]["exact_paths"] == ["approved/app.env"]


def test_a_push_before_the_feeds_first_look_is_not_lost():
    repo, _conn, profile, _item, settings = setup("github")
    bind(repo, "servicebus", profile, BUS)
    switch_triggers(repo, change_feeds_enabled=True)
    assert poll(repo, settings, "servicebus", FakeQueue(push()))["acknowledged"] == 1
    assert jobs(repo)[-1].payload["mode"] == "DELTA"


def test_the_worker_passes_poll_queue_an_opener_it_can_actually_call():
    """The poll loop swallows every trigger exception; exercise the real wiring."""
    from cremore.worker import JobWorker

    repo, _conn, profile, _item, settings = setup("gcp")
    bind(repo, "pubsub", profile, SUBSCRIPTION)
    queue, opened = FakeQueue(storage("OBJECT_FINALIZE")), []

    def opener(address):
        opened.append(address)
        return queue

    worker = JobWorker(repo, settings=settings, queue_openers={"pubsub": opener})
    worker._last_trigger_poll = 0
    worker.poll_triggers()
    assert opened == [SUBSCRIPTION] and len(repo.jobs) == 1 and not queue.messages
    # No binding, no client.
    switch_triggers(repo, pubsub_enabled=False)
    worker._last_trigger_poll = 0
    worker.poll_triggers()
    assert opened == [SUBSCRIPTION]
