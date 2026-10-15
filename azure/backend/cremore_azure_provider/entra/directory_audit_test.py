"""Directory creator evidence requires exact additions, not an app's owner."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from cremore_azure_provider.entra import adapter, directory_audit
from cremore_azure_provider.entra.entra_test import (
    APP,
    APP2,
    KEY,
    ORIGIN,
    Graph,
    application,
    collect,
    records,
    spec,
)
from cremore_azure_provider.metadata.transport import ApiError


def selected():
    return spec(capabilities=["inventory", "audit"], options={
        "sources": ["applications", "directory_audits"], "audit_lookback_days": 7})


def event(*, old="[]", new=None, **changes):
    return {"id": "Directory_" + APP2, "activityDateTime": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
            "result": "success", "initiatedBy": {"user": {"id": APP2, "userPrincipalName": "not-persisted@example.test"}},
            "targetResources": [{"type": "Application", "id": APP, "modifiedProperties": [{
                "displayName": "KeyDescription", "oldValue": old,
                "newValue": new if new is not None else json.dumps([f"[KeyIdentifier={KEY},KeyType=Password,DisplayName=must-not-persist]"])}]}],
            **changes}


def graph(logs):
    row = application()
    row["keyCredentials"] = []
    return Graph({"/v1.0/applications": {"value": [row]}, directory_audit.PATH: logs})


def test_exact_added_key_maps_actor_without_retaining_raw_change_or_profile():
    pages = collect(selected(), graph({"value": [event()]}))
    creators = [r for r in records(pages) if r.record_type == "relation"]
    assert len(creators) == 1
    assert creators[0].subject.object_id == f"application:{APP}:passwordCredentials:{KEY}"
    assert creators[0].target.object_id == f"user:{APP2}"
    assert adapter.validate_record(selected(), creators[0])
    assert not adapter.validate_record(spec(), creators[0])
    saved = json.dumps([r.model_dump() for r in records(pages)])
    assert "must-not-persist" not in saved and "not-persisted" not in saved
    assert pages[-1].status == "COMPLETE"


@pytest.mark.parametrize("row", [event(result="failure"), event(old=json.dumps([f"[KeyIdentifier={KEY},KeyType=Password]"])),
    event(old="null"), event(new="invalid"), event(initiatedBy={"app": {"appId": APP2}}),
    event(initiatedBy={"user": {"id": APP2}, "app": {"servicePrincipalId": APP}}),
    event(targetResources=[{"type": "Application", "id": APP2, "modifiedProperties": event()["targetResources"][0]["modifiedProperties"]}])])
def test_unknown_changes_actors_and_unlisted_targets_never_become_creator(row):
    pages = collect(selected(), graph({"value": [row]}))
    assert not any(r.record_type == "relation" for r in records(pages))


def test_denial_empty_unselected_and_resume_are_distinct():
    denied = collect(selected(), graph(ApiError("permission_denied")))
    assert denied[-1].status == "PARTIAL" and "PERMISSION_DENIED" in denied[-1].reasons
    assert collect(selected(), graph({"value": []}))[-1].status == "COMPLETE"
    unselected = graph(ApiError("must_not_call"))
    collect(spec(), unselected)
    assert directory_audit.PATH not in {path for path, _ in unselected.calls}
    api = graph({"value": [event()], "@odata.nextLink": ORIGIN + directory_audit.PATH + "?$skiptoken=next"})
    committed = []
    for page in adapter.collect_pages(selected(), secrets={}, checkpoint={}, check=lambda: None, transport=api):
        committed.extend(r.model_dump() for r in page.records)
        if page.checkpoint["cursor"].get("skiptoken"):
            break
    resumed = graph({"value": []})
    pages = collect(selected(), resumed, checkpoint=page.checkpoint, read_records=lambda: committed)
    assert pages[-1].status == "COMPLETE"
    assert "/v1.0/applications" not in {path for path, _ in resumed.calls}
    params = next(params for path, params in resumed.calls if path == directory_audit.PATH)
    assert params["$skiptoken"] == "next"
    assert page.checkpoint["cursor"]["window_start"] in params["$filter"]
