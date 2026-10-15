"""Exact credential attribution, durable pagination and denial reporting for beta logs."""

import json
from datetime import UTC, datetime, timedelta

from cremore_azure_provider.entra import adapter, audit
from cremore_azure_provider.entra.entra_test import (
    APP,
    APP2,
    CLIENT,
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
        "sources": ["applications", "credential_sign_ins"], "audit_lookback_days": 7})


def sign_in(**changes):
    return {"id": APP2, "createdDateTime": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
            "appId": CLIENT, "servicePrincipalId": APP, "servicePrincipalCredentialKeyId": KEY,
            "status": {"errorCode": 0}, "signInEventTypes": ["servicePrincipal"],
            "ipAddress": "192.0.2.1", "authenticationDetails": "must-not-persist", **changes}


def graph(logs):
    row = application()
    row["keyCredentials"] = []
    return Graph({"/v1.0/applications": {"value": [row]}, audit.PATH: logs})


def test_sign_ins_require_exact_key_app_type_and_success_without_retaining_raw_logs():
    pages = collect(selected(), graph({"value": [sign_in(), sign_in(appId=APP2),
        sign_in(servicePrincipalCredentialKeyId=None), sign_in(status={"errorCode": 500}),
        sign_in(signInEventTypes=["interactiveUser"])]}))
    used = [r for r in records(pages) if r.record_type == "provider_event"]
    assert len(used) == 1 and used[0].subject.object_id == f"application:{APP}:passwordCredentials:{KEY}"
    assert adapter.validate_record(selected(), used[0])
    assert pages[-1].status == "PARTIAL" and "SIGN_IN_CREDENTIAL_NOT_ATTRIBUTED" in pages[-1].reasons
    saved = json.dumps([r.model_dump() for r in records(pages)])
    assert "192.0.2.1" not in saved and "must-not-persist" not in saved and "synthetic-secret" not in saved


def test_denied_empty_unselected_and_ambiguous_are_distinct():
    denied = collect(selected(), graph(ApiError("permission_denied")))
    assert denied[-1].status == "PARTIAL" and "PERMISSION_DENIED" in denied[-1].reasons
    empty = collect(selected(), graph({"value": []}))
    assert empty[-1].status == "COMPLETE" and not any(r.record_type == "provider_event" for r in records(empty))
    api = graph({"value": [sign_in()]})
    collect(spec(), api)
    assert audit.PATH not in {path for path, _ in api.calls}
    ambiguous = Graph({"/v1.0/applications": {"value": [application()]}, audit.PATH: {"value": [sign_in()]}})
    pages = collect(selected(), ambiguous)
    assert not any(r.record_type == "provider_event" for r in records(pages))
    assert "SIGN_IN_CREDENTIAL_AMBIGUOUS" in pages[-1].reasons


def test_resume_preserves_audit_window_and_does_not_recollect_inventory():
    configured = selected()
    api = graph({"value": [sign_in()], "@odata.nextLink": ORIGIN + audit.PATH + "?$skiptoken=next"})
    committed = []
    for page in adapter.collect_pages(configured, secrets={}, checkpoint={}, check=lambda: None, transport=api):
        committed.extend(r.model_dump() for r in page.records)
        if page.checkpoint["cursor"].get("skiptoken"):
            break
    window = (page.checkpoint["cursor"]["window_start"], page.checkpoint["cursor"]["window_end"])
    resumed_api = graph({"value": []})
    resumed = collect(configured, resumed_api, checkpoint=page.checkpoint, read_records=lambda: committed)
    assert resumed[-1].status == "COMPLETE"
    assert "/v1.0/applications" not in {path for path, _ in resumed_api.calls}
    params = next(params for path, params in resumed_api.calls if path == audit.PATH)
    assert params["$skiptoken"] == "next" and all(t in params["$filter"] for t in window)
