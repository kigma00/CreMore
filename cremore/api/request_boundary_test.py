"""Synthetic request failures must not disclose inputs or partially change settings."""

from copy import deepcopy
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, ValidationError
from pydantic.fields import FieldInfo

from cremore.api.app_test import auth, client
from cremore.api.http_support import validation_details
from cremore.domain.models import Connection, FindingEvent, ScanJob


@pytest.mark.parametrize(
    ("method", "path", "body", "field"),
    [
        ("post", "/api/v1/scan", {"text": {"private": "SYNTHETIC_PRIVATE_INPUT"}}, "text"),
        (
            "patch",
            "/api/v1/connections/00000000-0000-4000-8000-000000000000",
            {"status": "ACTIVE", "token": ["SYNTHETIC_PRIVATE_INPUT"]},
            "token",
        ),
    ],
)
def test_invalid_typed_input_keeps_field_but_never_echoes_value(method, path, body, field):
    response = getattr(client(), method)(path, json=body, headers=auth())
    assert response.status_code == 422
    assert "SYNTHETIC_PRIVATE_INPUT" not in response.text
    error = response.json()["detail"][0]
    assert error["loc"] == ["body", field]
    assert error["type"] == "string_type"
    assert set(error) == {"loc", "type", "msg"}


def test_validation_locations_do_not_echo_arbitrary_dictionary_keys():
    c = client()

    @c.app.post("/boundary-proof")
    def typed_mapping(body: dict[str, int]):
        return body

    response = c.post("/boundary-proof", json={"SYNTHETIC_PRIVATE_INPUT": "invalid"})
    assert response.status_code == 422
    assert "SYNTHETIC_PRIVATE_INPUT" not in response.text
    assert response.json()["detail"][0]["loc"] == ["body", "<field>"]


def test_validation_locations_use_public_field_annotations():
    class Payload(BaseModel):
        values: list[dict[str, int]] = Field(alias="publicValues")

    with pytest.raises(ValidationError) as rejected:
        Payload.model_validate({
            "publicValues": [{"SYNTHETIC_PRIVATE_KEY": "SYNTHETIC_PRIVATE_VALUE"}],
        })
    errors = [{**error, "loc": ("body", *error["loc"])} for error in rejected.value.errors()]
    # Newer FastAPI fields expose FieldInfo without the former type_ attribute.
    field = SimpleNamespace(name="body", alias="body", field_info=FieldInfo(annotation=Payload))
    request = SimpleNamespace(scope={"route": SimpleNamespace(
        dependant=SimpleNamespace(body_params=[field]),
    )})

    assert validation_details(request, RequestValidationError(errors)) == [{
        "loc": ["body", "publicValues", 0, "<field>"],
        "type": "int_parsing",
        "msg": "Invalid value",
    }]


def test_identity_center_validates_new_permission_set_and_discovery_together():
    c = client()
    path = "/api/v1/settings/aws-identity-center"
    response = c.put(path, headers=auth(),
                     json={"permission_set": "Scanner", "discovery_enabled": True})
    assert response.status_code == 200
    assert response.json()["discovery"]["enabled"] is True
    before = deepcopy(c.app.state.repo.installation_settings)
    rejected = c.put(path, headers=auth(),
                     json={"permission_set": "", "discovery_enabled": True})
    assert rejected.status_code == 409
    assert c.app.state.repo.installation_settings == before


@pytest.mark.parametrize("item", ["invalid", None, [], {"finding_id": "00000000-0000-4000-8000-000000000000", "revision": True}])
def test_malformed_bulk_review_items_are_validation_errors(item):
    response = client().post("/api/v1/ownership-reviews/bulk", headers=auth(),
                             json={"status": "OPEN", "items": [item]})
    assert response.status_code == 422


def test_audit_preserves_newest_recording_when_clock_ticks_are_equal(monkeypatch):
    c = client()
    instant = datetime(2026, 9, 23, tzinfo=UTC)
    monkeypatch.setattr("cremore.db.repository._now", lambda: instant)
    for action in ("FIRST", "SECOND", "THIRD"):
        c.app.state.repo.record_finding_event(FindingEvent(event_type=action))
    rows = c.get("/api/v1/audit", headers=auth()).json()
    assert [row["action"] for row in rows] == ["FINDING_THIRD", "FINDING_SECOND", "FINDING_FIRST"]


@pytest.mark.parametrize(
    ("path", "body", "settings", "status"),
    [
        ("aws-investigations", {"usage_lookup": True, "potential_access": "yes"}, {}, 422),
        (
            "aws-investigations",
            {"potential_access": True, "usage_lookup": True},
            {"IAM_POTENTIAL_ACCESS_MODE": "disabled"},
            409,
        ),
        (
            "aws-identity-center",
            {"permission_set": "Scanner", "discovery_enabled": "yes"},
            {},
            422,
        ),
        (
            "aws-identity-center",
            {"permission_set": "Scanner", "discovery_enabled": True},
            {"AWS_SSO_DISCOVERY_MODE": "disabled"},
            409,
        ),
    ],
)
def test_rejected_settings_request_preserves_all_prior_values(path, body, settings, status):
    c = client(**settings)
    repo = c.app.state.repo
    before = deepcopy(repo.installation_settings)
    response = c.put(f"/api/v1/settings/{path}", json=body, headers=auth())
    assert response.status_code == status
    assert repo.installation_settings == before


@pytest.mark.parametrize("finished", [False, True])
def test_connection_history_handles_pending_and_finished_jobs(finished):
    c = client()
    repo = c.app.state.repo
    connection = repo.create_connection(Connection(provider="github", name="synthetic"))
    job = repo.enqueue_job(ScanJob(kind="github", connection_id=connection.id))
    if finished:
        repo.complete_job(job.id, objects=0, findings=0)
    response = c.get(f"/api/v1/source-connections/{connection.id}/blast-radius", headers=auth())
    assert response.status_code == 200
    body = response.json()
    assert body["scan_count"] == 1
    if finished:
        assert body["first_scan_at"] == body["last_scan_at"] == job.finished_at.isoformat()
        assert datetime.fromisoformat(body["last_scan_at"]) <= datetime.now(UTC)
    else:
        assert body["first_scan_at"] is None and body["last_scan_at"] is None


@pytest.mark.parametrize("storage", ["memory", "sqlite"])
@pytest.mark.parametrize("action", ["cancel", "revoke"])
def test_stopping_connection_work_preserves_audit_history(storage, action):
    from cremore.db.repository import InMemoryRepository
    from cremore.db.sql import SqlRepository, create_all, make_engine

    engine = make_engine("sqlite:///:memory:") if storage == "sqlite" else None
    if engine is not None:
        create_all(engine)
    repo = SqlRepository(engine) if engine is not None else InMemoryRepository()
    try:
        connection = repo.create_connection(Connection(
            provider="github", name="Synthetic", status="READY",
            config={"owner": "synthetic", "repo": "app"}))
        c = client(repo)
        base = f"/api/v1/source-connections/{connection.id}"
        queued = c.post(f"{base}/credential/check", headers=auth())
        assert queued.status_code == 202, queued.text
        job_id = queued.json()["id"]
        path = (f"/api/v1/source-scan-jobs/{job_id}/cancel" if action == "cancel"
                else f"{base}/credential/revoke")
        stopped = c.post(path, json={}, headers=auth())
        assert stopped.status_code == 200, stopped.text
        history = c.get(f"{base}/verification-history", headers=auth()).json()["items"]
        assert [(row["stage"], row["job_status"]) for row in history] == [
            ("TERMINAL", "CANCELLED"), ("REQUESTED", "QUEUED")]
        assert history[0]["outcome"] == "NOT_DISPATCHED"
        if action == "revoke":
            [event] = c.get("/api/v1/audit", headers=auth()).json()
            assert (event["from_status"], event["to_status"]) == ("READY", "DISABLED")
        else:
            assert c.post(path, headers=auth()).status_code == 200
            assert c.get(f"{base}/verification-history", headers=auth()).json()["items"] == history
    finally:
        if engine is not None:
            engine.dispose()
