"""A permission check whose job ended without storing an answer reads as a failed check, never as checking."""

from __future__ import annotations

import uuid

import pytest

from cremore.db.repository import InMemoryRepository
from cremore.onboarding import service
from cremore.onboarding.onboarding_test import SETTINGS
from cremore.onboarding.remediation_purpose_test import gitlab


def requested(repo):
    made = service.create(repo, SETTINGS, gitlab(purposes=["inventory"]), "admin")
    queued = service.request_check(repo, made["id"], "admin")
    assert queued["status"] == "CHECKING"
    return made["id"], uuid.UUID(queued["checks"]["job_id"])


@pytest.mark.parametrize("end,code", [
    (lambda repo, job: repo.fail_job(job, "WORKER_LOST: the worker stopped"), "WORKER_LOST"),
    (lambda repo, job: repo.cancel_job(job), "PROVIDER_CHECK_ENDED_WITHOUT_RESULT"),
])
def test_a_check_job_that_ended_without_an_answer_is_a_failed_check(end, code):
    repo = InMemoryRepository()
    connection_id, job = requested(repo)
    assert service.view(repo, service.get(repo, connection_id))["status"] == "CHECKING"  # still queued
    end(repo, job)
    shown = service.view(repo, service.get(repo, connection_id))
    assert shown["status"] == "CHECKED" and shown["checks"]["error"] == code
    assert shown["checks"]["checked_at"] and not shown["checks"]["stale"]
    items = [item for result in shown["checks"]["results"].values() for item in result["items"]]
    assert items and all(item["status"] == "ERROR" and item["detail"] == code for item in items)
    # Asking again queues a new check.
    assert service.request_check(repo, connection_id, "admin")["checks"]["job_id"] != str(job)
