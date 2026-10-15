"""New session facts remain consistent with the approved CloudTrail scope."""

import uuid

import pytest
from pydantic import ValidationError

from cremore.coverage.models import (
    AWSSession,
    Batch,
    ConnectionSpec,
    Contract,
    Observation,
    in_scope,
)
from cremore.coverage.store import CoverageError, CoverageStore
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine

ACCOUNT = "123456789012"
OTHER_ACCOUNT = "210987654321"
KEY_ID = "ASIA" + "A1B2C3D4E5F6G7H8"


def spec(source="event_history"):
    options = {"cloudtrail_source": "s3", "trail_bucket": "synthetic-trail",
               "trail_prefixes": ["approved"]} if source == "s3" else {}
    return ConnectionSpec(name="Synthetic trail", provider="aws_cloudtrail", account_id=ACCOUNT,
                          regions=["us-east-1"], **options)


def event(**session_changes):
    return Observation(reference="event-history/event-1", account_id=ACCOUNT, region="us-east-1",
                       evidence="SESSION_ISSUED", credential_type="AWS_ACCESS_KEY", identifier=KEY_ID,
                       session=AWSSession(**{"event_id": "event-1", "event_name": "AssumeRole",
                                             "recipient_account_id": ACCOUNT, "issuer_account_id": OTHER_ACCOUNT,
                                             **session_changes}))


@pytest.fixture(params=["memory", "sqlite"])
def repo(request):
    if request.param == "memory":
        yield InMemoryRepository()
        return
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    try:
        yield SqlRepository(engine)
    finally:
        engine.dispose()


@pytest.mark.parametrize("changes", [
    {"credential_type": "GITHUB_TOKEN"}, {"credential_type": "AWS_ACCESS_KEY_ID"},
    {"credential_type": "AWS_SESSION_TOKEN"}, {"identifier": "AKIA" + "A1B2C3D4E5F6G7H8"},
    {"identifier": "ASIA"},
])
def test_session_value_fingerprint_requires_a_complete_aws_key_identity(changes):
    row = {"reference": "synthetic", "evidence": "VALUE", "credential_type": "AWS_ACCESS_KEY",
           "identifier": KEY_ID, "fingerprint": "a" * 64, "session_fingerprint": "b" * 64}
    assert Observation(**row).session_fingerprint == "b" * 64
    with pytest.raises(ValidationError, match="SESSION_VALUE_EVIDENCE_REQUIRED"):
        Observation(**(row | changes))


@pytest.mark.parametrize("changes", [
    {"recipient_account_id": OTHER_ACCOUNT}, {"event_id": "different-event"},
    {"evidence_source": "TRAIL_S3"},
])
def test_conflicting_session_metadata_is_rejected_at_the_submission_scope(repo, changes):
    owner_spec = spec()
    item = event(**changes)
    assert not in_scope(owner_spec, item)
    store = CoverageStore(repo)
    connection, token = store.create(owner_spec, "admin")
    run = store.start(connection["id"], connection["revision"], str(uuid.uuid4()),
                      Contract(engine_digest="f" * 64).model_dump(), token=token)
    with pytest.raises(CoverageError, match="OBSERVATION_OUTSIDE_SCOPE"):
        store.append(connection["id"], run["id"], Batch(index=0, items=[item]), token=token)
    snapshot = store.snapshots(connection["id"])[0]
    assert snapshot["items"] == [] and snapshot["item_count"] == 0


def test_cross_account_issuer_and_optional_legacy_session_facts_remain_supported():
    assert in_scope(spec(), event())  # The issuer may differ from the recipient account.
    assert in_scope(spec(), event(recipient_account_id=""))
    legacy = Observation(reference="event-history/legacy", account_id=ACCOUNT, region="us-east-1",
                         evidence="USAGE", credential_type="AWS_ACCESS_KEY", identifier=KEY_ID)
    assert in_scope(spec(), legacy)
    assert Observation(reference="synthetic", evidence="VALUE", credential_type="AWS_ACCESS_KEY",
                       identifier=KEY_ID, fingerprint="a" * 64).session_fingerprint is None


def test_s3_reference_and_session_source_must_agree():
    item = event(evidence_source="TRAIL_S3")
    item.reference = "trail-s3/event-1"
    assert in_scope(spec("s3"), item)
    assert not in_scope(spec(), item)
    item.session.evidence_source = "EVENT_HISTORY"
    assert not in_scope(spec("s3"), item)
