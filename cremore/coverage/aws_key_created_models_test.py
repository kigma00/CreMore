"""Synthetic sovereign CloudTrail creation events retain creator evidence."""

import pytest
from pydantic import ValidationError

from cremore.coverage.models import Observation


@pytest.mark.parametrize("service,resource", [("iam", "user/builder"), ("sts", "assumed-role/build/run")])
@pytest.mark.parametrize("partition", ["aws", "aws-cn", "aws-us-gov", "aws-eusc"])
def test_key_created_accepts_supported_caller_partition(partition, service, resource):
    caller = f"arn:{partition}:{service}::123456789012:{resource}"
    row = created(caller)
    assert row.session.caller_arn == caller
    assert row.state == "OBSERVED" and not row.last_used_at


def created(caller):
    return Observation(reference="event-history/create", evidence="KEY_CREATED", credential_type="AWS_ACCESS_KEY",
        identifier="AKIA" + "C" * 16, account_id="123456789012", state="OBSERVED",
        created_at="2026-09-25T12:00:00Z", session={"caller_arn": caller, "event_id": "create",
            "recipient_account_id": "123456789012", "event_source": "iam.amazonaws.com",
            "event_name": "CreateAccessKey", "outcome": "SUCCEEDED", "issued_at": "2026-09-25T12:00:00Z"})


@pytest.mark.parametrize("caller", ["arn:aws-invalid:iam::123456789012:user/builder",
                                    "arn:aws-eusc:iam::123:user/builder"])
def test_key_created_still_rejects_malformed_caller(caller):
    with pytest.raises(ValidationError, match="KEY_CREATION_EVENT_REQUIRED"):
        created(caller)
