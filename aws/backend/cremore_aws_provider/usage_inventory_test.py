"""Synthetic CloudTrail events prove collection without using any credentials."""

import gzip
import io
import json
from datetime import UTC, datetime, timedelta

import pytest

from cremore.coverage.collection import CollectionLimit
from cremore.coverage.models import ConnectionSpec
from cremore_aws_provider.usage_inventory import collect_usage

ACCOUNT = "123456789012"
OTHER = "210987654321"
NOW = datetime(2026, 9, 25, 12, tzinfo=UTC)
CALLER = "AKIA" + "A" * 16
TEMP = "ASIA" + "B" * 16
ROLE = f"arn:aws:iam::{OTHER}:role/application"
SESSION = f"arn:aws:sts::{OTHER}:assumed-role/application/build"


def spec(**changes):
    return ConnectionSpec(**{"name": "Sessions", "provider": "aws_cloudtrail", "account_id": ACCOUNT,
                             "regions": ["us-east-1", "eu-west-1"], **changes})


def issuance(**changes):
    return {"eventID": "issue-event", "eventTime": (NOW - timedelta(hours=1)).isoformat(),
            "eventSource": "sts.amazonaws.com", "eventName": "AssumeRole", "awsRegion": "us-east-1",
            "recipientAccountId": ACCOUNT, "userIdentity": {"accessKeyId": CALLER, "arn": f"arn:aws:iam::{ACCOUNT}:user/builder"},
            "requestParameters": {"roleArn": ROLE, "roleSessionName": "build", "sourceIdentity": "developer"},
            "responseElements": {"credentials": {"accessKeyId": TEMP, "expiration": "Sep 25, 2026, 1:00:00 PM",
                                                  "sessionToken": "synthetic-session-secret", "secretAccessKey": "synthetic-secret-value"},
                                 "assumedRoleUser": {"arn": SESSION}}, **changes}


def usage(**changes):
    return {"eventID": "use-event", "eventTime": (NOW - timedelta(minutes=5)).isoformat(),
            "eventSource": "s3.amazonaws.com", "eventName": "GetObject", "eventCategory": "Data",
            "awsRegion": "us-east-1", "recipientAccountId": ACCOUNT,
            "userIdentity": {"accessKeyId": TEMP, "arn": SESSION,
                             "sessionContext": {"sessionIssuer": {"arn": ROLE},
                                                "attributes": {"creationDate": (NOW - timedelta(hours=1)).isoformat()},
                                                "sourceIdentity": "developer"}}, **changes}


class Trail:
    def __init__(self, records):
        self.records = records
        self.calls = []

    def lookup_events(self, **kwargs):
        self.calls.append(kwargs)
        return {"Events": [{"EventId": record["eventID"], "CloudTrailEvent": json.dumps(record)} for record in self.records]}


def data(result):
    return [item for item in result.items if item.evidence != "OPERATION"]


def test_issuance_and_caller_use_are_distinct_and_out_of_order_is_preserved():
    trail = Trail([usage(), issuance(), usage()])
    result = collect_usage(spec(), lambda region: trail if region == "us-east-1" else Trail([]), now=NOW)
    assert result.status == "COMPLETE"
    issued = next(item for item in data(result) if item.evidence == "SESSION_ISSUED")
    assert issued.identifier == TEMP and issued.principal_arn == SESSION
    assert issued.session.issuer_account_id == OTHER and issued.session.recipient_account_id == ACCOUNT
    assert issued.session.caller_access_key_id == CALLER and issued.session.source_identity == "developer"
    assert issued.session.expires_at == "2026-09-25T13:00:00+00:00"
    assert len(data(result)) == 3
    assert {item.identifier for item in data(result) if item.evidence == "USAGE"} == {CALLER, TEMP}
    encoded = json.dumps([item.model_dump() for item in result.items])
    assert "synthetic-session-secret" not in encoded and "synthetic-secret-value" not in encoded
    assert len([item for item in result.items if item.evidence == "OPERATION"]) == 2
    assert trail.calls[0]["StartTime"] == NOW - timedelta(days=7)


def test_missing_response_never_becomes_empty_complete_issuance_inventory():
    trail = Trail([issuance(responseElements=None)])
    result = collect_usage(spec(), lambda _: trail, now=NOW)
    assert result.status == "PARTIAL"
    assert "STS_ISSUANCE_METADATA_NOT_RETURNED" in result.reasons
    assert all(item.evidence != "SESSION_ISSUED" for item in result.items)
    # A repeated error in a different region must not make that region COMPLETE.
    assert all(item.operation.status == "PARTIAL" or item.operation.status == "FAILED"
               for item in result.items if item.evidence == "OPERATION")


@pytest.mark.parametrize("record", [issuance(recipientAccountId=None), issuance(responseElements={"credentials": {"accessKeyId": "invalid-id"}})])
def test_invalid_account_or_issued_identifier_cannot_claim_complete(record):
    result = collect_usage(spec(), lambda _: Trail([record]), now=NOW)
    assert result.status in ("PARTIAL", "FAILED") and result.reasons
    assert not any(item.evidence == "SESSION_ISSUED" for item in result.items)


def test_usage_only_session_has_unknown_expiration_and_foreign_scope_is_ignored():
    records = [usage(), issuance(recipientAccountId=OTHER), issuance(awsRegion="ap-northeast-2"),
               issuance(eventTime=(NOW - timedelta(days=8)).isoformat())]
    result = collect_usage(spec(), lambda _: Trail(records), now=NOW)
    assert result.status == "COMPLETE" and len(data(result)) == 1
    assert data(result)[0].session.expires_at == ""
    assert data(result)[0].evidence == "USAGE"


def test_conflicting_event_id_and_invalid_timestamp_are_incomplete():
    records = [usage(), usage(eventTime=(NOW - timedelta(minutes=4)).isoformat()),
               issuance(eventTime="2026-09-25T10:00:00")]
    result = collect_usage(spec(), lambda _: Trail(records), now=NOW)
    assert result.status == "PARTIAL"
    assert {"CLOUDTRAIL_EVENT_CONFLICT", "EVENT_METADATA_MALFORMED"} <= result.reasons


def test_denied_region_and_budget_report_incomplete_without_overrun():
    def clients(region):
        if region == "eu-west-1":
            raise RuntimeError("private provider error")
        return Trail([usage()])
    result = collect_usage(spec(), clients, now=NOW)
    assert result.status == "PARTIAL"
    failed = next(item for item in result.items if item.evidence == "OPERATION" and item.region == "eu-west-1")
    assert failed.operation.status == "FAILED"
    limited = collect_usage(spec(max_records=1), clients, now=NOW)
    assert len(limited.items) == 1 and limited.status == "PARTIAL"
    assert "OPERATION_REPORT_LIMIT" in limited.reasons
    calls = []
    def revoked():
        raise CollectionLimit("AWS_ACCESS_REVISION_CHANGED")
    result = collect_usage(spec(), lambda r: calls.append(r) or Trail([]), checkpoint=revoked, now=NOW)
    assert result.status == "FAILED" and calls == ["us-east-1"]


class Logs:
    def __init__(self, raw, *, key="approved/trail.json.gz"):
        self.raw, self.key, self.reads, self.bodies = raw, key, [], []

    def list_objects_v2(self, **kwargs):
        assert kwargs["Bucket"] == "company-trail"
        if kwargs.get("Delimiter"):
            assert kwargs["Prefix"] == "approved/"
            return {"Contents": [{"Key": self.key, "Size": len(self.raw)}]}
        assert kwargs["Prefix"] == "approved/"
        return {"Contents": [{"Key": self.key, "Size": len(self.raw)}]}

    def get_object(self, **kwargs):
        self.reads.append(kwargs)
        body = io.BytesIO(self.raw)
        self.bodies.append(body)
        return {"Body": body}


def test_s3_gzip_data_events_and_long_history_are_scoped_and_bounded():
    old = usage(eventTime=(NOW - timedelta(days=120)).isoformat())
    logs = Logs(gzip.compress(json.dumps({"Records": [old, issuance(), usage(recipientAccountId=OTHER)]}).encode()))
    cfg = spec(cloudtrail_source="s3", trail_bucket="company-trail", trail_prefixes=["approved"], window_days=180)
    result = collect_usage(cfg, lambda _: pytest.fail("event history not used"), s3_client=logs, now=NOW)
    assert result.status == "COMPLETE" and len(data(result)) == 3
    assert any(item.session.event_category == "Data" for item in data(result))
    assert all(item.session.evidence_source == "TRAIL_S3" for item in data(result))
    assert logs.bodies[0].closed
    outside = Logs(logs.raw, key="approved-neighbor/trail.json.gz")
    result = collect_usage(cfg, None, s3_client=outside, now=NOW)
    assert result.status == "FAILED" and not outside.reads
    assert "CLOUDTRAIL_LOG_OUTSIDE_SCOPE" in result.reasons


class Bucket:
    """An S3 bucket as list_objects_v2 answers it: prefix, delimiter, StartAfter and pages."""

    def __init__(self, objects, *, page=1000):
        self.objects, self.page, self.listings, self.reads = dict(sorted(objects.items())), page, [], []

    def list_objects_v2(self, *, Bucket, Prefix, MaxKeys=1000, Delimiter=None, StartAfter="", ContinuationToken=None):
        assert Bucket == "company-trail"
        self.listings.append((Prefix, Delimiter, StartAfter))
        entries = []
        for key in self.objects:
            if not key.startswith(Prefix) or key <= StartAfter:
                continue
            rest = key[len(Prefix):]
            entry = ("prefix", Prefix + rest.split(Delimiter, 1)[0] + Delimiter) if Delimiter and Delimiter in rest else ("key", key)
            if entry not in entries:
                entries.append(entry)
        first = int(ContinuationToken or 0)
        chunk = entries[first:first + min(MaxKeys, self.page)]
        response = {"Contents": [{"Key": key, "Size": len(self.objects[key])} for kind, key in chunk if kind == "key"],
                    "CommonPrefixes": [{"Prefix": key} for kind, key in chunk if kind == "prefix"]}
        if first + len(chunk) < len(entries):
            response.update(IsTruncated=True, NextContinuationToken=str(first + len(chunk)))
        return response

    def get_object(self, *, Bucket, Key):
        assert Bucket == "company-trail"
        self.reads.append(Key)
        return {"Body": io.BytesIO(self.objects[Key])}


def log(*records):
    return gzip.compress(json.dumps({"Records": list(records)}).encode())


ORG = "o-exampleorg1"


def test_an_organization_prefix_reads_only_this_accounts_regions_and_window():
    # One organization-wide prefix for every account: each reads its own logs only.
    home = f"AWSLogs/{ORG}/{ACCOUNT}/"
    kept = {home + "CloudTrail/us-east-1/2026/09/25/issue.json.gz": log(issuance()),
            home + "CloudTrail/eu-west-1/2026/09/24/use.json.gz": log(usage(awsRegion="eu-west-1",
                                                                           eventTime=(NOW - timedelta(days=1)).isoformat()))}
    never = {home + "CloudTrail/us-east-1/2025/01/01/old.json.gz": log(issuance(eventID="old")),
             home + "CloudTrail/ap-northeast-2/2026/09/25/other-region.json.gz": log(usage(awsRegion="ap-northeast-2")),
             home + "CloudTrail-Digest/us-east-1/2026/09/25/digest.json.gz": b"not a log",
             home + "CloudTrail-Insight/us-east-1/2026/09/25/insight.json.gz": log({"eventCategory": "Insight"}),
             f"AWSLogs/{ORG}/{OTHER}/CloudTrail/us-east-1/2026/09/25/other-account.json.gz": log(issuance())}
    bucket = Bucket({**kept, **never})
    cfg = spec(cloudtrail_source="s3", trail_bucket="company-trail", trail_prefixes=["AWSLogs"], window_days=7)
    result = collect_usage(cfg, None, s3_client=bucket, now=NOW)
    assert result.status == "COMPLETE", result.reasons
    assert sorted(bucket.reads) == sorted(kept)
    assert {item.evidence for item in data(result)} == {"SESSION_ISSUED", "USAGE"}
    # The history before the window is not even listed: each region is listed from a day before it.
    assert (home + "CloudTrail/us-east-1/", None, home + "CloudTrail/us-east-1/2026/09/17/") in bucket.listings


def test_a_single_account_trail_under_its_own_prefix_is_found_below_awslogs():
    key = f"security/AWSLogs/{ACCOUNT}/CloudTrail/us-east-1/2026/09/25/issue.json.gz"
    bucket = Bucket({key: log(issuance()), f"security/AWSLogs/{OTHER}/CloudTrail/us-east-1/2026/09/25/x.json.gz": log(issuance())})
    cfg = spec(cloudtrail_source="s3", trail_bucket="company-trail", trail_prefixes=["security"])
    result = collect_usage(cfg, None, s3_client=bucket, now=NOW)
    assert result.status == "COMPLETE" and bucket.reads == [key]
    assert {item.evidence for item in data(result)} == {"SESSION_ISSUED", "USAGE"}


def test_long_history_no_longer_exhausts_the_log_object_limit():
    # Three years of daily files; the window needs a week of them.
    home = f"AWSLogs/{ORG}/{ACCOUNT}/CloudTrail/us-east-1/"
    objects = {home + (NOW - timedelta(days=days)).strftime("%Y/%m/%d/") + f"{days}.json.gz": log(issuance(eventID=f"e{days}"))
               for days in range(3 * 365)}
    bucket = Bucket(objects)
    cfg = spec(cloudtrail_source="s3", trail_bucket="company-trail", trail_prefixes=[f"AWSLogs/{ORG}"], window_days=7,
               regions=["us-east-1"], max_records=50)
    result = collect_usage(cfg, None, s3_client=bucket, now=NOW)
    assert result.status == "COMPLETE", result.reasons
    assert len(bucket.reads) == 9  # the window's 8 publication days and the day before
    assert "LOG_OBJECT_LIMIT" not in result.reasons


def test_a_prefix_naming_another_account_or_a_narrower_path_is_respected():
    home = f"AWSLogs/{ORG}/{ACCOUNT}/CloudTrail/"
    bucket = Bucket({home + "us-east-1/2026/09/25/a.json.gz": log(issuance()),
                     home + "eu-west-1/2026/09/25/b.json.gz": log(usage(awsRegion="eu-west-1"))})
    other = spec(cloudtrail_source="s3", trail_bucket="company-trail", trail_prefixes=[f"AWSLogs/{ORG}/{OTHER}"])
    result = collect_usage(other, None, s3_client=bucket, now=NOW)
    assert result.status == "COMPLETE" and not bucket.reads and not bucket.listings
    narrow = spec(cloudtrail_source="s3", trail_bucket="company-trail", trail_prefixes=[home + "eu-west-1"])
    result = collect_usage(narrow, None, s3_client=bucket, now=NOW)
    assert bucket.reads == [home + "eu-west-1/2026/09/25/b.json.gz"] and len(data(result)) == 1


def test_a_directory_named_awslogs_that_is_not_cloudtrails_layout_is_read_whole():
    key = "AWSLogs/archive/2026/issue.json.gz"
    bucket = Bucket({key: log(issuance())})
    cfg = spec(cloudtrail_source="s3", trail_bucket="company-trail", trail_prefixes=["AWSLogs/archive"])
    result = collect_usage(cfg, None, s3_client=bucket, now=NOW)
    assert result.status == "COMPLETE" and bucket.reads == [key]
    assert bucket.listings == [("AWSLogs/archive/", None, "")]
    # Below AWSLogs itself, directories CloudTrail does not write are not its layout either.
    bucket = Bucket({"AWSLogs/exports/issue.json.gz": log(issuance())})
    cfg = spec(cloudtrail_source="s3", trail_bucket="company-trail", trail_prefixes=["AWSLogs"])
    result = collect_usage(cfg, None, s3_client=bucket, now=NOW)
    assert result.status == "COMPLETE" and bucket.reads == ["AWSLogs/exports/issue.json.gz"]


@pytest.mark.parametrize("prefix, loose", [
    ("security", "security/imported.json.gz"),
    ("AWSLogs", "AWSLogs/imported.json.gz"),
    (f"AWSLogs/{ORG}", f"AWSLogs/{ORG}/archive/imported.json.gz"),
    (f"AWSLogs/{ACCOUNT}", f"AWSLogs/{ACCOUNT}/imported.json.gz"),
])
def test_mixed_trail_layout_keeps_imported_log_coverage(prefix, loose):
    canonical = f"{prefix.rstrip('/')}/AWSLogs/{OTHER}/note.txt" if prefix == "security" else f"{prefix}/{OTHER}/note.txt"
    bucket = Bucket({loose: log(usage()), canonical: b"not a log"})
    cfg = spec(cloudtrail_source="s3", trail_bucket="company-trail", trail_prefixes=[prefix])
    result = collect_usage(cfg, None, s3_client=bucket, now=NOW)
    assert result.status == "COMPLETE" and bucket.reads == [loose]
    assert {item.evidence for item in data(result)} == {"USAGE"}


def test_compressed_size_and_malformed_logs_cannot_claim_complete():
    cfg = spec(cloudtrail_source="s3", trail_bucket="company-trail", trail_prefixes=["approved"], max_value_bytes=1024)
    for raw in (gzip.compress(b" " * 2000), gzip.compress(b'{"Records":{}}'), b"bad gzip"):
        result = collect_usage(cfg, None, s3_client=Logs(raw), now=NOW)
        assert result.status == "FAILED" and "CLOUDTRAIL_LOG_READ_FAILED" in result.reasons


def test_scope_contract_requires_explicit_log_prefix_and_history_limit():
    with pytest.raises(ValueError):
        spec(window_days=91)
    with pytest.raises(ValueError):
        spec(cloudtrail_source="s3", trail_bucket="company-trail", trail_prefixes=[""])


@pytest.mark.parametrize("response", [None, [], {}, {"Events": None}, {"Events": {}}, {"Events": ""},
                                     {"Events": [], "NextToken": 0}, {"Events": [], "NextToken": []}])
def test_invalid_event_history_page_cannot_be_reported_as_complete_empty_inventory(response):
    class MalformedTrail:
        def lookup_events(self, **_kwargs):
            return response

    result = collect_usage(spec(regions=["us-east-1"]), lambda _: MalformedTrail(), now=NOW)
    assert result.status == "FAILED"
    assert data(result) == []
    assert result.reasons == {"EVENT_HISTORY_COLLECTION_FAILED"}
    assert result.requests == 1
    assert result.items[0].operation.status == "FAILED"
    assert result.items[0].operation.requests == 1


def test_invalid_later_page_keeps_prior_evidence_and_request_accounting():
    class LaterMalformedTrail:
        def lookup_events(self, **kwargs):
            if "NextToken" in kwargs:
                assert kwargs["NextToken"] == "page-two"
                return {}
            return {"Events": [{"EventId": "use-event", "CloudTrailEvent": json.dumps(usage())}],
                    "NextToken": "page-two"}

    result = collect_usage(spec(regions=["us-east-1"]), lambda _: LaterMalformedTrail(), now=NOW)
    assert result.status == "PARTIAL"
    assert len(data(result)) == 1
    assert result.reasons == {"EVENT_HISTORY_COLLECTION_FAILED"}
    assert result.requests == 2
    operation = next(item.operation for item in result.items if item.evidence == "OPERATION")
    assert operation.status == "PARTIAL" and operation.requests == 2 and operation.records == 1


def test_explicit_empty_events_and_empty_s3_listing_remain_complete():
    result = collect_usage(spec(regions=["us-east-1"]), lambda _: Trail([]), now=NOW)
    assert result.status == "COMPLETE" and not data(result)

    class EmptyLogs:
        def list_objects_v2(self, **_kwargs):
            return {"KeyCount": 0, "IsTruncated": False}

    config = spec(cloudtrail_source="s3", trail_bucket="company-trail", trail_prefixes=["approved"])
    result = collect_usage(config, None, s3_client=EmptyLogs(), now=NOW)
    assert result.status == "COMPLETE" and not data(result)


def test_malformed_event_wrappers_still_consume_the_event_budget():
    class BrokenEvents:
        def lookup_events(self, **_kwargs):
            return {"Events": [None, {"CloudTrailEvent": "{}"}]}

    result = collect_usage(spec(regions=["us-east-1"], max_records=1), lambda _: BrokenEvents(), now=NOW)
    assert result.status == "FAILED"
    assert result.requests == 1
    assert {"EVENT_METADATA_MALFORMED", "EVENT_SCAN_LIMIT"} <= result.reasons
    assert not data(result)


def key_creation(**changes):
    return issuance(eventName="CreateAccessKey", eventSource="iam.amazonaws.com",
        responseElements={"accessKey": {"accessKeyId": "AKIA" + "C" * 16,
            "userName": "robot", "secretAccessKey": "synthetic-created-secret"}}, **changes)


def test_key_creation_uses_response_key_not_caller_and_never_claims_use_or_validity():
    trail = Trail([key_creation(), key_creation()])
    result = collect_usage(spec(regions=["us-east-1"]), lambda _: trail, now=NOW)
    assert result.status == "COMPLETE"
    [created] = [item for item in data(result) if item.evidence == "KEY_CREATED"]
    assert created.identifier == "AKIA" + "C" * 16 and created.identifier != CALLER
    assert created.session.caller_arn == f"arn:aws:iam::{ACCOUNT}:user/builder"
    assert created.state == "OBSERVED" and not created.last_used_at and not created.principal_arn
    assert created.created_at == (NOW - timedelta(hours=1)).isoformat()
    assert [item.identifier for item in data(result) if item.evidence == "USAGE"] == [CALLER]
    assert "synthetic-created-secret" not in json.dumps([item.model_dump() for item in result.items])


@pytest.mark.parametrize("changes", [
    {"errorCode": "AccessDenied"}, {"responseElements": None},
    {"responseElements": {"accessKey": {"accessKeyId": TEMP}}},
    {"userIdentity": {"accessKeyId": CALLER}}, {"recipientAccountId": OTHER},
    {"awsRegion": "ap-northeast-2"}, {"eventTime": (NOW - timedelta(days=91)).isoformat()},
])
def test_creation_requires_successful_scoped_response_and_identified_actor(changes):
    event = key_creation()
    event.update(changes)
    result = collect_usage(spec(regions=["us-east-1"], window_days=90), lambda _: Trail([event]), now=NOW)
    assert not any(item.evidence == "KEY_CREATED" for item in data(result))


def test_cloudtrail_denial_is_distinct_from_an_empty_event_window():
    from botocore.exceptions import ClientError
    class Denied:
        def lookup_events(self, **kwargs):
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "synthetic-secret"}}, "LookupEvents")
    result = collect_usage(spec(regions=["us-east-1"]), lambda _: Denied(), now=NOW)
    assert "EVENT_HISTORY_COLLECTION_DENIED" in result.reasons and result.status == "FAILED"


def test_key_creation_filter_is_sent_to_aws_and_enforced_on_returned_events():
    from cremore.coverage.models import in_scope
    trail = Trail([key_creation(), usage()])
    selected = spec(regions=["us-east-1"], cloudtrail_event_name="CreateAccessKey")
    result = collect_usage(selected, lambda _: trail, now=NOW)
    assert trail.calls[0]["LookupAttributes"] == [{"AttributeKey": "EventName", "AttributeValue": "CreateAccessKey"}]
    assert all(item.session.event_name == "CreateAccessKey" for item in data(result))
    [created] = [item for item in data(result) if item.evidence == "KEY_CREATED"]
    assert in_scope(selected, created)
    other = next(item for item in data(collect_usage(spec(), lambda _: Trail([usage()]), now=NOW)))
    assert not in_scope(selected, other)


@pytest.mark.parametrize("error,expected", [
    ("AccessDenied", "DENIED"), ("Client.UnauthorizedOperation", "DENIED"),
    ("NoSuchEntity", "UNKNOWN"), ("ValidationException", "UNKNOWN"),
    ("ThrottlingException", "UNKNOWN"), ("ResourceNotFoundException", "UNKNOWN"),
])
def test_inventory_only_authorization_errors_are_denied(error, expected):
    result = collect_usage(spec(regions=["us-east-1"]), lambda _: Trail([usage(errorCode=error)]), now=NOW)
    assert result.status == "COMPLETE"
    assert [item.session.outcome for item in data(result)] == [expected]


def test_inventory_paces_each_additional_history_page_per_region():
    timeline = []

    class PagedTrail:
        def __init__(self, region):
            self.region = region

        def lookup_events(self, **kwargs):
            token = kwargs.get("NextToken")
            timeline.append((self.region, token))
            return {"Events": [], **({"NextToken": "next"} if not token else {})}

    result = collect_usage(spec(), PagedTrail, now=NOW, sleep_fn=lambda delay: timeline.append(("sleep", delay)))
    assert result.status == "COMPLETE" and result.requests == 4
    assert timeline == [("us-east-1", None), ("sleep", 0.55), ("us-east-1", "next"),
                        ("eu-west-1", None), ("sleep", 0.55), ("eu-west-1", "next")]


def test_inventory_rechecks_cancellation_after_pacing():
    stopped, calls = False, []

    def pause(_delay):
        nonlocal stopped
        stopped = True

    def checkpoint():
        if stopped:
            raise CollectionLimit("CANCELLED")

    class PagedTrail:
        def lookup_events(self, **kwargs):
            calls.append(kwargs)
            return {"Events": [], "NextToken": "next"}

    result = collect_usage(spec(regions=["us-east-1"]), lambda _: PagedTrail(),
                           now=NOW, checkpoint=checkpoint, sleep_fn=pause)
    assert len(calls) == 1 and result.status == "FAILED"
    assert "CANCELLED" in result.reasons
