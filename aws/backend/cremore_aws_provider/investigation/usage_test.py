import datetime as dt
import json

import pytest

from cremore_aws_provider.investigation import usage as usage_module
from cremore_aws_provider.investigation.usage import (
    TECHNIQUES,
    CredentialUsageService,
    classify_events,
    credential_class,
    empty_usage,
    event_from_lookup,
)

NOW = dt.datetime(2026, 9, 13, 12, 0, tzinfo=dt.UTC)


@pytest.fixture(autouse=True)
def no_lookup_wait(monkeypatch):
    monkeypatch.setattr(usage_module, "sleep", lambda seconds: None, raising=False)


@pytest.mark.parametrize("count, expected", [(151, "COMPLETE"), (1000, "COMPLETE"), (1001, "CAPPED")])
def test_lookup_reads_beyond_100_with_fixed_window_and_honest_limit(count, expected, monkeypatch):
    waits = []
    monkeypatch.setattr(usage_module, "sleep", waits.append, raising=False)
    rows = [_entry(str(i), "ListBuckets") for i in range(count)]
    pages = [{"Events": rows[i:i + 50]} for i in range(0, count, 50)]
    trail = CloudTrail({"us-east-1": pages})
    service = CredentialUsageService(lambda region: RegionBound(trail, region), now=lambda: NOW)
    start = NOW - dt.timedelta(days=90)
    result = service._lookup_region("us-east-1", "synthetic-key", start, NOW)
    assert result["coverage"]["status"] == expected
    assert [e["event_id"] for e in result["events"]] == [str(i) for i in range(min(count, 1000))]
    assert all(c["StartTime"] == start and c["EndTime"] == NOW for c in trail.calls)
    assert len(waits) == len(trail.calls) - 1 and all(delay >= 0.5 for delay in waits)
    if expected == "CAPPED":
        assert result["coverage"]["error_code"] == "EVENT_LIMIT_REACHED"
    assert "CloudTrailEvent" not in json.dumps(result) and "NextToken" not in json.dumps(result)


def test_lookup_preserves_events_on_later_failure_and_bounds_saved_bytes(monkeypatch):
    first = _entry("first", "ListBuckets")
    oversized = _entry("large", "ListBuckets")
    oversized["Resources"] = [{"ResourceName": "x" * (2 * 1024 * 1024)}]
    trail = CloudTrail({"us-east-1": [{"Events": [first]}, {"Events": [oversized]}]})
    service = CredentialUsageService(lambda region: RegionBound(trail, region), now=lambda: NOW)
    result = service._lookup_region("us-east-1", "synthetic-key", NOW, NOW)
    assert result["coverage"]["status"] == "CAPPED"
    assert result["coverage"]["error_code"] == "BYTE_LIMIT_REACHED"
    assert [e["event_id"] for e in result["events"]] == ["first"]

    def fail_later(**kwargs):
        if kwargs.get("NextToken"):
            raise AwsErr("AccessDeniedException")
        return {"Events": [first], "NextToken": "next"}

    monkeypatch.setattr(trail, "lookup_events", fail_later)
    result = service._lookup_region("us-east-1", "synthetic-key", NOW, NOW)
    assert result["coverage"]["status"] == "FAILED"
    assert result["coverage"]["error_code"] == "AccessDeniedException"
    assert [e["event_id"] for e in result["events"]] == ["first"]


def test_empty_pages_have_a_separate_bounded_limit():
    trail = CloudTrail({"us-east-1": [{"Events": []} for _ in range(101)]})
    service = CredentialUsageService(lambda region: RegionBound(trail, region), now=lambda: NOW)
    result = service._lookup_region("us-east-1", "synthetic-key", NOW, NOW)
    assert len(trail.calls) == 100
    assert result["coverage"]["status"] == "CAPPED"
    assert result["coverage"]["error_code"] == "PAGE_LIMIT_REACHED"
    assert not result["events"]


@pytest.mark.parametrize("raw", ["{broken", "null", "[]", "42", "{}"])
def test_unavailable_cloudtrail_event_details_do_not_prove_success(raw):
    event = event_from_lookup({"EventId": "synthetic", "CloudTrailEvent": raw}, "us-east-1")
    assert event["outcome"] == "UNKNOWN"


def test_region_limit_and_fallback_cannot_claim_account_wide_completion():
    for ec2 in (EC2(), None):
        trail = CloudTrail({"us-east-1": [{"Events": []}], "ap-northeast-2": [{"Events": []}]})
        service = CredentialUsageService(lambda region, trail=trail: RegionBound(trail, region), ec2, region_limit=1,
                                         now=lambda: NOW)
        result = service.collect("synthetic-key")
        assert result["collection_status"] == "PARTIAL" and result["region_discovery_status"] != "COMPLETE"


def test_cyclic_cloudtrail_pages_terminate_and_preserve_partial_events():
    class Repeating:
        calls = 0

        def lookup_events(self, **kwargs):
            self.calls += 1
            assert self.calls <= 3
            return {"Events": [], "NextToken": "same"}

    client = Repeating()
    service = CredentialUsageService(lambda region: client, now=lambda: NOW)
    result = service._lookup_region("us-east-1", "synthetic-key", NOW, NOW)
    assert client.calls == 2 and result["coverage"]["status"] != "COMPLETE"


def _entry(event_id, name, *, read_only=True, error=None, ip="203.0.113.10", region="us-east-1"):
    raw = {"eventID": event_id, "eventName": name, "eventSource": "s3.amazonaws.com", "awsRegion": region,
           "readOnly": read_only, "sourceIPAddress": ip, "eventCategory": "Management",
           "userIdentity": {"arn": "arn:aws:iam::123456789012:user/ci", "userName": "ci",
                            "sessionContext": {"sessionIssuer": {"arn": "arn:aws:iam::123456789012:role/x"},
                                               "sourceIdentity": "deploy-bot",
                                               "attributes": {"creationDate": "2026-09-13T11:00:00Z"}}}}
    if error:
        raw["errorCode"] = error
    return {"EventId": event_id, "EventName": name, "EventTime": NOW - dt.timedelta(hours=1),
            "EventSource": "s3.amazonaws.com", "Username": "ci",
            "Resources": [{"ResourceType": "AWS::S3::Bucket", "ResourceName": "example-bucket"}],
            "CloudTrailEvent": json.dumps(raw)}


class CloudTrail:
    def __init__(self, pages_by_region):
        self.pages_by_region = pages_by_region
        self.calls = []

    def lookup_events(self, **kwargs):
        region = kwargs.pop("_region")
        self.calls.append(kwargs)
        pages = self.pages_by_region[region]
        token = kwargs.get("NextToken")
        index = int(token) if token else 0
        if isinstance(pages, Exception):
            raise pages
        page = dict(pages[index])
        if index + 1 < len(pages):
            page["NextToken"] = str(index + 1)
        return page


class RegionBound:
    """Per-region client wrapper so the fake can tell regions apart."""

    def __init__(self, trail, region):
        self.trail, self.region = trail, region

    def lookup_events(self, **kwargs):
        return self.trail.lookup_events(_region=self.region, **kwargs)


class EC2:
    def describe_regions(self, AllRegions=False):
        return {"Regions": [{"RegionName": "us-east-1"}, {"RegionName": "eu-west-1"}, {"RegionName": "ap-northeast-2"}]}


class IAM:
    def get_access_key_last_used(self, AccessKeyId):
        return {"AccessKeyLastUsed": {"LastUsedDate": NOW - dt.timedelta(days=2), "ServiceName": "s3", "Region": "us-east-1"}}


class AwsErr(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


def test_event_mapping_is_safe_and_complete():
    event = event_from_lookup(_entry("e1", "GetObject", read_only=True), "us-east-1")
    assert event["access_mode"] == "READ" and event["outcome"] == "SUCCEEDED" and event["event_category"] == "MANAGEMENT"
    assert event["source_address"] == "203.0.113.10" and event["source_address_kind"] == "IPV4"
    assert event["principal_arn"].endswith(":user/ci") and event["session_issuer_arn"].endswith(":role/x")
    assert event["source_identity"] == "deploy-bot" and event["session_created_at"].startswith("2026-09-13T11:00")
    assert event["resources"] == [{"type": "AWS::S3::Bucket", "name": "example-bucket"}]
    denied = event_from_lookup(_entry("e2", "PutObject", read_only=False, error="AccessDenied", ip="ec2.amazonaws.com"), "eu-west-1")
    assert denied["access_mode"] == "WRITE" and denied["outcome"] == "DENIED" and denied["error_code"] == "AccessDenied"
    assert denied["source_address_kind"] == "AWS_INTERNAL"
    garbage = event_from_lookup({"EventId": "x", "CloudTrailEvent": "{not json"}, "us-west-2")
    assert garbage["region"] == "us-west-2" and garbage["access_mode"] == "UNKNOWN"


def test_collect_reports_per_region_coverage_and_partial_status():
    trail = CloudTrail({
        "us-east-1": [{"Events": [_entry("a", "GetObject"), _entry("b", "PutObject", read_only=False)]}],
        "eu-west-1": AwsErr("AccessDeniedException"),
        "ap-northeast-2": [{"Events": [_entry(f"c{i}", "ListBuckets") for i in range(3)]},
                           {"Events": [_entry("d", "ListBuckets")]}],
    })
    service = CredentialUsageService(lambda region: RegionBound(trail, region), EC2(), IAM(),
                                     events_per_region=3, now=lambda: NOW)
    snapshot = service.collect("AKIAZ5X9K2" "MBV7QP3LN6", "arn:aws:iam::123456789012:user/ci")
    assert snapshot["credential_class"] == "LONG_LIVED" and snapshot["region_discovery_status"] == "COMPLETE"
    assert snapshot["regions_discovered"] == 3 and snapshot["regions_failed"] == 1 and snapshot["regions_capped"] == 1
    assert snapshot["collection_status"] == "PARTIAL"
    assert snapshot["events_per_region"] == 3
    by_region = {c["region"]: c for c in snapshot["coverage"]}
    assert by_region["eu-west-1"]["status"] == "FAILED" and by_region["eu-west-1"]["error_code"] == "AccessDeniedException"
    assert by_region["ap-northeast-2"]["status"] == "CAPPED" and by_region["ap-northeast-2"]["events_collected"] == 3
    assert by_region["us-east-1"]["status"] == "COMPLETE" and by_region["us-east-1"]["events_collected"] == 2
    assert len(snapshot["events"]) == 5 and snapshot["window_start"] < snapshot["window_end"]
    # every lookup was filtered by the exact key id inside the 90-day window
    assert all(c["LookupAttributes"] == [{"AttributeKey": "AccessKeyId", "AttributeValue": "AKIAZ5X9K2" "MBV7QP3LN6"}] for c in trail.calls)
    assert snapshot["potential_access"]["collection_status"] == "NOT_COLLECTED"
    assert snapshot["cloudtrail_lake"]["status"] == "NOT_CONFIGURED" and snapshot["scenarios"] == []
    last = service.last_used("AKIAZ5X9K2" "MBV7QP3LN6")
    assert last.service == "s3" and last.region == "us-east-1" and last.at == NOW - dt.timedelta(days=2)


def test_region_discovery_falls_back_when_ec2_is_unavailable():
    class BrokenEC2:
        def describe_regions(self, AllRegions=False):
            raise AwsErr("UnauthorizedOperation")

    trail = CloudTrail({})
    service = CredentialUsageService(lambda region: RegionBound(trail, region), BrokenEC2(), None,
                                     region_limit=2, now=lambda: NOW)
    regions, status, error = service.regions()
    assert status == "FALLBACK" and error == "UnauthorizedOperation" and len(regions) == 2
    assert service.last_used("AKIA").snapshot() == {"status": "NOT_REQUESTED", "observed_at": NOW.isoformat()}


@pytest.mark.parametrize("response,status,error", [
    ({"AccessKeyLastUsed": {"LastUsedDate": NOW, "ServiceName": "s3", "Region": "us-east-1"}}, "AVAILABLE", ""),
    ({"AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"}}, "NO_INFORMATION", ""),
    (AwsErr("AccessDenied"), "DENIED", "AccessDenied"),
    (AwsErr("ThrottlingException"), "FAILED", "ThrottlingException"),
    (AwsErr("NoSuchEntity"), "FAILED", "NoSuchEntity"),
    ({}, "FAILED", "ValueError"),
    ({"AccessKeyLastUsed": {"LastUsedDate": "bad date", "ServiceName": "s3", "Region": "us-east-1"}}, "FAILED", "ValueError"),
    ({"AccessKeyLastUsed": {"LastUsedDate": NOW.replace(tzinfo=None), "ServiceName": "s3", "Region": "us-east-1"}}, "FAILED", "ValueError"),
    (["raw malformed response"], "FAILED", "AttributeError"),
    (AwsErr("unsafe code with raw message"), "FAILED", "AwsErr"),
])
def test_last_used_preserves_status_and_safe_provenance(response, status, error):
    class Client:
        def get_access_key_last_used(self, **kwargs):
            assert kwargs == {"AccessKeyId": "synthetic-key"}
            if isinstance(response, Exception):
                raise response
            return response

    result = CredentialUsageService(lambda _: None, iam_client=Client(), now=lambda: NOW).last_used("synthetic-key")
    assert result.status == status and result.error_code == error and result.observed_at == NOW.isoformat()
    expected = {"status": status, "observed_at": NOW.isoformat()}
    if error:
        expected["error_code"] = error
    if status == "AVAILABLE":
        expected.update(at=NOW.isoformat(), service="s3", region="us-east-1")
    else:
        assert result.at is None
    assert result.snapshot() == expected


@pytest.mark.parametrize("code", ["ExpiredToken", "InvalidClientTokenId"])
def test_last_used_login_failure_still_requires_scanner_login(code):
    from cremore_aws_provider.aws_identity import AwsLoginRequired

    class Client:
        def get_access_key_last_used(self, **_):
            raise AwsErr(code)

    with pytest.raises(AwsLoginRequired):
        CredentialUsageService(lambda _: None, iam_client=Client()).last_used("synthetic-key")


def test_last_used_without_key_does_not_request_iam():
    assert CredentialUsageService(lambda _: None, iam_client=object(), now=lambda: NOW).last_used("").snapshot() == {
        "status": "NOT_REQUESTED", "observed_at": NOW.isoformat(),
    }


def test_empty_usage_and_classes():
    assert credential_class("ASIA000000" "000000000A") == "TEMPORARY_STS" and credential_class("x") == "UNKNOWN"
    assert empty_usage("AKIAZ5X9K2" "MBV7QP3LN6")["collection_status"] == "NOT_COLLECTED"


def test_observed_calls_are_labelled_with_the_technique_they_belong_to():
    snapshot = classify_events({"events": [
        {"event_name": "StopLogging"}, {"event_name": "ListBuckets"},
        {"event_name": "CreateAccessKey"}, {"event_name": "GetObject"},
        {"event_name": "PutMetricData"}, {"event_name": ""}, "not a dict"]})
    assert [e.get("technique_id") if isinstance(e, dict) else e for e in snapshot["events"]] == [
        "T1562.008", "T1619", "T1098.001", "T1530", None, None, "not a dict"]
    counted = snapshot["techniques"]
    # Four of the seven rows match; the rest are left unclassified, not called benign.
    assert counted["classified_events"] == 4 and counted["total_events"] == 7
    assert [row["technique_id"] for row in counted["observed"]] == ["T1098.001", "T1530", "T1562.008", "T1619"]
    assert counted["observed"][0]["technique_name"] == TECHNIQUES["T1098.001"][0]
    # A snapshot saved before the mapping existed is labelled the same way, and one
    # without an event list is returned untouched.
    assert classify_events({"collection_status": "NOT_COLLECTED"}) == {"collection_status": "NOT_COLLECTED"}
    assert classify_events(empty_usage("AKIA"))["techniques"]["total_events"] == 0
    # Every listed event name resolves to exactly one technique.
    names = [name for _label, names in TECHNIQUES.values() for name in names]
    assert len(names) == len(set(names))


@pytest.mark.parametrize("error,expected", [
    ("AccessDenied", "DENIED"), ("AccessDeniedException", "DENIED"),
    ("Client.UnauthorizedOperation", "DENIED"), ("UnauthorizedException", "DENIED"),
    ("VpceAccessDenied", "DENIED"), ("NoSuchEntity", "UNKNOWN"),
    ("ValidationException", "UNKNOWN"), ("ThrottlingException", "UNKNOWN"),
    ("ResourceNotFoundException", "UNKNOWN"),
])
def test_only_authorization_errors_count_as_denied(error, expected):
    from cremore_aws_provider.investigation import usage_pages

    entry = _entry("failed", "GetObject", error=error)
    event = event_from_lookup(entry, "us-east-1")
    assert event["outcome"] == expected and event["error_code"] == error
    trail = CloudTrail({"us-east-1": [{"Events": [entry]}]})
    result = CredentialUsageService(lambda region: RegionBound(trail, region), now=lambda: NOW)._lookup_region(
        "us-east-1", "synthetic-key", NOW, NOW)
    assert result["coverage"]["status"] == "COMPLETE"
    snapshot = usage_pages.start_snapshot("synthetic-key", ["us-east-1"], "COMPLETE", "", NOW.isoformat(), NOW.isoformat())
    usage_pages.add_page(snapshot, 0, [event], None)
    assert usage_pages.finish_view(snapshot)["collection_status"] == "COMPLETE"
    assert snapshot["summary"]["denied"] == (expected == "DENIED")
    assert snapshot["summary"]["services"]["s3"]["denied"] == (expected == "DENIED")
    assert "last_success" not in snapshot["summary"]


@pytest.mark.parametrize("address,kind", [
    ("AWS Internal", "AWS_INTERNAL"), ("ec2.amazonaws.com.cn", "AWS_INTERNAL"),
    ("ec2.amazonaws.com", "AWS_INTERNAL"), ("203.0.113.10", "IPV4"), ("2001:db8::1", "IPV6"),
    ("ec2.amazonaws.com.cn.example.test", "HOSTNAME"), ("notamazonaws.com.cn", "HOSTNAME"),
])
def test_aws_internal_source_addresses_keep_their_kind_in_aggregates(address, kind):
    from cremore_aws_provider.investigation import usage_pages

    event = event_from_lookup(_entry("source", "GetObject", ip=address), "us-east-1")
    assert event["source_address_kind"] == kind
    snapshot = usage_pages.start_snapshot("synthetic-key", ["us-east-1"], "COMPLETE", "", NOW.isoformat(), NOW.isoformat())
    usage_pages.add_page(snapshot, 0, [event], None)
    assert snapshot["summary"]["sources"][address]["kind"] == kind
