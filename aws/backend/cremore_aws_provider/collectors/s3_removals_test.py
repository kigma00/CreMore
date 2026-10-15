"""A resumed S3 listing run to its end checks the watched keys at or before its cursor with HEAD
(S3Collector.confirm_before_start): only a 404 confirms one missing, within a cap and what the budget leaves."""

import io
from datetime import UTC, datetime

import pytest

from cremore.collectors.base import CollectorError, RequestBudget
from cremore_aws_provider.aws_identity import AwsLoginRequired
from cremore_aws_provider.collectors import s3
from cremore_aws_provider.collectors.s3 import S3Collector

MODIFIED = datetime(2020, 1, 1, tzinfo=UTC)


class S3Error(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class Bucket:
    """``objects`` present; a GET or HEAD of a key in ``answers`` raises that answer, of a missing one NoSuchKey/404."""

    def __init__(self, objects, answers=None):
        self.objects, self.answers, self.heads, self.gets = set(objects), dict(answers or {}), [], []

    def list_objects_v2(self, **kw):
        keys = sorted(k for k in self.objects if k.startswith(kw.get("Prefix", "")) and k > kw.get("StartAfter", ""))
        return {"Contents": [{"Key": k, "Size": 1, "ETag": f'"{k}"', "LastModified": MODIFIED} for k in keys],
                "IsTruncated": False}

    def get_object(self, Bucket, Key):
        self.gets.append(Key)
        if Key in self.answers:
            raise self.answers[Key]
        if Key not in self.objects:
            raise S3Error("NoSuchKey")
        return {"Body": io.BytesIO(b"x"), "ContentLength": 1, "ETag": f'"{Key}"', "LastModified": MODIFIED}

    def head_object(self, Bucket, Key):
        assert Bucket == "bucket"
        self.heads.append(Key)
        if Key in self.answers:
            raise self.answers[Key]
        if Key not in self.objects:
            raise S3Error("404")
        return {}


def resumed(bucket, watched, **kwargs):
    collector = S3Collector(bucket, "bucket", prefixes=["a/"], start_after="a/m", watched_keys=watched, lazy=True,
                            **kwargs)
    list(collector.collect())
    return collector


def test_only_a_404_confirms_a_key_before_the_cursor_missing():
    answers = {"a/b-denied": S3Error("403"), "a/c-access": S3Error("AccessDenied"), "a/d-throttled": S3Error("SlowDown"),
               "a/e-unknown": RuntimeError("connection reset"), "a/f-nosuchkey": S3Error("NoSuchKey"),
               "a/g-notfound": S3Error("NotFound")}
    watched = ["a/a-gone", *answers, "a/h-kept"]
    budget = RequestBudget(100)
    collector = resumed(Bucket({"a/h-kept", "a/z"}, answers), watched, request_budget=budget)
    assert collector.unseen_before_start == watched
    collector.confirm_before_start("run")
    assert sorted(collector.client.heads) == watched and collector.unseen_before_start == []  # each once
    assert collector.confirmed_missing_keys == {"a/a-gone", "a/f-nosuchkey", "a/g-notfound"}
    # Every HEAD is charged: one listing, then the checks. None is a failed or skipped object.
    assert budget.used == collector.requests == 1 + len(watched)
    assert (collector.failed_objects, collector.skipped_archived, collector.failed_keys) == (0, 0, set())


@pytest.mark.parametrize("retry_before_start", [True, False])
def test_checks_skip_keys_out_of_scope_after_the_cursor_or_read_again_and_put_failures_last(retry_before_start):
    """Watched keys outside the approved prefixes, under an excluded one or after the cursor are never checked; earlier
    failures read again in this attempt are not either, while those not read again are, after the other keys."""
    bucket = Bucket({"a/n-listed"})
    watched = ["0/outside", "a/b-failed", "a/c-gone", "a/e/excluded", "a/n-listed", "a/z-after"]
    collector = S3Collector(bucket, "bucket", prefixes=["a/"], excluded_prefixes=["a/e/"], start_after="a/m",
                            watched_keys=watched, failed_keys=["a/b-failed"], lazy=True)
    collector.retry_before_start = retry_before_start
    list(collector.collect())
    assert bucket.gets == (["a/b-failed"] if retry_before_start else [])
    assert collector.missing_after_start == {"a/z-after"}
    assert collector.unseen_before_start == (["a/c-gone"] if retry_before_start else ["a/b-failed", "a/c-gone"])
    collector.confirm_before_start("run")
    assert bucket.heads == (["a/c-gone"] if retry_before_start else ["a/c-gone", "a/b-failed"])


def test_successive_runs_check_different_windows_and_one_run_always_the_same(monkeypatch):
    """More candidates than the cap: each run checks the open exposures from a place its run id picks, so a run
    resumed again checks the same ones and another run others; earlier failures come after every exposure."""
    exposures, failed = ["a/a", "a/b", "a/c", "a/d", "a/e"], ["a/f-failed", "a/g-failed"]

    def checked(run_id):
        collector = S3Collector(Bucket(set(exposures + failed)), "bucket", prefixes=["a/"], start_after="a/m",
                                watched_keys=exposures + failed, failed_keys=failed, lazy=True)
        collector.retry_before_start = False  # the task read its earlier failures again before
        list(collector.collect())
        collector.confirm_before_start(run_id)
        return collector.client.heads

    monkeypatch.setattr(s3, "MAX_REMOVAL_CHECKS", 2)
    first, again, other = checked("run-1"), checked("run-1"), checked("run-2")
    assert first == again and first != other and len(first) == len(other) == 2
    assert set(first) | set(other) <= set(exposures)
    monkeypatch.setattr(s3, "MAX_REMOVAL_CHECKS", 1000)
    whole = checked("run-2")
    assert sorted(whole[:5]) == exposures and sorted(whole[5:]) == failed


def test_a_get_404_confirms_a_key_missing_and_is_no_failure():
    """The retry pass reads earlier failures at or before the cursor again: a 404 there is the same evidence as a
    HEAD's, so the key is confirmed missing and neither failed nor checked again; a refusal stays a failure."""
    bucket = Bucket({"a/n"}, {"a/b-404": S3Error("404"), "a/d-denied": S3Error("AccessDenied")})
    failed = ["a/a-nosuchkey", "a/b-404", "a/d-denied"]
    collector = S3Collector(bucket, "bucket", prefixes=["a/"], start_after="a/m", failed_keys=failed,
                            watched_keys=failed, lazy=True)
    assert [obj.resource.location for obj in collector.collect()] == ["a/n"]
    assert bucket.gets == failed
    assert collector.confirmed_missing_keys == {"a/a-nosuchkey", "a/b-404"}
    assert (collector.failed_objects, collector.failed_keys) == (1, {"a/d-denied"})
    assert collector.unseen_before_start == []


def test_a_listing_cut_short_or_a_whole_run_checks_nothing():
    bucket = Bucket({"a/n-1", "a/n-2"})
    cut = S3Collector(bucket, "bucket", prefixes=["a/"], start_after="a/m", watched_keys=["a/a-gone"], lazy=True)
    listing = cut.collect()
    next(listing)
    listing.close()
    whole = S3Collector(bucket, "bucket", prefixes=["a/"], watched_keys=["a/a-gone"], lazy=True)
    list(whole.collect())
    for collector in (cut, whole):
        collector.confirm_before_start("run")
    assert bucket.heads == [] and cut.confirmed_missing_keys == whole.confirmed_missing_keys == set()
    assert whole.missing_keys == {"a/a-gone"}  # a whole listing settles it itself


def test_the_cap_and_a_spent_budget_end_the_checks_with_what_they_confirmed(monkeypatch):
    gone = ["a/a", "a/b", "a/c"]
    monkeypatch.setattr(s3, "MAX_REMOVAL_CHECKS", 2)
    capped = resumed(Bucket(set()), gone)
    capped.confirm_before_start("run")
    assert len(capped.client.heads) == 2 and capped.confirmed_missing_keys == set(capped.client.heads) < set(gone)
    monkeypatch.setattr(s3, "MAX_REMOVAL_CHECKS", 1000)
    budget = RequestBudget(3)  # the listing and two checks
    spent = resumed(Bucket(set()), gone, request_budget=budget)
    spent.confirm_before_start("run")  # ends without a stop: the run's listing and reads are complete
    assert len(spent.client.heads) == 2 and spent.confirmed_missing_keys == set(spent.client.heads) < set(gone)
    assert budget.used == spent.requests == 3


def test_a_stop_of_the_run_and_an_expired_sign_in_propagate():
    class Cancelled(RequestBudget):
        def consume(self):
            if self.used >= 1:
                raise CollectorError("RUN_CANCELLED")
            super().consume()

    cancelled = resumed(Bucket(set()), ["a/a"], request_budget=Cancelled(100))
    with pytest.raises(CollectorError, match="RUN_CANCELLED"):
        cancelled.confirm_before_start("run")
    expired = resumed(Bucket(set(), {"a/a": AwsLoginRequired()}), ["a/a"])
    with pytest.raises(AwsLoginRequired):
        expired.confirm_before_start("run")
    assert cancelled.confirmed_missing_keys == expired.confirmed_missing_keys == set()
