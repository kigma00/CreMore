import hashlib

import pytest

from cremore.collectors import base
from cremore.collectors.base import CollectorError, CursorHistory


@pytest.mark.parametrize("value", [None, "", 1, True, [], {}, b"bytes", "\ud800"])
def test_cursor_admission_rejects_malformed_values_without_echoing_them(value):
    history = CursorHistory()
    with pytest.raises(CollectorError) as caught:
        history.add(value)
    assert str(caught.value) == "SOURCE_CURSOR_INVALID"
    assert history._seen == set() and history._admitted == [0]


@pytest.mark.parametrize("cursor", ["x" * (base.MAX_CURSOR_BYTES + 1), "한" * (base.MAX_CURSOR_BYTES // 3 + 1)])
def test_cursor_length_is_bounded_in_bytes_before_hashing_or_retention(cursor):
    history = CursorHistory()
    with pytest.raises(CollectorError) as caught:
        history.add(cursor)
    assert str(caught.value) == "SOURCE_CURSOR_LIMIT"
    assert history._seen == set() and history._admitted == [0]


def test_only_fixed_size_digests_are_retained_and_cycles_are_detected():
    history = CursorHistory()
    cursor = "synthetic-opaque-cursor"
    history.add(cursor)
    assert history._seen == {hashlib.sha256(cursor.encode()).digest()}
    with pytest.raises(CollectorError, match="SOURCE_PAGINATION_LOOP"):
        history.add(cursor)
    assert history._admitted == [1]


def test_nested_and_sequential_histories_share_one_aggregate_limit(monkeypatch):
    monkeypatch.setattr(base, "MAX_CURSOR_HISTORY", 2)
    owner = CursorHistory()
    parent = owner.fork()
    parent.add("same-cursor-in-an-independent-list")
    child = parent.fork()
    child.add("same-cursor-in-an-independent-list")
    with pytest.raises(CollectorError, match="SOURCE_CURSOR_LIMIT"):
        owner.fork().add("third-stream")
    assert parent._admitted == child._admitted == owner._admitted == [2]
