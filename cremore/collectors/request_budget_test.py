"""Parallel fetch admission shares one bound; waits still check authorization."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from cremore.collectors.base import (
    RequestBudget,
    RequestBudgetExceeded,
    check_request_guard,
    guard_requests,
)


def test_parallel_admission_never_exceeds_shared_limit():
    budget = RequestBudget(limit=37)

    def consume(_):
        try:
            budget.consume()
            return True
        except RequestBudgetExceeded:
            return False

    with ThreadPoolExecutor(max_workers=16) as pool:
        assert sum(pool.map(consume, range(1000))) == 37
    assert budget.used == 37


def test_wait_guard_spends_no_request_and_restores_context():
    budget = RequestBudget(limit=2)

    def revoked():
        raise RuntimeError("REVOKED")

    with guard_requests(revoked):
        with pytest.raises(RuntimeError, match="REVOKED"):
            check_request_guard()
        with pytest.raises(RuntimeError, match="REVOKED"):
            budget.consume()
    assert budget.used == 0
    check_request_guard()
    budget.consume()
    assert budget.used == 1
