"""The in-process fixed-window limiter behind the platform middleware's 429s."""

from __future__ import annotations

import pytest

from feathers_demo.core.rate_limit import FixedWindowLimiter


class _Clock:
    """A controllable monotonic clock."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_allows_up_to_the_limit_then_refuses() -> None:
    limiter = FixedWindowLimiter(limit=3, window_s=60.0, clock=_Clock())
    assert [limiter.allow("k") for _ in range(4)] == [True, True, True, False]


def test_keys_have_independent_budgets() -> None:
    limiter = FixedWindowLimiter(limit=1, window_s=60.0, clock=_Clock())
    assert limiter.allow("bastion:v_a")
    assert not limiter.allow("bastion:v_a")
    assert limiter.allow("bastion:v_b")


def test_budget_resets_when_the_window_ends() -> None:
    clock = _Clock()
    limiter = FixedWindowLimiter(limit=1, window_s=60.0, clock=clock)
    assert limiter.allow("k")
    clock.now += 59.9
    assert not limiter.allow("k")
    clock.now += 0.1
    assert limiter.allow("k")


def test_memory_is_bounded_by_forgetting_expired_windows() -> None:
    clock = _Clock()
    limiter = FixedWindowLimiter(limit=1, window_s=60.0, clock=clock, max_keys=2)
    limiter.allow("a")
    limiter.allow("b")
    clock.now += 61
    limiter.allow("c")
    assert limiter.tracked_keys == 1


@pytest.mark.parametrize(
    ("limit", "window_s", "max_keys"),
    [(0, 60.0, 10), (1, 0.0, 10), (1, -1.0, 10), (1, 60.0, 0)],
)
def test_rejects_a_limiter_that_could_never_allow(
    limit: int, window_s: float, max_keys: int
) -> None:
    with pytest.raises(ValueError):
        FixedWindowLimiter(limit=limit, window_s=window_s, max_keys=max_keys)
