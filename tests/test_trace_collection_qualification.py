"""Qualification receipts must not turn failure or missing work into green evidence."""

import pytest

from scripts.run_trace_collection_qualification import assess


def attempt(phase, ms, *, ok=True, operation="status"):
    return {"phase": phase, "ms": ms, "ok": ok, "operation": operation}


@pytest.mark.parametrize(
    "rows,reconciled",
    [
        ([], True),
        ([attempt("baseline", 10)], True),
        ([attempt("baseline", 10), attempt("mixed", 10)], False),
        ([attempt("baseline", 10), attempt("mixed", 10), attempt("mixed", 10, ok=False, operation="collect")], True),
        ([attempt("baseline", 10), attempt("mixed", 41)], True),
        ([attempt("baseline", 2000), attempt("mixed", 5001)], True),
    ],
)
def test_missing_failed_unreconciled_or_slow_attempts_fail(rows, reconciled):
    assert not assess(rows, reconciled, p95_limit_ms=5000, slowdown_limit=4)["passed"]


def test_warmup_is_retained_but_excluded_from_baseline():
    rows = [attempt("warmup", 5000), attempt("baseline", 10), attempt("mixed", 30)]
    receipt = assess(rows, True, p95_limit_ms=5000, slowdown_limit=4)
    assert receipt["passed"]
    assert receipt["all_attempts_ms"]["samples"] == 3
    assert receipt["baseline_light_ms"]["p95"] == 10
    assert receipt["light_p95_slowdown"] == 3
