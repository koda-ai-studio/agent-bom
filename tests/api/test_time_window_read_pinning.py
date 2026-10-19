"""One aggregate findings read uses one window cutoff across all its pages."""

from __future__ import annotations

import time

from agent_bom.api.finding_read_context import finding_read_scope
from agent_bom.api.time_window import window_since_iso


def test_cutoff_is_pinned_within_one_read_scope() -> None:
    with finding_read_scope():
        first = window_since_iso(90)
        time.sleep(0.002)
        assert window_since_iso(90) == first


def test_cutoff_moves_between_reads() -> None:
    with finding_read_scope():
        first = window_since_iso(90)
    time.sleep(0.002)
    with finding_read_scope():
        assert window_since_iso(90) != first
