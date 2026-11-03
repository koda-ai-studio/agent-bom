"""One wording for "better or worse than the last scan" across the CLI, reports and the brief.

Direction compares only what both scans can answer: findings that appeared
against findings no longer detected. Equal counts are "unchanged" even when
individual findings rotated, and a partial scan on either side is flagged
rather than turned into a verdict.
"""

from __future__ import annotations


def trend_direction(new: int, resolved: int) -> str:
    if new > resolved:
        return "worse"
    if resolved > new:
        return "better"
    return "unchanged"


def trend_sentence(new: int, resolved: int, *, partial: bool = False) -> str:
    """``Worse than the last scan: 3 new, 1 resolved.`` (plain text, no markup)."""
    direction = trend_direction(new, resolved)
    head = {
        "worse": "Worse than the last scan",
        "better": "Better than the last scan",
        "unchanged": "Unchanged since the last scan",
    }[direction]
    tail = " Coverage was partial on one side, so counts may be incomplete." if partial else ""
    return f"{head}: {new} new, {resolved} resolved.{tail}"


__all__ = ["trend_direction", "trend_sentence"]
