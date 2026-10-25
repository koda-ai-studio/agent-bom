"""Which parts of the NVD ``lastModified`` window the local DB already holds.

NVD 2.0 has no sort parameter, so a capped run that pages one long window
from ``startIndex=0`` keeps the oldest records and drops the newest — exactly
the day-zero CVEs that matter. The window is therefore walked newest first in
day slices, and the checkpoint records the covered time ranges. A later run
fetches only what is still uncovered (the gap since the last run first, then
any older tail a capped or failed run left), so nothing is fetched twice and
nothing is skipped.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

SLICE = timedelta(days=1)
_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.000"

Interval = tuple[datetime, datetime]


def nvd_ts(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime(_TS_FORMAT)


def parse_nvd_ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def merge(intervals: list[Interval], floor: datetime) -> list[Interval]:
    """Merge overlapping/touching intervals and clip them to ``floor``; oldest first."""
    clipped = sorted((max(start, floor), end) for start, end in intervals if end > floor and end > start)
    merged: list[Interval] = []
    for start, end in clipped:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def uncovered(floor: datetime, now: datetime, covered: list[Interval]) -> list[Interval]:
    """Gaps of ``[floor, now]`` not in ``covered``, newest first."""
    gaps: list[Interval] = []
    cursor = now
    for start, end in sorted(merge(covered, floor), key=lambda item: item[1], reverse=True):
        if end < cursor:
            gaps.append((max(end, floor), cursor))
        cursor = min(cursor, start)
    if cursor > floor:
        gaps.append((floor, cursor))
    return [gap for gap in gaps if gap[1] > gap[0]]


def slices(gaps: list[Interval]) -> list[Interval]:
    """Cut each gap into at most one-day slices, newest first."""
    out: list[Interval] = []
    for start, end in gaps:
        top = end
        while top > start:
            bottom = max(start, top - SLICE)
            out.append((bottom, top))
            top = bottom
    return out


def load_covered(meta: dict[str, Any]) -> list[Interval]:
    """Covered ranges from sync metadata, including a pre-slice clean checkpoint."""
    rows = meta.get("covered")
    if isinstance(rows, list):
        parsed = [(parse_nvd_ts(row[0]), parse_nvd_ts(row[1])) for row in rows if isinstance(row, list) and len(row) == 2]
        return [(start, end) for start, end in parsed if start and end]
    start, end = parse_nvd_ts(meta.get("last_modified_start")), parse_nvd_ts(meta.get("last_modified_end"))
    clean = not meta.get("sync_failed") and not meta.get("sync_truncated")
    return [(start, end)] if clean and start and end and end > start else []


@dataclass(frozen=True)
class Resume:
    """Where a capped run stopped inside one slice."""

    start: datetime
    end: datetime
    index: int

    def to_meta(self) -> dict[str, Any]:
        return {"start": nvd_ts(self.start), "end": nvd_ts(self.end), "index": self.index}


def load_resume(meta: dict[str, Any]) -> Resume | None:
    raw = meta.get("resume")
    if not isinstance(raw, dict):
        return None
    start, end, index = parse_nvd_ts(raw.get("start")), parse_nvd_ts(raw.get("end")), raw.get("index")
    if not (start and end and isinstance(index, int) and index > 0):
        return None
    return Resume(start, end, index)


def plan(floor: datetime, now: datetime, covered: list[Interval], resume: Resume | None) -> list[Interval]:
    """Slices to fetch, newest first; a half-read slice keeps its boundaries so its index stays valid."""
    held = [(resume.start, resume.end)] if resume and resume.end > floor else []
    pieces = slices(uncovered(floor, now, covered + held))
    return sorted(pieces + held, key=lambda item: item[1], reverse=True)


def resume_index(resume: Resume | None, piece: Interval, page_size: int) -> int:
    """Start index for a slice a capped run left half-read.

    Records modified since then leave the slice and shift later ones down, so
    the resume backs up a small overlap rather than risk skipping them.
    """
    if resume is None or (resume.start, resume.end) != piece:
        return 0
    return max(0, resume.index - page_size // 40)
