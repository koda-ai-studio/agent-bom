"""Short-text helpers for the compact console output."""

from __future__ import annotations

import re

# The "(F, 37.0%)" grade/score echo a posture summary carries.
GRADE_ECHO = re.compile(r"\s*\((?:[A-F]|N/A), [\d.]+%\)")


def clip(name: str, limit: int) -> str:
    """Shorten a table cell to ``limit`` characters, marking the cut with an ellipsis."""
    return name if len(name) <= limit else name[: limit - 1] + "…"


def compact_detail(text: str, limit: int = 88) -> str:
    """Trim long explanatory detail so the default output stays one-screen friendly."""
    clean = " ".join(text.split())
    if len(clean) <= limit:
        return clean
    trimmed = clean[: limit - 1].rstrip()
    # Never end on dangling connector punctuation ("… posture — …" cut right
    # after the dash renders as a stray "—…" fragment when the line wraps).
    trimmed = trimmed.rstrip("—·-,:;")
    return trimmed.rstrip() + "…"
