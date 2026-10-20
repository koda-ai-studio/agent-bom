"""One rendering of a risk score that may not have been assessed.

``None`` means no scorer ran. It renders as "not assessed" and is never shown,
exported or gated on as a score of 0.
"""

from __future__ import annotations

from typing import Any

NOT_ASSESSED = "not assessed"


def risk_label(score: float | None, *, missing: str = NOT_ASSESSED) -> str:
    """``7.2`` for an assessed score, ``missing`` for an unassessed one."""
    return missing if score is None else f"{score:.1f}"


def assessed_risk_score(blast_radius: Any) -> float:
    """A blast radius's risk score, running the scorer first when none has run yet."""
    score = blast_radius.risk_score
    return float(score) if score is not None else float(blast_radius.calculate_risk_score())
