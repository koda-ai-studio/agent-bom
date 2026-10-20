"""One rule for a suppressed occurrence's risk: keep the real score, say it is suppressed.

Suppression (an approved exception, an ignore entry, operator VEX) is a
decision about the finding, not a re-assessment of it. The overlay keeps
``risk_score`` as assessed, mirrors it into ``unsuppressed_risk_score`` for
readers of the older contract, and sets ``suppression_state``. Ranked
surfaces order open findings before suppressed ones (:func:`risk_rank_key`)
and open-risk reads ignore suppressed ones (:func:`open_risk_score`); open
counts already exclude them.

Works on blast radii, findings and API rows (attributes or mapping keys).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def _get(item: Any, name: str) -> Any:
    return item.get(name) if isinstance(item, Mapping) else getattr(item, name, None)


def is_suppressed(item: Any) -> bool:
    return _get(item, "suppressed") is True


def mark_blast_radius_suppressed(br: Any, *, suppression_id: str | None, state: str, reason: str | None) -> None:
    """Suppress ``br`` keeping its assessed score (scored first when no scorer has run)."""
    if br.risk_score is None:
        br.calculate_risk_score()
    br.suppressed = True
    br.suppression_id = suppression_id
    br.suppression_state = state
    br.suppression_reason = reason
    br.unsuppressed_risk_score = br.risk_score


def clear_blast_radius_suppression(br: Any) -> None:
    """Lift a suppression; a score zeroed under the old contract is restored from ``unsuppressed_risk_score``."""
    br.suppressed = False
    br.suppression_id = None
    br.suppression_state = None
    br.suppression_reason = None
    if br.unsuppressed_risk_score is not None:
        br.risk_score = br.unsuppressed_risk_score
    br.unsuppressed_risk_score = None


def open_risk_score(item: Any) -> float | None:
    """The risk an open-risk read sees: ``None`` for a suppressed or unassessed occurrence."""
    if is_suppressed(item):
        return None
    score = _get(item, "risk_score")
    return None if score is None else float(score)


def risk_rank_key(item: Any) -> tuple[int, int, float]:
    """Sort key, ascending: open assessed findings by descending risk, then unassessed, then suppressed."""
    if is_suppressed(item):
        score = _get(item, "risk_score")
        return (2, 0, -float(score or 0.0))
    score = _get(item, "risk_score")
    return (0, 0, -float(score)) if score is not None else (1, 0, 0.0)


__all__ = ["clear_blast_radius_suppression", "is_suppressed", "mark_blast_radius_suppressed", "open_risk_score", "risk_rank_key"]
