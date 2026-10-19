"""Posture dimension scores and which of them the scan could actually assess.

``--no-scan`` is a complete run for what was asked, but no vulnerability was
looked for: grading the vulnerability dimensions as clean would be a false
100. Those dimensions are marked not assessed, contribute nothing, and the
grade is taken over the assessed dimensions only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

VULNERABILITY_LANE_DIMENSIONS = ("vulnerability_posture", "active_exploitation")
NOT_ASSESSED_DETAIL = "Not assessed — vulnerability scanning skipped by request"


@dataclass
class DimensionScore:
    """Score for a single posture dimension."""

    name: str
    score: float  # 0-100
    weight: float  # 0-1
    details: str = ""
    assessed: bool = True

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "score": self.score,
            "weight": self.weight,
            "weighted_score": round(self.score * self.weight, 1) if self.assessed else 0.0,
            "details": self.details,
            "assessed": self.assessed,
        }


def mark_vulnerability_lane_not_assessed(dimensions: Mapping[str, DimensionScore]) -> None:
    """Mark the vulnerability-lane dimensions not assessed: the lane was skipped."""
    for key in VULNERABILITY_LANE_DIMENSIONS:
        dim = dimensions[key]
        dim.score, dim.details, dim.assessed = 0.0, NOT_ASSESSED_DETAIL, False


def assessed_weighted_total(dimensions: Mapping[str, DimensionScore]) -> float:
    """Weighted score over assessed dimensions, renormalised when any were not assessed."""
    assessed = [d for d in dimensions.values() if d.assessed]
    total = sum(d.score * d.weight for d in assessed)
    weight = sum(d.weight for d in assessed)
    if len(assessed) < len(dimensions) and weight > 0:
        total = total / weight
    return round(min(100.0, max(0.0, total)), 1)


def lane_summary(summary: str, *, skipped: bool, grade: str, score: float) -> str:
    """The headline sentence, stating the skipped lane instead of a clean verdict."""
    if not skipped:
        return summary
    return f"Vulnerability posture not assessed (scanning skipped); best-practice/config posture {grade}, {score}%"


__all__ = [
    "DimensionScore",
    "NOT_ASSESSED_DETAIL",
    "VULNERABILITY_LANE_DIMENSIONS",
    "assessed_weighted_total",
    "lane_summary",
    "mark_vulnerability_lane_not_assessed",
]
