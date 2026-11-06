"""The hard rule: AI advice never dismisses or downgrades a protected finding.

Enforced here for every model response and again on every read, because a finding
can turn known-exploited after its assessment was stored.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from agent_bom.finding import Finding, FindingType

_REACHABLE_VERDICTS = frozenset({"confirmed", "likely", "reachable"})
_REASON_LABELS = {
    "kev": "known-exploited (KEV)",
    "malicious_package": "malicious package",
    "reachable_critical": "reachable critical",
}
_DISMISSAL_WORDS = re.compile(
    r"false[\s_-]*positive|benign|not[\s_-]*(?:affected|vulnerable|exploitable|applicable|a[\s_-]*risk)"
    r"|downgrad|safe|ignor|suppress|dismiss|low[\s_-]*risk|no[\s_-]*risk|noise|can[\s_-]*be[\s_-]*closed",
    re.IGNORECASE,
)


def _attributes(finding: Finding | Mapping[str, Any]) -> Mapping[str, Any]:
    if not isinstance(finding, Finding):
        return finding
    return {
        "is_kev": finding.is_kev,
        "is_malicious": finding.is_malicious,
        "finding_type": finding.finding_type.value,
        "severity": finding.severity,
        "effective_severity": finding.effective_severity(),
        "cvss_severity": finding.cvss_severity,
        "reachability": finding.reachability,
        "graph_reachable": finding.graph_reachable,
    }


def protected_reasons(finding: Finding | Mapping[str, Any]) -> tuple[str, ...]:
    """Why AI advice may not dismiss this finding; empty when it may."""
    row = _attributes(finding)
    reasons = []
    if row.get("is_kev") is True:
        reasons.append("kev")
    if row.get("is_malicious") is True or row.get("finding_type") == FindingType.MALICIOUS_PACKAGE.value:
        reasons.append("malicious_package")
    critical = any(str(row.get(key) or "").lower() == "critical" for key in ("severity", "effective_severity", "cvss_severity"))
    reachable = row.get("graph_reachable") is True or str(row.get("reachability") or "").lower() in _REACHABLE_VERDICTS
    if critical and reachable:
        reasons.append("reachable_critical")
    return tuple(reasons)


def proposes_dismissal(fields: Mapping[str, Any]) -> bool:
    """Whether any model-supplied field argues the finding away."""
    return (
        fields.get("verdict") == "likely_false_positive"
        or fields.get("false_positive_likelihood") in {"high", "medium"}
        or bool(_DISMISSAL_WORDS.search(str(fields.get("classification") or "")))
        or bool(_DISMISSAL_WORDS.search(str(fields.get("rationale") or "")))
    )


def enforce_protection(fields: Mapping[str, Any], reasons: tuple[str, ...]) -> dict[str, Any]:
    """Return assessment fields with the hard rule applied for ``reasons``."""
    guarded = dict(fields)
    guarded["protected_reasons"] = list(reasons)
    if not reasons or not proposes_dismissal(fields):
        return guarded
    labels = ", ".join(_REASON_LABELS[reason] for reason in reasons)
    guarded.update(
        verdict="confirmed",
        classification="protected",
        false_positive_likelihood="low",
        guard_applied=True,
        rationale=f"Scanner evidence stands ({labels}). AI advice cannot dismiss or downgrade it, so the model's dismissal was discarded.",
    )
    return guarded


def enforce_tampering(fields: Mapping[str, Any], *, protected: bool) -> dict[str, Any]:
    """Text aimed at the reader cannot earn a verdict: a person decides, and the model's words are dropped."""
    return {
        **fields,
        "verdict": "confirmed" if protected else "needs_review",
        "classification": "tampering_signal",
        "confidence": "low",
        "false_positive_likelihood": "low",
        "guard_applied": True,
        "rationale": "This finding's text has instruction-like wording aimed at the reader. A person should review it.",
        "suggested_controls": [],
    }


def guard_verdict(assessment: Mapping[str, Any], finding: Finding | Mapping[str, Any]) -> dict[str, Any]:
    """Re-apply the hard rule to a stored assessment against the finding as it is now."""
    return enforce_protection(assessment, protected_reasons(finding))
