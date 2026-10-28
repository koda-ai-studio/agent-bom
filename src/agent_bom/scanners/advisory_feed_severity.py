"""Severity of a feed advisory assembled from several local records, by the scan's own policy.

OSV splits one vulnerability across records (the CVE row, a GHSA row, a
distro row). The scan rates a finding from the record it matched: a CVSS
score decides the band and the record's label applies only without one
(``local_advisories._local_vuln_to_vulnerability``). The affected answer
rates the same advisory the same way: a CVSS score on the requested id's own
record first, else a score on an alias record, and only without any score the
worst label the records carry (the label the scan reports when the matched
record is the rated one). A label never outranks a score, so a GHSA copy
labelled ``critical`` cannot inflate a CVE the NVD scored ``high``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from agent_bom.core.severity import Severity, normalize_severity, severity_rank
from agent_bom.scanners.risk import cvss_to_severity, parse_cvss_vector

# Column order of ``advisory_affected._VULN_COLUMNS``.
_SEVERITY, _CVSS_SCORE, _CVSS_VECTOR, _SOURCE = 2, 5, 6, 7
_UNRATED = frozenset({"", "unknown", "none"})


def _column(record: Sequence[Any], index: int) -> Any:
    return record[index] if len(record) > index else None


def _cvss(record: Sequence[Any]) -> float | None:
    score = _column(record, _CVSS_SCORE)
    if isinstance(score, (int, float)) and not isinstance(score, bool):
        return float(score)
    vector = _column(record, _CVSS_VECTOR)
    if isinstance(vector, str) and vector:
        parsed = parse_cvss_vector(vector)
        return float(parsed) if parsed is not None else None
    return None


def _label_source(record: Sequence[Any]) -> str:
    origin = str(_column(record, _SOURCE) or "osv").lower()
    return "osv_database" if origin == "osv" else f"{origin}_advisory"


def _scored(record: Sequence[Any]) -> tuple[str, str, float] | None:
    cvss = _cvss(record)
    if cvss is None:
        return None
    severity = cvss_to_severity(cvss)
    return None if severity in (Severity.UNKNOWN, Severity.NONE) else (severity.value, "cvss", cvss)


def feed_severity(records: Sequence[Sequence[Any]]) -> tuple[str, str | None, float | None]:
    """``(severity, severity_source, cvss_score)`` for the advisory the records describe; ``unknown`` when none rates it."""
    for record in records:
        scored = _scored(record)
        if scored is not None:
            return scored
    labelled = [(normalize_severity(_column(record, _SEVERITY)), _label_source(record)) for record in records]
    rated = [item for item in labelled if item[0] not in _UNRATED]
    if not rated:
        return "unknown", None, None
    severity, source = max(rated, key=lambda item: severity_rank(item[0]))
    return severity, source, None
