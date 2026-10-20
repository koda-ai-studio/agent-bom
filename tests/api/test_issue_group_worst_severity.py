"""An issue's severity is its worst open occurrence, whatever the list order.

The findings page sorts by effective reach while the overview and nav badges
read the same grouping sorted by severity. When a group's severity came from
whichever occurrence the sort put first, one advisory counted as high on the
overview and medium on the findings page.
"""

from __future__ import annotations

import itertools

from agent_bom.api.finding_grouping import _group_occurrence_rows, _grouped_severity_counts


def _occurrence(asset: str, severity: str) -> dict:
    return {
        "id": f"cve-2026-0001:{asset}",
        "finding_id": f"cve-2026-0001:{asset}",
        "vulnerability_id": "CVE-2026-0001",
        "package_name": "requests",
        "package_version": "2.28.0",
        "ecosystem": "pypi",
        "severity": severity,
        "asset_id": asset,
    }


def test_group_severity_is_worst_occurrence_in_every_order() -> None:
    rows = [_occurrence("agent-a", "medium"), _occurrence("agent-b", "high"), _occurrence("agent-c", "low")]
    for ordering in itertools.permutations(rows):
        groups = _group_occurrence_rows(list(ordering))
        assert len(groups) == 1
        assert groups[0]["severity"] == "high"
        assert groups[0]["occurrence_count"] == 3
        assert _grouped_severity_counts(groups)["high"] == 1


def test_group_keeps_first_occurrence_order_and_aggregates() -> None:
    first, worse = _occurrence("agent-a", "medium"), _occurrence("agent-b", "critical")
    other = {**_occurrence("agent-z", "low"), "vulnerability_id": "CVE-2026-0002", "id": "x", "finding_id": "x"}
    groups = _group_occurrence_rows([first, other, worse])
    assert [group["severity"] for group in groups] == ["critical", "low"]
    assert groups[0]["occurrence_count"] == 2
    assert len(groups[0]["_occurrence_rows"]) == 2
