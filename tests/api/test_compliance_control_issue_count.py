"""A control reports occurrences and the distinct issues they collapse to.

``findings`` counts every mapped blast-radius occurrence; the findings view the
drawer links to lists issue groups. ``issue_count`` uses the same group key, so
the drawer can label both units instead of presenting occurrences as issues.
"""

from __future__ import annotations

from agent_bom.api.routes.compliance_routes.scoring import _build_controls


def _row(vuln: str, package: str, agent: str) -> dict:
    return {"vulnerability_id": vuln, "package": package, "ecosystem": "pypi", "severity": "high", "affected_agents": [agent]}


def test_control_counts_occurrences_and_issues_separately() -> None:
    rows = [
        _row("CVE-2023-32681", "requests@2.28.0", "svc-a"),
        _row("CVE-2023-32681", "requests@2.28.0", "svc-b"),
        _row("CVE-2023-32681", "requests@2.28.0", "svc-a"),
        _row("CVE-2024-0001", "urllib3@1.26.0", "svc-a"),
    ]
    [control] = _build_controls({"C-1": rows}, {"C-1": "Patch management"}, "owasp_llm_tags", "code", scan_count=1, latest_scan=None)

    assert control["findings"] == 4
    assert control["issue_count"] == 2


def test_control_without_mapped_rows_has_zero_issues() -> None:
    [control] = _build_controls({}, {"C-1": "Patch management"}, "owasp_llm_tags", "code", scan_count=1, latest_scan=None)

    assert (control["findings"], control["issue_count"]) == (0, 0)
