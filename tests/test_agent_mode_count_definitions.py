"""Agent-mode counts must say what they count and agree where they overlap."""

from __future__ import annotations

from agent_bom.cli._agent_mode import COUNT_DEFINITIONS, summarize_scan_data


def _report() -> dict:
    blast = [
        {"vulnerability_id": "CVE-1", "severity": "high", "severity_label": "high"},
        {"vulnerability_id": "CVE-1", "severity": "high", "severity_label": "high"},
        {"vulnerability_id": "CVE-2", "severity": "medium", "severity_label": "medium"},
    ]
    findings = [
        {"finding_type": "CVE", "severity": "high", "effective_severity": "high"},
        {"finding_type": "CVE", "severity": "high", "effective_severity": "high"},
        {"finding_type": "CVE", "severity": "medium", "effective_severity": "medium"},
        {"finding_type": "PROMPT_SECURITY", "severity": "high", "effective_severity": "critical"},
    ]
    return {"summary": {"total_vulnerabilities": 2}, "blast_radius": blast, "findings": findings, "agents": []}


def test_every_count_is_defined_and_the_overlapping_ones_agree() -> None:
    data = summarize_scan_data(_report())
    counts = data["counts"]
    assert data["count_definitions"] == COUNT_DEFINITIONS
    for key in ("vulnerabilities", "vulnerability_exposures", "vulnerability_exposures_by_severity", "findings", "findings_by_severity"):
        assert key in counts and key in COUNT_DEFINITIONS
    assert counts["vulnerabilities"] == 2
    assert counts["vulnerability_exposures"] == 3
    assert sum(counts["vulnerability_exposures_by_severity"].values()) == counts["vulnerability_exposures"]
    assert counts["findings"] == 4
    assert sum(counts["findings_by_severity"].values()) == counts["findings"]
    assert counts["findings_by_severity"]["critical"] == 1
    # The legacy name is the same exposure histogram, not a third definition.
    assert counts["severity_counts"] == counts["vulnerability_exposures_by_severity"]
    assert counts["exposure_by_severity"] == counts["vulnerability_exposures_by_severity"]
