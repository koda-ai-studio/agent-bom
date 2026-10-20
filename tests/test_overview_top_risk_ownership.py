"""A top risk carries its owner and remediation SLA so leadership sees who owns it and when it is due."""

from __future__ import annotations

from agent_bom.api.read_models.posture import OverviewTopRisk
from agent_bom.api.overview_rollup import _finding_top_risk


def _row(**extra):
    return {"cve_id": "CVE-2023-36258", "canonical_id": "occ-1", "package": "langchain@0.0.150", "severity": "critical", **extra}


def test_top_risk_carries_owner_and_sla():
    risk = _finding_top_risk(_row(owner="platform-team", sla_due_at="2026-10-26T00:00:00Z", sla_due_at_source="severity-kev/v1"))
    assert risk["owner"] == "platform-team"
    assert risk["sla_due_at"] == "2026-10-26T00:00:00Z"
    assert risk["sla_due_at_source"] == "severity-kev/v1"
    assert OverviewTopRisk.model_validate(risk).owner == "platform-team"


def test_top_risk_without_ownership_stays_null_not_invented():
    risk = _finding_top_risk(_row())
    assert risk["owner"] is None
    assert risk["sla_due_at"] is None
