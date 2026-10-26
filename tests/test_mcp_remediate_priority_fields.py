"""MCP remediate carries severity and KEV per fix so a plan can rank known-exploited first."""

from __future__ import annotations

import asyncio
import json

from agent_bom.models import Severity
from agent_bom.remediate import generate_package_fixes


def _item(package: str, fix: str | None, *, kev: bool, severity: Severity) -> dict:
    return {
        "package": package,
        "ecosystem": "npm",
        "current": "1.0.0",
        "fix": fix,
        "vulns": [f"CVE-2026-{package}"],
        "agents": ["shop-api"],
        "max_severity": severity,
        "has_kev": kev,
    }


def test_package_fixes_keep_severity_and_kev():
    fixable, unfixable = generate_package_fixes(
        [_item("lodash", "4.18.0", kev=True, severity=Severity.HIGH), _item("event-stream", None, kev=False, severity=Severity.CRITICAL)]
    )
    assert (fixable[0].max_severity, fixable[0].has_kev) == ("high", True)
    assert (unfixable[0]["max_severity"], unfixable[0]["has_kev"]) == ("critical", False)


def test_mcp_remediate_reports_severity_and_kev(monkeypatch):
    import agent_bom.remediate as remediate
    from agent_bom.mcp_tools.sbom import remediate_impl

    fixable, unfixable = generate_package_fixes([_item("lodash", "4.18.0", kev=True, severity=Severity.HIGH)])
    plan = remediate.RemediationPlan(package_fixes=fixable, unfixable=unfixable)
    monkeypatch.setattr(remediate, "generate_remediation", lambda *a, **k: plan)

    async def _pipeline(config_path, image):
        return [object()], [], [], ["project"]

    monkeypatch.setattr("agent_bom.models.AIBOMReport", lambda **kwargs: None)
    data = json.loads(asyncio.run(remediate_impl(config_path="/x", _run_scan_pipeline=_pipeline, _truncate_response=lambda s: s)))
    fix = data["package_fixes"][0]
    assert (fix["max_severity"], fix["has_kev"]) == ("high", True)
