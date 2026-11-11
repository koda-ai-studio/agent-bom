"""Deterministic large-report fixtures and an export measurement for the standalone HTML report.

Run ``python -m tests.html_report_scale_fixtures 2000 10000 50000`` (with
``PYTHONPATH=src``) to print export CPU seconds, peak traced memory and file
bytes for each size. Every size is generated from the same rules, so numbers
are comparable across commits on one machine.
"""

from __future__ import annotations

import sys
import time
from datetime import datetime

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import Agent, AgentStatus, AgentType, AIBOMReport, BlastRadius, Package, Severity

_SEVS = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
_ECO = ["npm", "pypi", "go", "cargo", "maven"]
_AGENTS = 12
_PACKAGES = 400
_POLICY_SHARE = 10
# Real advisories routinely carry multi-paragraph text; repeat a sentence to about 1.4 KB.
_ADVISORY = (
    "A crafted request can make the parser read past the end of its buffer and expose memory "
    "or crash the process; deployments that accept untrusted input are affected <script>x</script> & 'quoted'. "
) * 7


def _agent(i: int) -> Agent:
    return Agent(
        name=f"agent-{i % _AGENTS}",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path=f"/srv/agents/agent-{i % _AGENTS}.json",
        mcp_servers=[],
        status=AgentStatus.CONFIGURED,
    )


def _blast(i: int, agents: list[Agent]) -> BlastRadius:
    from agent_bom.models import Vulnerability

    sev = _SEVS[i % 4]
    missing = i % 5
    return BlastRadius(
        package=Package(name=f"pkg-{i % _PACKAGES}", version=f"1.{i % 9}.0", ecosystem=_ECO[i % 5]),
        vulnerability=Vulnerability(
            id=f"CVE-2026-{100000 + i}",
            severity=sev,
            # Mixed missing evidence: no advisory text, no CVSS, no EPSS, no fix, no KEV join.
            summary="" if missing == 0 else f"Finding {i}. {_ADVISORY}",
            cvss_score=None if missing == 1 else round(9.8 - (i % 4) * 2.1, 1),
            epss_score=None if missing == 2 else round((i % 100) / 100, 2),
            fixed_version=None if missing == 3 else f"1.{i % 9}.1",
            is_kev=(i % 15 == 0),
            kev_status=None if missing == 4 else ("listed" if i % 15 == 0 else "not_listed"),
            kev_due_date="2026-12-01" if i % 15 == 0 else None,
            match_confidence_tier="unverified_range" if i % 11 == 0 else None,
        ),
        # Repeated assets: every finding points at one of a few shared agents.
        affected_agents=[agents[i % _AGENTS], agents[(i + 1) % _AGENTS]] if i % 2 else [agents[i % _AGENTS]],
        affected_servers=[],
        exposed_credentials=[f"SECRET_{i % 7}"] if i % 4 == 0 else [],
        exposed_tools=[],
    )


def _policy(i: int) -> Finding:
    return Finding(
        finding_type=FindingType.MCP_BLOCKLIST,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name=f"srv-{i % 50}", asset_type="mcp_server", identifier=f"srv-{i % 50}"),
        severity=str(_SEVS[i % 4]).lower().split(".")[-1],
        title=f"Policy finding {i}",
        description="" if i % 3 == 0 else _ADVISORY,
        evidence={} if i % 4 == 0 else {"rule": f"R{i}", "match": "blocklist", "detail": _ADVISORY[:200]},
    )


def scale_report(total: int) -> tuple[AIBOMReport, list[BlastRadius]]:
    """``total`` findings: one tenth policy findings, the rest CVE findings."""
    policy_count = total // _POLICY_SHARE
    agents = [_agent(i) for i in range(_AGENTS)]
    radii = [_blast(i, agents) for i in range(total - policy_count)]
    report = AIBOMReport(agents=agents, blast_radii=radii, generated_at=datetime(2026, 11, 1, 12), tool_version="0.114.0")
    report.findings = [_policy(i) for i in range(policy_count)]
    return report, radii


def _max_rss_mib() -> float:
    import resource

    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss / 2**20 if sys.platform == "darwin" else rss / 2**10


def measure(total: int) -> dict[str, float]:
    """Export CPU, the process peak-RSS growth during export, and the document size.

    Peak RSS only grows, so run one size per process (``__main__`` does).
    """
    from agent_bom.output.html import to_html

    report, radii = scale_report(total)
    before = _max_rss_mib()
    started = time.process_time()
    html = to_html(report, radii)
    cpu = time.process_time() - started
    return {
        "findings": total,
        "cpu_s": round(cpu, 2),
        "peak_rss_growth_mib": round(_max_rss_mib() - before, 1),
        "bytes": len(html.encode()),
    }


if __name__ == "__main__":
    import json
    import subprocess

    if len(sys.argv) == 3 and sys.argv[1] == "--one":
        print(json.dumps(measure(int(sys.argv[2]))), flush=True)
    else:
        for size in sys.argv[1:] or ["2000"]:
            subprocess.run([sys.executable, "-m", "tests.html_report_scale_fixtures", "--one", size], check=True)
