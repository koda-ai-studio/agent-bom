"""Each CVE's ``ai_risk_context`` describes that CVE only.

The per-package context used to be extended in place inside the per-CVE loop,
so the Nth CVE of a package carried the attack summaries of all N-1 before it:
wrong text on every finding and quadratic memory on a kernel-header package
with thousands of CVEs.
"""

from __future__ import annotations

import asyncio

import pytest

from agent_bom.models import Agent, AgentType, MCPServer, Package, Severity, Vulnerability
from agent_bom.scanners.package_scan import scan_agents


async def _no_lookup(packages: list[Package], **_kwargs: object) -> int:
    return sum(len(pkg.vulnerabilities) for pkg in packages)


def _agent_with(package: Package) -> Agent:
    server = MCPServer(name="image", command="", packages=[package])
    return Agent(name="image:test", agent_type=AgentType.CUSTOM, config_path="image", mcp_servers=[server])


def _vulns(count: int, cwe: str) -> list[Vulnerability]:
    return [Vulnerability(id=f"CVE-2026-{20_000 + i}", summary="issue", severity=Severity.MEDIUM, cwe_ids=[cwe]) for i in range(count)]


@pytest.mark.parametrize("package_name", ["linux-libc-dev", "langchain"])
def test_each_blast_radius_carries_only_its_own_attack_summary(monkeypatch: pytest.MonkeyPatch, package_name: str) -> None:
    monkeypatch.setattr("agent_bom.scanners.scan_packages", _no_lookup)
    package = Package(name=package_name, version="1.0.0", ecosystem="deb" if package_name.startswith("linux") else "pypi")
    package.vulnerabilities = _vulns(50, "CWE-400")

    blast_radii = asyncio.run(scan_agents([_agent_with(package)], show_scan_banner=False))

    assert len(blast_radii) == 50
    contexts = {br.ai_risk_context for br in blast_radii}
    assert len(contexts) == 1, "same CWE, same package: every CVE must get the same bounded context"
    (context,) = contexts
    assert context
    summary = blast_radii[0].attack_vector_summary
    assert summary and context.count(summary) == 1
