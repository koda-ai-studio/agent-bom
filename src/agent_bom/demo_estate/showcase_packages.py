"""The showcase's packages and their CVEs, drawn from the bundled demo inventory.

``agent_bom.demo.DEMO_INVENTORY`` is what the demo scan reads, so it is also
what records which server holds which package. Drawing every recorded holder,
rather than one per package, is what keeps a finding's named servers and agents
on the graph: PyYAML sits in two servers used by two agents, and both chains
exist. ``SHOWCASE_PACKAGES`` only says which advisory each package carries.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agent_bom.demo import DEMO_INVENTORY
from agent_bom.demo_advisories import DEMO_ADVISORIES
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.package_utils import canonical_package_key

NodeFn = Callable[..., str]
EdgeFn = Callable[..., None]

# Advisories with a CISA KEV entry among the showcase CVEs.
_KEV_CVES = frozenset({"CVE-2023-4863"})


def showcase_package_holders() -> dict[tuple[str, str, str], list[str]]:
    """``(name, version, ecosystem)`` -> every server the demo inventory records it in."""
    holders: dict[tuple[str, str, str], set[str]] = {}
    for agent in DEMO_INVENTORY["agents"]:
        for server in agent["mcp_servers"]:
            for package in server["packages"]:
                key = (package["name"], package["version"], package["ecosystem"])
                holders.setdefault(key, set()).add(server["name"])
    return {key: sorted(servers) for key, servers in holders.items()}


def seed_showcase_packages(node: NodeFn, edge: EdgeFn, packages: dict[str, tuple[str, str, str, float]]) -> None:
    """Draw every inventory package under each server that holds it, plus its CVE when it has one."""
    advisory_by_id = {advisory.vuln_id: advisory for advisory in DEMO_ADVISORIES}
    for (name, version, ecosystem), servers in sorted(showcase_package_holders().items()):
        package_id = f"pkg:{canonical_package_key(name, version, ecosystem)}"
        node(package_id, EntityType.PACKAGE, f"{name}@{version}", ecosystem=ecosystem, version=version)
        for server in servers:
            edge(f"server:{server}", package_id, RelationshipType.DEPENDS_ON)
        recorded = packages.get(f"{name}@{version}")
        if recorded is not None:
            _seed_vulnerability(node, edge, package_id, recorded, advisory_by_id)


def _seed_vulnerability(
    node: NodeFn, edge: EdgeFn, package_id: str, recorded: tuple[str, str, str, float], advisory_by_id: dict[str, Any]
) -> None:
    _server, cve, severity, score = recorded
    advisory = advisory_by_id[cve]
    vuln_id = f"vuln:{cve}"
    node(
        vuln_id,
        EntityType.VULNERABILITY,
        cve,
        severity=severity,
        risk_score=score,
        vulnerability_id=cve,
        is_kev=cve in _KEV_CVES,
        summary=advisory.summary,
        cvss_score=advisory.cvss_score,
        fixed_version=advisory.fixed,
        cwe_ids=[advisory.cwe] if advisory.cwe else [],
        reachability="likely",
        reachability_basis=["graph_path"],
        graph_reachable=True,
    )
    edge(package_id, vuln_id, RelationshipType.VULNERABLE_TO)


__all__ = ["seed_showcase_packages", "showcase_package_holders"]
