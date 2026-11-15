"""A blast-radius row without a graph node id still joins the path of its own occurrence."""

from __future__ import annotations

from agent_bom.api.finding_reachability import project_attack_path_reachability
from agent_bom.graph.container import AttackPath

_CVE = "CVE-2026-000001"


def _path(agent: str, package: str) -> AttackPath:
    return AttackPath(
        source=f"agent:{agent}",
        target=f"vuln:{_CVE}",
        hops=[f"agent:{agent}", f"server:{agent}:mcp", f"pkg:npm:{package}@1.0.0", f"vuln:{_CVE}"],
        edges=["uses", "depends_on", "vulnerable_to"],
        vuln_ids=[_CVE],
    )


def _row(package: str = "svc-a", agents: list[str] | None = None) -> dict[str, object]:
    # The shape a pushed legacy ``blast_radius`` item lands in: no node id, no canonical finding id.
    return {"id": f"{_CVE}:{package}", "cve_id": _CVE, "package": package, "affected_agents": agents or ["agent-1"]}


def test_row_without_node_id_is_reached_by_its_own_occurrence_path() -> None:
    rows = [_row()]
    assert project_attack_path_reachability(rows, [_path("agent-1", "svc-a")]) == 1
    assert rows[0]["graph_reachable"] is True
    assert rows[0]["graph_reachable_from_agents"] == ["agent:agent-1"]


def test_scoped_agent_ids_match_the_rows_agent_name() -> None:
    rows = [_row(agents=["project:projA"])]
    assert project_attack_path_reachability(rows, [_path("host-1.cfg-abc:project%3AprojA", "svc-a")]) == 1


def test_a_path_without_a_package_hop_matches_on_the_agent() -> None:
    path = AttackPath(
        source="agent:agent-1",
        target=f"vuln:{_CVE}",
        hops=["agent:agent-1", "server:5d46", f"vuln:{_CVE}"],
        edges=["uses", "vulnerable_to"],
        vuln_ids=[_CVE],
    )
    rows = [_row(agents=["agent-1"]), _row(agents=["agent-2"])]
    assert project_attack_path_reachability(rows, [path]) == 1
    assert rows[0]["graph_reachable"] is True and rows[1].get("graph_reachable") is None


def test_shared_cve_on_another_package_or_agent_does_not_mark_the_row() -> None:
    rows = [_row(package="svc-a", agents=["agent-1"])]
    paths = [_path("agent-1", "svc-b"), _path("agent-2", "svc-a")]
    assert project_attack_path_reachability(rows, paths) == 0
    assert rows[0].get("graph_reachable") is None


def test_row_without_package_or_agents_stays_unknown() -> None:
    rows = [{"id": "x", "cve_id": _CVE}]
    assert project_attack_path_reachability(rows, [_path("agent-1", "svc-a")]) == 0
