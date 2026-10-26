"""Investigation paths from a vulnerable host GPU stack through a GPU workload.

The NVIDIA driver and Container Toolkit run on the node, not in the image, so a
CVE in them is a host-level foothold for every GPU workload scheduled there:
container-escape issues in the toolkit hand the node to the pod. For each GPU
workload agent whose packages include a vulnerable driver / toolkit release,
two chains are walked over recorded edges only:

- workload ``AUTHENTICATES_AS`` its service account ``ASSUMES`` its cloud role;
- workload ``HOSTED_ON`` its GPU node pool ``ASSUMES`` the node identity.

The vulnerability anchors the path (``vuln_ids`` / ``finding_ids``) rather
than being a hop, because the hops follow edge direction. Reachability stays
``unknown``: the topology is recorded, exploitation is not.
"""

from __future__ import annotations

from agent_bom.core.severity import SEVERITY_RANK
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

HOST_STACK_PACKAGES = frozenset({"nvidia-container-toolkit", "nvidia-gpu-display-driver"})
MAX_GPU_PATHS = 200
_R = RelationshipType


def _targets(graph: UnifiedGraph, node_id: str, rel: RelationshipType) -> list[str]:
    return [e.target for e in graph.adjacency.get(node_id, []) if e.traversable and e.relationship == rel and e.target in graph.nodes]


def _sources(graph: UnifiedGraph, node_id: str, rel: RelationshipType) -> list[str]:
    return [e.source for e in graph.reverse_adjacency.get(node_id, []) if e.relationship == rel and e.source in graph.nodes]


def _host_stack_vulns(graph: UnifiedGraph, package: UnifiedNode) -> list[UnifiedNode]:
    vulns = [graph.nodes[v] for v in _targets(graph, package.id, _R.VULNERABLE_TO)]
    return [v for v in vulns if v.entity_type == EntityType.VULNERABILITY]


def _package_name(node: UnifiedNode) -> str:
    return str(node.attributes.get("name") or node.label.split("@", 1)[0])


def _chains(graph: UnifiedGraph, agent_id: str) -> list[tuple[list[str], list[str], str]]:
    chains: list[tuple[list[str], list[str], str]] = []
    for sa in _targets(graph, agent_id, _R.AUTHENTICATES_AS):
        roles = _targets(graph, sa, _R.ASSUMES)
        for role in roles or [""]:
            hops = [agent_id, sa, role] if role else [agent_id, sa]
            rels = [_R.AUTHENTICATES_AS.value, _R.ASSUMES.value][: len(hops) - 1]
            chains.append((hops, rels, "the workload's service account" + (" and the cloud role it assumes" if role else "")))
    for pool in _targets(graph, agent_id, _R.HOSTED_ON):
        if graph.nodes[pool].attributes.get("resource_type") != "gpu_node_pool":
            continue
        for identity in _targets(graph, pool, _R.ASSUMES) or [""]:
            hops = [agent_id, pool, identity] if identity else [agent_id, pool]
            rels = [_R.HOSTED_ON.value, _R.ASSUMES.value][: len(hops) - 1]
            chains.append((hops, rels, "the GPU node pool" + (" and its node identity" if identity else "")))
    return chains


def gpu_host_escape_paths(graph: UnifiedGraph) -> list[AttackPath]:
    """Bounded, deterministic set of host-GPU-stack CVE paths through GPU workloads."""
    paths: list[AttackPath] = []
    for package in sorted(graph.nodes.values(), key=lambda n: n.id):
        if package.entity_type != EntityType.PACKAGE or _package_name(package) not in HOST_STACK_PACKAGES:
            continue
        vulns = _host_stack_vulns(graph, package)
        if not vulns:
            continue
        for server in sorted(_sources(graph, package.id, _R.DEPENDS_ON)):
            for agent_id in sorted(_sources(graph, server, _R.USES)):
                if not graph.nodes[agent_id].label.startswith("gpu-workload:"):
                    continue
                for hops, rels, reach in _chains(graph, agent_id):
                    if len(paths) >= MAX_GPU_PATHS:
                        return paths
                    worst = max(vulns, key=lambda v: SEVERITY_RANK.get(v.severity, 0))
                    paths.append(
                        AttackPath(
                            source=hops[0],
                            target=hops[-1],
                            hops=hops,
                            edges=rels,
                            composite_risk=min(100.0, SEVERITY_RANK.get(worst.severity, 0) * 20.0),
                            summary=(
                                f"{', '.join(v.label for v in vulns)} in host {_package_name(package)} "
                                f"{package.attributes.get('version', '')} on GPU workload {graph.nodes[agent_id].label}; "
                                f"a node-level foothold reaches {reach}. "
                                "Unverified structural candidate: exploitation needs separate evidence."
                            ),
                            vuln_ids=[v.label for v in vulns],
                            finding_ids=[str(v.attributes["finding_id"]) for v in vulns if v.attributes.get("finding_id")],
                            reachability="unknown",
                            reachability_basis=["structural_topology_only"],
                        )
                    )
    return paths
