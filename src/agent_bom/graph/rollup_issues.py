"""Finding-issue basis for roll-up severity counts.

A roll-up scope reports how many open issues it contains, on the same basis as
the overview and the grouped findings list: only finding nodes count (an agent,
server or package carries a rolled-up risk rating, which would restate the
findings beneath it), VEX-suppressed findings are excluded, and occurrences of
one advisory on one package collapse to a single issue. Every other finding is
its own issue, keyed by its occurrence (each recorded finding on a shared node).

Occurrences are counted the same way the finding store counts rows: each
recorded finding id once, and for an advisory node each package holder the
graph models without a recorded id once, so a scope never reports fewer
occurrences than issues.

The index is built once per roll-up so each scope's aggregate is a set union
over its descendants, not a second graph walk.
"""

from __future__ import annotations

from collections import defaultdict

from agent_bom.core.packages import canonical_package_identity
from agent_bom.core.severity import SEVERITY_RANK
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.path_derivation import _node_type_value
from agent_bom.graph.severity_floor import counts_as_finding_node
from agent_bom.graph.types import EntityType, RelationshipType

ISSUE_SEVERITY_BASIS = "issue_groups"
ISSUE_SEVERITY_DEFINITION = (
    "Distinct open finding issues among the scope's descendants: VEX-suppressed findings and rated "
    "non-finding nodes are excluded, and occurrences of one advisory on one package count once."
)

_PACKAGE = EntityType.PACKAGE.value
_VULNERABLE_TO = RelationshipType.VULNERABLE_TO.value


def _package_identity(node: UnifiedNode) -> str:
    attrs = node.attributes or {}
    purl = next(
        (value for key in ("purl", "native_id", "resource_id") if isinstance(value := attrs.get(key), str) and value.startswith("pkg:")),
        None,
    )
    name = node.label or ""
    version = str(attrs.get("version") or "")
    if version and name.endswith(f"@{version}"):
        name = name[: -len(version) - 1]
    elif "@" in name[1:]:
        name = name.rsplit("@", 1)[0]
    ecosystem, package, _version = canonical_package_identity(name, "", str(attrs.get("ecosystem") or ""), purl)
    return f"{ecosystem or 'unknown'}:{package}"


def _vulnerability_id(node: UnifiedNode) -> str:
    attrs = node.attributes or {}
    value = attrs.get("vulnerability_id") or attrs.get("cve_id")
    return str(value).strip().lower() if value else ""


def _occurrence_keys(node: UnifiedNode) -> tuple[str, ...]:
    """One issue per recorded occurrence: a node several assets share counts each finding on it."""
    attrs = node.attributes or {}
    by_asset = attrs.get("finding_ids_by_asset")
    if isinstance(by_asset, dict):
        recorded = sorted({f for ids in by_asset.values() if isinstance(ids, list) for f in ids if isinstance(f, str) and f.strip()})
        if recorded:
            return tuple(f"occurrence:{fid}" for fid in recorded)
    finding_id = attrs.get("finding_id") or attrs.get("canonical_finding_id")
    return (f"occurrence:{finding_id}" if isinstance(finding_id, str) and finding_id.strip() else f"occurrence:{node.id}",)


def _package_parents(graph: UnifiedGraph) -> dict[str, set[str]]:
    parents: dict[str, set[str]] = defaultdict(set)
    for edge in graph.edges:
        rel = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else str(edge.relationship)
        if rel != _VULNERABLE_TO:
            continue
        source = graph.nodes.get(edge.source)
        if source is not None and _node_type_value(source) == _PACKAGE:
            parents[edge.target].add(edge.source)
    return parents


def _issue_keys(graph: UnifiedGraph, node_id: str, node: UnifiedNode, holders: set[str], package_keys: dict[str, str]) -> tuple[str, ...]:
    vulnerability_id = _vulnerability_id(node)
    if not vulnerability_id:
        return _occurrence_keys(node)
    packages = set()
    for parent_id in holders:
        key = package_keys.get(parent_id)
        if key is None:
            key = package_keys[parent_id] = _package_identity(graph.nodes[parent_id])
        packages.add(key)
    if not packages:
        evidence_package = str((node.attributes or {}).get("package_name") or "").strip().lower()
        packages.add(f"unknown:{evidence_package}")
    return tuple(sorted(f"vulnerability:{vulnerability_id}:{package}" for package in packages))


def _holder_occurrence_keys(node_id: str, node: UnifiedNode, holders: set[str]) -> tuple[str, ...]:
    """Recorded finding ids, plus each package holder the graph models without a recorded one."""
    by_asset = (node.attributes or {}).get("finding_ids_by_asset")
    by_asset = by_asset if isinstance(by_asset, dict) else {}
    recorded = {
        f"occurrence:{fid}" for ids in by_asset.values() if isinstance(ids, list) for fid in ids if isinstance(fid, str) and fid.strip()
    }
    unrecorded = {f"occurrence:{node_id}<-{holder}" for holder in holders if holder not in by_asset}
    return tuple(sorted(recorded | unrecorded)) or _occurrence_keys(node)


def build_finding_index(graph: UnifiedGraph) -> dict[str, tuple[tuple[str, ...], tuple[str, ...]]]:
    """Map each open finding node to its (issue keys, occurrence keys)."""
    package_parents = _package_parents(graph)
    index: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {}
    package_keys: dict[str, str] = {}
    for node_id, node in graph.nodes.items():
        if not counts_as_finding_node(node):
            continue
        holders = package_parents.get(node_id, set())
        issues = _issue_keys(graph, node_id, node, holders, package_keys)
        occurrences = _holder_occurrence_keys(node_id, node, holders) if _vulnerability_id(node) else _occurrence_keys(node)
        index[node_id] = (issues, occurrences)
    return index


def build_issue_index(graph: UnifiedGraph) -> dict[str, tuple[str, ...]]:
    """Map each open finding node to the issue key(s) it contributes."""
    return {node_id: issues for node_id, (issues, _occurrences) in build_finding_index(graph).items()}


class IssueTally:
    """Distinct issues seen in one scope, each at its worst observed severity, and their occurrences."""

    __slots__ = ("_occurrences", "_issues")

    def __init__(self) -> None:
        self._occurrences: set[str] = set()
        self._issues: dict[str, str] = {}

    def add(self, node: UnifiedNode, keys: tuple[str, ...], occurrences: tuple[str, ...] = ()) -> None:
        self._occurrences.update(occurrences or (f"occurrence:{node.id}",))
        severity = (node.severity or "").lower()
        rank = SEVERITY_RANK.get(severity, 0)
        for key in keys:
            current = self._issues.get(key)
            if current is None or rank > SEVERITY_RANK.get(current, 0):
                self._issues[key] = severity

    @property
    def occurrences(self) -> int:
        return len(self._occurrences)

    @property
    def issue_count(self) -> int:
        return len(self._issues)

    def severities(self) -> list[str]:
        return list(self._issues.values())
