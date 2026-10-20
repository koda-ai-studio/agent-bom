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
from collections.abc import Container
from dataclasses import dataclass, field

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
    """The node's own occurrence when no asset records one: its finding id, else the node."""
    attrs = node.attributes or {}
    finding_id = attrs.get("finding_id") or attrs.get("canonical_finding_id")
    return (f"occurrence:{finding_id}" if isinstance(finding_id, str) and finding_id.strip() else f"occurrence:{node.id}",)


def _own_finding_id(node: UnifiedNode) -> str:
    attrs = node.attributes or {}
    value = attrs.get("finding_id") or attrs.get("canonical_finding_id")
    return value.strip() if isinstance(value, str) else ""


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


def _recorded_by_asset(node: UnifiedNode) -> dict[str, list[str]]:
    by_asset = (node.attributes or {}).get("finding_ids_by_asset")
    if not isinstance(by_asset, dict):
        return {}
    recorded = {
        str(asset): sorted({fid for fid in ids if isinstance(fid, str) and fid.strip()})
        for asset, ids in by_asset.items()
        if isinstance(ids, list)
    }
    return {asset: ids for asset, ids in recorded.items() if ids}


_Keys = tuple[tuple[str, ...], tuple[str, ...]]


@dataclass(frozen=True, slots=True)
class FindingFacts:
    """One open finding node's issue and occurrence keys, whole and per holding asset.

    ``by_holder`` maps each holder with an open occurrence to its keys;
    ``holders`` also names holders whose every occurrence is suppressed. With
    no holders the node counts whole wherever it is contained.
    """

    issues: tuple[str, ...]
    occurrences: tuple[str, ...]
    by_holder: dict[str, _Keys] = field(default_factory=dict)
    holders: frozenset[str] = frozenset()

    def scoped(self, scope: Container[str] | None) -> _Keys:
        """The keys the holders inside ``scope`` contribute; the whole node for the estate."""
        if scope is None or not self.holders:
            return self.issues, self.occurrences
        if not any(holder in scope for holder in self.holders):
            # Contained through an asset that records none of its occurrences.
            return self.issues, self.occurrences
        held = [keys for holder, keys in self.by_holder.items() if holder in scope]
        return (
            tuple(sorted({key for issues, _ in held for key in issues})),
            tuple(sorted({key for _, occurrences in held for key in occurrences})),
        )


def _whole(by_holder: dict[str, _Keys]) -> _Keys:
    return (
        tuple(sorted({key for issues, _ in by_holder.values() for key in issues})),
        tuple(sorted({key for _, occurrences in by_holder.values() for key in occurrences})),
    )


def _vulnerability_facts(
    graph: UnifiedGraph,
    node: UnifiedNode,
    vulnerability_id: str,
    parents: set[str],
    suppressed: frozenset[str],
    package_keys: dict[str, str],
) -> FindingFacts | None:
    recorded = _recorded_by_asset(node)

    def package_key(holder: str) -> str | None:
        holder_node = graph.nodes.get(holder)
        if holder not in parents and (holder_node is None or _node_type_value(holder_node) != _PACKAGE):
            return None
        if holder not in package_keys:
            package_keys[holder] = _package_identity(holder_node) if holder_node is not None else f"unknown:{holder}"
        return package_keys[holder]

    holders = sorted(set(recorded) | parents)
    keyed = {holder: package_key(holder) for holder in holders}
    fallback_package = str((node.attributes or {}).get("package_name") or "").strip().lower()
    fallback = (f"vulnerability:{vulnerability_id}:unknown:{fallback_package}",)
    any_package = any(keyed.values())
    by_holder: dict[str, _Keys] = {}
    for holder in holders:
        ids = recorded.get(holder)
        if ids is not None:
            open_ids = [fid for fid in ids if fid not in suppressed]
            if not open_ids:
                continue
            occurrences = tuple(f"occurrence:{fid}" for fid in open_ids)
        else:
            occurrences = (f"occurrence:{node.id}<-{holder}",)
        package = keyed[holder]
        issues = (f"vulnerability:{vulnerability_id}:{package}",) if package else (() if any_package else fallback)
        by_holder[holder] = (issues, occurrences)
    if holders:
        if not by_holder:
            return None
        whole_issues, whole_occurrences = _whole(by_holder)
        return FindingFacts(whole_issues or fallback, whole_occurrences, by_holder, frozenset(holders))
    if _own_finding_id(node) in suppressed:
        return None
    return FindingFacts(fallback, _occurrence_keys(node))


def _other_facts(node: UnifiedNode, suppressed: frozenset[str]) -> FindingFacts | None:
    """Every other finding is its own issue per recorded occurrence."""
    recorded = _recorded_by_asset(node)
    if not recorded:
        if _own_finding_id(node) in suppressed:
            return None
        keys = _occurrence_keys(node)
        return FindingFacts(keys, keys)
    by_holder: dict[str, _Keys] = {}
    for holder, ids in recorded.items():
        keys = tuple(f"occurrence:{fid}" for fid in ids if fid not in suppressed)
        if keys:
            by_holder[holder] = (keys, keys)
    if not by_holder:
        return None
    issues, occurrences = _whole(by_holder)
    return FindingFacts(issues, occurrences, by_holder, frozenset(recorded))


def build_finding_index(graph: UnifiedGraph, suppressed: frozenset[str] = frozenset()) -> dict[str, FindingFacts]:
    """Map each open finding node to its issue and occurrence keys, whole and per holder.

    ``suppressed`` names finding occurrences an approved exception suppresses:
    they are not open, so they contribute no occurrence, and a node whose every
    occurrence is suppressed is no open finding at all.
    """
    package_parents = _package_parents(graph)
    index: dict[str, FindingFacts] = {}
    package_keys: dict[str, str] = {}
    for node_id, node in graph.nodes.items():
        if not counts_as_finding_node(node):
            continue
        vulnerability_id = _vulnerability_id(node)
        if vulnerability_id:
            facts = _vulnerability_facts(graph, node, vulnerability_id, package_parents.get(node_id, set()), suppressed, package_keys)
        else:
            facts = _other_facts(node, suppressed)
        if facts is not None:
            index[node_id] = facts
    return index


def build_issue_index(graph: UnifiedGraph) -> dict[str, tuple[str, ...]]:
    """Map each open finding node to the issue key(s) it contributes."""
    return {node_id: facts.issues for node_id, facts in build_finding_index(graph).items()}


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

    def occurrence_keys(self) -> frozenset[str]:
        return frozenset(self._occurrences)

    @property
    def occurrences(self) -> int:
        return len(self._occurrences)

    @property
    def issue_count(self) -> int:
        return len(self._issues)

    def severities(self) -> list[str]:
        return list(self._issues.values())
