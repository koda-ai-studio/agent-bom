"""Per-snapshot index behind the grouped full map.

Built once per snapshot from a lean projection — each node's stored type,
label, severity, risk score, ecosystem and resource type, each edge's
endpoints and relationship, and the hops of the snapshot's attack paths — and
then reused by every grouped-map read of that snapshot. It holds:

* each node's group (see :mod:`agent_bom.graph.cluster_classes`) and its
  effective severity: its own, or the worst finding it is directly linked to;
* each group's members ranked by risk, with member counts, per-type counts,
  worst severity and attack-path membership;
* the exact edge count between every pair of groups per relationship, so a
  view answers bundled counts from the aggregation instead of walking edges;
* compact forward and reverse adjacency, so expanding a group touches only the
  edges of the members it shows.
"""

from __future__ import annotations

from array import array
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from agent_bom.graph.cluster_classes import FINDING_TYPES, RISKY_RANK, SEVERITY_WORDS, TIERS, classify, severity_rank

#: A bundle is marked as on an attack path when it carries a hop of one of this many highest-risk paths;
#: with every path counted, an estate whose paths cover every group would mark every bundle and single out none.
TOP_PATHS_FOR_BUNDLES = 10

#: (id, entity_type, label, severity, risk_score, ecosystem, resource_type)
NodeRow = tuple[str, str, str, str, float, str, str]
#: (source_id, target_id, relationship)
EdgeRow = tuple[str, str, str]


@dataclass(slots=True)
class LeafCluster:
    """One group: its identity, ranked members and the summary a card shows."""

    index: int
    key: str
    label: str
    tier: int
    members: list[int] = field(default_factory=list)
    entity_types: Counter[str] = field(default_factory=Counter)
    severity_counts: Counter[str] = field(default_factory=Counter)
    worst_rank: int = 0
    on_path_count: int = 0

    @property
    def count(self) -> int:
        return len(self.members)

    @property
    def risky(self) -> bool:
        return self.on_path_count > 0 or self.worst_rank >= RISKY_RANK

    def rank_key(self) -> tuple[Any, ...]:
        severe = self.severity_counts["critical"] + self.severity_counts["high"]
        return (not self.risky, self.on_path_count == 0, -self.worst_rank, -severe, -self.count, self.tier, self.key)

    def summary(self) -> dict[str, Any]:
        return {
            "cluster_key": self.key,
            "label": self.label,
            "tier": self.tier,
            "tier_label": TIERS[self.tier],
            "member_count": self.count,
            "worst_severity": SEVERITY_WORDS[self.worst_rank],
            "severity_counts": {
                word: self.severity_counts[word] for word in ("critical", "high", "medium", "low") if self.severity_counts[word]
            },
            "on_attack_path_count": self.on_path_count,
            "risky": self.risky,
            "entity_types": dict(sorted(self.entity_types.items())),
        }


class ClusterIndex:
    """Groups, ranked members, group-to-group edge counts and adjacency for one snapshot."""

    def __init__(
        self,
        nodes: Sequence[NodeRow],
        edges: Iterable[EdgeRow],
        path_node_ids: Iterable[str] = (),
        path_pairs: Iterable[tuple[str, str]] = (),
    ) -> None:
        self.ids: list[str] = [row[0] for row in nodes]
        self.id_to_idx: dict[str, int] = {node_id: idx for idx, node_id in enumerate(self.ids)}
        self.labels: list[str] = [str(row[2] or row[0]) for row in nodes]
        self.types: list[str] = [str(row[1] or "") for row in nodes]
        own_rank = [severity_rank(row[3]) for row in nodes]
        self.risk: list[float] = [float(row[4] or 0.0) for row in nodes]
        self.on_path = bytearray(len(self.ids))
        for node_id in path_node_ids:
            idx = self.id_to_idx.get(node_id)
            if idx is not None:
                self.on_path[idx] = 1
        self.clusters: list[LeafCluster] = []
        keys: dict[str, int] = {}
        self.cluster_of = array("i", bytes(4 * len(self.ids)))
        for idx, row in enumerate(nodes):
            group = classify(row[1], row[3], row[5], row[6])
            if group.key not in keys:
                keys[group.key] = len(self.clusters)
                self.clusters.append(LeafCluster(len(self.clusters), group.key, group.label, group.tier))
            self.cluster_of[idx] = keys[group.key]
        self.cluster_by_key = keys
        # Consecutive hops of the stored attack paths, either direction: an edge between them carries a path hop.
        self.path_pairs: set[tuple[int, int]] = set()
        for source, target in path_pairs:
            s, t = self.id_to_idx.get(source), self.id_to_idx.get(target)
            if s is not None and t is not None:
                self.path_pairs.update({(s, t), (t, s)})
        self._index_edges(edges, own_rank)
        self._summarise()

    # ── construction ────────────────────────────────────────────────────

    def _index_edges(self, edges: Iterable[EdgeRow], own_rank: list[int]) -> None:
        rels: dict[str, int] = {}
        self.rel_names: list[str] = []
        self.edge_source = array("i")
        self.edge_target = array("i")
        self.edge_rel = array("i")
        self.dangling_edge_count = 0
        self.eff_rank = list(own_rank)
        finding = [kind in FINDING_TYPES for kind in self.types]
        level0: Counter[tuple[int, int, int]] = Counter()
        path_level0: Counter[tuple[int, int, int]] = Counter()
        self.edge_on_path = bytearray()
        for source, target, relationship in edges:
            s, t = self.id_to_idx.get(source), self.id_to_idx.get(target)
            if s is None or t is None:
                self.dangling_edge_count += 1
                continue
            rel = rels.get(relationship)
            if rel is None:
                rel = rels[relationship] = len(self.rel_names)
                self.rel_names.append(str(relationship))
            self.edge_source.append(s)
            self.edge_target.append(t)
            self.edge_rel.append(rel)
            level0[(self.cluster_of[s], self.cluster_of[t], rel)] += 1
            on_path = (s, t) in self.path_pairs
            self.edge_on_path.append(on_path)
            if on_path:
                path_level0[(self.cluster_of[s], self.cluster_of[t], rel)] += 1
            # A node directly linked to a finding carries that finding's severity.
            if finding[t] and not finding[s] and own_rank[t] > self.eff_rank[s]:
                self.eff_rank[s] = own_rank[t]
            elif finding[s] and not finding[t] and own_rank[s] > self.eff_rank[t]:
                self.eff_rank[t] = own_rank[s]
        self.level0 = dict(level0)
        self.path_level0 = dict(path_level0)
        self.out_start, self.out_edges = _csr(len(self.ids), self.edge_source)
        self.in_start, self.in_edges = _csr(len(self.ids), self.edge_target)

    def _summarise(self) -> None:
        for idx, cluster_idx in enumerate(self.cluster_of):
            cluster = self.clusters[cluster_idx]
            cluster.members.append(idx)
            cluster.entity_types[self.types[idx]] += 1
            rank = self.eff_rank[idx]
            cluster.severity_counts[SEVERITY_WORDS[rank]] += 1
            cluster.worst_rank = max(cluster.worst_rank, rank)
            cluster.on_path_count += self.on_path[idx]
        for cluster in self.clusters:
            cluster.members.sort(key=self.member_rank)
        self.ranked: list[int] = sorted(range(len(self.clusters)), key=lambda c: self.clusters[c].rank_key())

    def member_rank(self, idx: int) -> tuple[Any, ...]:
        return (-self.on_path[idx], -self.eff_rank[idx], -self.risk[idx], self.labels[idx].lower(), self.ids[idx])

    # ── reads ───────────────────────────────────────────────────────────

    @property
    def edge_count(self) -> int:
        return len(self.edge_source)

    def incident_edges(self, idx: int) -> Iterable[int]:
        yield from self.out_edges[self.out_start[idx] : self.out_start[idx + 1]]
        yield from self.in_edges[self.in_start[idx] : self.in_start[idx + 1]]

    # ── builders ────────────────────────────────────────────────────────

    @classmethod
    def from_rows(
        cls,
        nodes: Sequence[NodeRow],
        edges: Iterable[EdgeRow],
        path_node_ids: Iterable[str] = (),
        path_pairs: Iterable[tuple[str, str]] = (),
    ) -> ClusterIndex:
        return cls(nodes, edges, path_node_ids, path_pairs)

    @staticmethod
    def rows_from_graph(graph: Any) -> tuple[list[NodeRow], list[EdgeRow], set[str], set[tuple[str, str]]]:
        """The lean projection a store returns, derived from a loaded graph (stores without a lean read)."""
        nodes: list[NodeRow] = []
        for node in graph.nodes.values():
            attrs = node.attributes or {}
            kind = node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type)
            nodes.append(
                (
                    node.id,
                    kind,
                    node.label,
                    node.severity or "",
                    float(node.risk_score or 0.0),
                    str(attrs.get("ecosystem") or ""),
                    str(attrs.get("resource_type") or ""),
                )
            )
        edges: list[EdgeRow] = [
            (edge.source, edge.target, edge.relationship.value if hasattr(edge.relationship, "value") else str(edge.relationship))
            for edge in graph.edges
        ]
        ranked = sorted(getattr(graph, "attack_paths", []) or [], key=lambda path: -float(getattr(path, "composite_risk", 0.0) or 0.0))
        paths = [list(getattr(path, "hops", []) or []) for path in ranked]
        return nodes, edges, {hop for hops in paths for hop in hops}, hop_pairs(paths[:TOP_PATHS_FOR_BUNDLES])

    @classmethod
    def from_graph(cls, graph: Any) -> ClusterIndex:
        return cls(*cls.rows_from_graph(graph))


def hop_pairs(paths: Iterable[Sequence[str]]) -> set[tuple[str, str]]:
    """Consecutive hops of each path."""
    return {(str(a), str(b)) for hops in paths for a, b in zip(hops, list(hops)[1:])}


def _csr(size: int, endpoint: array) -> tuple[array, array]:
    """Edge indices grouped by one endpoint: ``edges[start[i]:start[i + 1]]`` are node ``i``'s."""
    start = array("i", bytes(4 * (size + 1)))
    for node in endpoint:
        start[node + 1] += 1
    for i in range(size):
        start[i + 1] += start[i]
    cursor = array("i", start[:-1]) if size else array("i")
    edges = array("i", bytes(4 * len(endpoint)))
    for edge_idx, node in enumerate(endpoint):
        edges[cursor[node]] = edge_idx
        cursor[node] += 1
    return start, edges


__all__ = ["TOP_PATHS_FOR_BUNDLES", "ClusterIndex", "EdgeRow", "LeafCluster", "NodeRow", "hop_pairs"]
