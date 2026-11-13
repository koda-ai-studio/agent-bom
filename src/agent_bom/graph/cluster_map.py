"""The grouped full map: a bounded, risk-first view of one snapshot's graph.

Nodes collapse into groups (:mod:`agent_bom.graph.cluster_classes`); one edge
is drawn between two groups per direction, carrying the exact number of
underlying edges per relationship. Expanding a group shows its top members by
risk plus a "+K more" node that pages; everything not drawn is accounted for:

    drawn bundle counts + hidden bundles + edges inside one group + edges of
    filtered groups == every edge in the snapshot

Counts never come from walking the estate per request. Group-to-group totals
come from the per-snapshot :class:`ClusterIndex`; only the edges of members a
view actually shows are visited, and each one moves its count from the
group-level bundle to the member-level bundle, so the remainder left on the
group (or its "+K more" node) stays exact.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from typing import Any, Optional

from agent_bom.graph.cluster_classes import SEVERITY_WORDS, TIERS
from agent_bom.graph.cluster_index import ClusterIndex, LeafCluster

#: The first frame (nothing expanded) never draws more nodes plus edges than this.
FIRST_FRAME_ELEMENT_BUDGET = 60
#: Groups drawn before the rest fold into one "Other groups" node.
MAX_TOP_CLUSTERS = 18
DEFAULT_MEMBER_LIMIT = 8
MAX_MEMBER_LIMIT = 50
MAX_EXPANDED = 24
#: An expanded view may draw more, but never without bound.
MAX_DRAWN_EDGES = 400
#: The group list beside the map is itself bounded.
MAX_LISTED_CLUSTERS = 500

OTHER_KEY = "other"
GROUP_PREFIX = "@group:"
MORE_PREFIX = "@more:"


def group_id(key: str) -> str:
    return f"{GROUP_PREFIX}{key}"


def more_id(key: str) -> str:
    return f"{MORE_PREFIX}{key}"


class _Frame:
    """Which groups are drawn, folded, hidden or open, and what each node is drawn as."""

    def __init__(
        self, index: ClusterIndex, *, expanded: set[str], pages: Mapping[str, int], risky_only: bool, focus: int | None, limit: int
    ):
        self.index = index
        clusters = index.clusters
        focus_cluster = index.cluster_of[focus] if focus is not None else None
        candidates = [c for c in index.ranked if not risky_only or clusters[c].risky or c == focus_cluster]
        self.hidden = set(range(len(clusters))) - set(candidates)
        fold = len(candidates) > MAX_TOP_CLUSTERS + 1
        self.top = candidates[:MAX_TOP_CLUSTERS] if fold else candidates
        self.folded = candidates[MAX_TOP_CLUSTERS:] if fold else []
        self.listed = candidates
        self.other_open = bool(self.folded) and (group_id(OTHER_KEY) in expanded or focus_cluster in self.folded)
        self.visible = self.top + (self.folded if self.other_open else [])
        visible = set(self.visible)
        self.folded_set = set(self.folded)
        self.open = [c for c in self.visible if group_id(clusters[c].key) in expanded or c == focus_cluster][:MAX_EXPANDED]
        self.shown: dict[int, list[int]] = {}
        self.offsets: dict[int, int] = {}
        for c in self.open:
            cluster = clusters[c]
            offset = max(0, min(int(pages.get(group_id(cluster.key), 0) or 0), max(cluster.count - 1, 0)))
            members = list(cluster.members[offset : offset + limit])
            if focus is not None and c == focus_cluster and focus not in members:
                members.append(focus)
            self.shown[c] = members
            self.offsets[c] = offset
        self.shown_set = {idx for members in self.shown.values() for idx in members}
        self.open_set = set(self.open)
        self._visible = visible

    def vis(self, c: int) -> Optional[str]:
        """What an edge of a group's not-shown member is drawn from."""
        if c in self.hidden:
            return None
        key = self.index.clusters[c].key
        if c in self.open_set:
            return more_id(key)
        if c in self._visible:
            return group_id(key)
        return group_id(OTHER_KEY)

    def rep(self, idx: int) -> Optional[str]:
        if idx in self.shown_set:
            return self.index.ids[idx]
        return self.vis(self.index.cluster_of[idx])


def _bundle_totals(
    frame: _Frame,
) -> tuple[Counter[tuple[Optional[str], Optional[str], int]], Counter[tuple[Optional[str], Optional[str]]], dict[str, int]]:
    index = frame.index
    totals: Counter[tuple[Optional[str], Optional[str], int]] = Counter()
    for (cs, ct, rel), count in index.level0.items():
        totals[(frame.vis(cs), frame.vis(ct), rel)] += count
    # Path hops per drawn pair, moved with their edges exactly like the counts above.
    path: Counter[tuple[Optional[str], Optional[str]]] = Counter()
    for (cs, ct, _rel), count in index.path_level0.items():
        path[(frame.vis(cs), frame.vis(ct))] += count
    seen: set[int] = set()
    for idx in frame.shown_set:
        for edge in index.incident_edges(idx):
            if edge in seen:
                continue
            seen.add(edge)
            s, t, rel = index.edge_source[edge], index.edge_target[edge], index.edge_rel[edge]
            totals[(frame.vis(index.cluster_of[s]), frame.vis(index.cluster_of[t]), rel)] -= 1
            totals[(frame.rep(s), frame.rep(t), rel)] += 1
            if index.edge_on_path[edge]:
                path[(frame.vis(index.cluster_of[s]), frame.vis(index.cluster_of[t]))] -= 1
                path[(frame.rep(s), frame.rep(t))] += 1
    return totals, path, {"edges_scanned": len(seen), "bundles_considered": len(index.level0)}


def _cluster_node(cluster: LeafCluster, *, expanded: bool, shown: int) -> dict[str, Any]:
    return {"id": group_id(cluster.key), "kind": "cluster", **cluster.summary(), "expanded": expanded, "shown_member_count": shown}


def _other_node(clusters: list[LeafCluster]) -> dict[str, Any]:
    types: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    for cluster in clusters:
        types.update(cluster.entity_types)
        severities.update(cluster.severity_counts)
    worst = max((cluster.worst_rank for cluster in clusters), default=0)
    on_path = sum(cluster.on_path_count for cluster in clusters)
    return {
        "id": group_id(OTHER_KEY),
        "kind": "cluster",
        "cluster_key": OTHER_KEY,
        "label": f"Other groups · {len(clusters)}",
        "tier": len(TIERS) - 1,
        "tier_label": TIERS[-1],
        "member_count": sum(cluster.count for cluster in clusters),
        "worst_severity": SEVERITY_WORDS[worst],
        "severity_counts": {word: severities[word] for word in ("critical", "high", "medium", "low") if severities[word]},
        "on_attack_path_count": on_path,
        "risky": any(cluster.risky for cluster in clusters),
        "entity_types": dict(sorted(types.items())),
        "expanded": False,
        "shown_member_count": 0,
        "folded_cluster_count": len(clusters),
    }


def _member_node(index: ClusterIndex, idx: int, cluster: LeafCluster, focus: int | None) -> dict[str, Any]:
    return {
        "id": index.ids[idx],
        "kind": "member",
        "cluster_id": group_id(cluster.key),
        "label": index.labels[idx],
        "entity_type": index.types[idx],
        "severity": SEVERITY_WORDS[index.eff_rank[idx]],
        "risk_score": index.risk[idx],
        "on_attack_path": bool(index.on_path[idx]),
        "focused": idx == focus,
        "tier": cluster.tier,
    }


def _more_node(cluster: LeafCluster, *, shown: int, offset: int, limit: int) -> dict[str, Any]:
    remaining = cluster.count - shown
    next_offset = offset + limit if offset + limit < cluster.count else None
    return {
        "id": more_id(cluster.key),
        "kind": "more",
        "cluster_id": group_id(cluster.key),
        "label": f"+{remaining:,} more",
        "count": remaining,
        "offset": offset,
        "limit": limit,
        "next_offset": next_offset,
        "prev_offset": max(0, offset - limit) if offset > 0 else None,
        "tier": cluster.tier,
    }


def _nodes(frame: _Frame, focus: int | None, limit: int) -> list[dict[str, Any]]:
    index = frame.index
    nodes: list[dict[str, Any]] = []
    for c in frame.visible:
        cluster = index.clusters[c]
        shown = frame.shown.get(c, [])
        nodes.append(_cluster_node(cluster, expanded=c in frame.open_set, shown=len(shown)))
        nodes.extend(_member_node(index, idx, cluster, focus) for idx in shown)
        if c in frame.open_set and cluster.count > len(shown):
            nodes.append(_more_node(cluster, shown=len(shown), offset=frame.offsets[c], limit=limit))
    if frame.folded and not frame.other_open:
        nodes.append(_other_node([index.clusters[c] for c in frame.folded]))
    return nodes


def _select_edges(bundles: list[dict[str, Any]], node_order: list[str], cap: int) -> list[dict[str, Any]]:
    """The bundles to draw: each node's strongest first, so no drawn node looks unconnected, then by priority."""
    ranked = sorted(bundles, key=lambda b: (-b["priority"], -b["count"], b["source"], b["target"]))
    chosen: dict[str, dict[str, Any]] = {}
    by_node: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for bundle in ranked:
        by_node[bundle["source"]].append(bundle)
        by_node[bundle["target"]].append(bundle)
    for node_id in node_order:
        if len(chosen) >= cap:
            break
        if any(b["id"] in chosen for b in by_node.get(node_id, [])):
            continue
        best = next(iter(by_node.get(node_id, [])), None)
        if best is not None:
            chosen[best["id"]] = best
    for bundle in ranked:
        if len(chosen) >= cap:
            break
        chosen.setdefault(bundle["id"], bundle)
    return [b for b in ranked if b["id"] in chosen]


def _bundles(frame: _Frame, risky_ids: set[str], shown_ids: set[str]) -> tuple[list[dict[str, Any]], int, int, dict[str, int]]:
    """Group-pair bundles with their per-relationship counts, plus the edges filtered out and the edges inside one node."""
    totals, path, cost = _bundle_totals(frame)
    pairs: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    filtered = internal = 0
    for (a, b, rel), count in totals.items():
        if count == 0:
            continue
        if count < 0:  # pragma: no cover - the arithmetic above cannot go negative
            raise AssertionError("grouped-map bundle went negative")
        if a is None or b is None:
            filtered += count
        elif a == b:
            internal += count
        else:
            pairs[(a, b)][frame.index.rel_names[rel]] += count
    bundles = [
        {
            "id": f"{a}->{b}",
            "source": a,
            "target": b,
            "count": sum(rels.values()),
            "relationships": [{"relationship": rel, "count": n} for rel, n in sorted(rels.items(), key=lambda item: (-item[1], item[0]))],
            "risky": a in risky_ids and b in risky_ids,
            "on_attack_path": path[(a, b)] > 0,
            "priority": 4 * (path[(a, b)] > 0) + 2 * (a in shown_ids or b in shown_ids) + (a in risky_ids) + (b in risky_ids),
        }
        for (a, b), rels in pairs.items()
    ]
    return bundles, filtered, internal, cost


def cluster_map_view(
    index: ClusterIndex,
    *,
    expanded: Iterable[str] = (),
    pages: Optional[Mapping[str, int]] = None,
    risky_only: bool = False,
    focus: Optional[str] = None,
    member_limit: int = DEFAULT_MEMBER_LIMIT,
) -> dict[str, Any]:
    """One frame of the grouped map; deterministic for the same index and arguments."""
    limit = max(1, min(int(member_limit), MAX_MEMBER_LIMIT))
    focus_idx = index.id_to_idx.get(focus) if focus else None
    frame = _Frame(
        index, expanded=set(list(expanded)[:MAX_EXPANDED]), pages=pages or {}, risky_only=risky_only, focus=focus_idx, limit=limit
    )
    nodes = _nodes(frame, focus_idx, limit)
    node_ids = [node["id"] for node in nodes]
    risky_ids = {
        node["id"] for node in nodes if node.get("risky") or node.get("on_attack_path") or node.get("severity") in ("critical", "high")
    }
    shown_ids = {index.ids[idx] for idx in frame.shown_set}

    bundles, filtered, internal, cost = _bundles(frame, risky_ids, shown_ids)
    first_frame = not frame.open and not frame.other_open
    cap = (
        max(FIRST_FRAME_ELEMENT_BUDGET - len(nodes), 0)
        if first_frame
        else min(MAX_DRAWN_EDGES, max(FIRST_FRAME_ELEMENT_BUDGET - len(nodes), 2 * len(nodes)))
    )
    drawn = _select_edges(bundles, node_ids, cap)
    for bundle in drawn:
        bundle.pop("priority", None)
    drawn_ids = {bundle["id"] for bundle in drawn}
    hidden = [bundle for bundle in bundles if bundle["id"] not in drawn_ids]
    filtered_nodes = sum(index.clusters[c].count for c in frame.hidden)
    focus_cluster = index.clusters[index.cluster_of[focus_idx]] if focus_idx is not None else None
    return {
        "mode": "cluster_map",
        "tiers": list(TIERS),
        "nodes": nodes,
        "edges": drawn,
        "clusters": [
            {"id": group_id(index.clusters[c].key), **index.clusters[c].summary(), "folded": c in frame.folded_set and not frame.other_open}
            for c in frame.listed[:MAX_LISTED_CLUSTERS]
        ],
        "filters": {"risky_only": risky_only, "member_limit": limit},
        "focus": None
        if not focus
        else {"node_id": focus, "cluster_id": group_id(focus_cluster.key) if focus_cluster else None, "found": focus_idx is not None},
        "summary": {
            "total_nodes": len(index.ids),
            "total_edges": index.edge_count,
            "cluster_count": len(index.clusters),
            "listed_cluster_count": min(len(frame.listed), MAX_LISTED_CLUSTERS),
            "visible_cluster_count": len(frame.visible) + (1 if frame.folded and not frame.other_open else 0),
            "folded_cluster_count": 0 if frame.other_open else len(frame.folded),
            "filtered_node_count": filtered_nodes,
            "filtered_edge_count": filtered,
            "internal_edge_count": internal,
            "drawn_bundle_count": len(drawn),
            "hidden_bundle_count": len(hidden),
            "hidden_bundle_edge_count": sum(bundle["count"] for bundle in hidden),
            "element_count": len(nodes) + len(drawn),
            "element_budget": FIRST_FRAME_ELEMENT_BUDGET if first_frame else len(nodes) + cap,
            "dangling_edge_count": index.dangling_edge_count,
        },
        "cost": cost,
    }


__all__ = ["DEFAULT_MEMBER_LIMIT", "FIRST_FRAME_ELEMENT_BUDGET", "MAX_MEMBER_LIMIT", "cluster_map_view", "group_id", "more_id"]
