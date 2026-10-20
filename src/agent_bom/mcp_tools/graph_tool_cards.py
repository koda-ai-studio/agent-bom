"""Server-card entries for the graph tools agents use to triage: deploy gate, reach, diffs, paths and findings."""

from __future__ import annotations

from typing import Any

GRAPH_AGENT_TOOL_CARDS: list[dict[str, Any]] = [
    {
        "name": "should_i_deploy",
        "description": (
            "Pre-deployment gate: resolves a candidate (package, CVE, resource, or graph node) against the"
            " every ranked path of the latest security-graph snapshot by exact identifier and returns allow/warn/block from"
            " the matched paths' risk and KEV exposure, or not_found when no path names the candidate"
        ),
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "cross_vendor_paths",
        "description": (
            "Attack paths whose source and target nodes are recorded in different vendors, in queue order, with path counts per vendor pair"
        ),
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "graph_reach",
        "description": "Page what can reach a graph node (or what it reaches) over recorded edges, with walk completeness",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "graph_diff",
        "description": "What changed between two graph snapshots: summary counts and highlights, or filtered cursor-paged change rows",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "findings_query",
        "description": "Query tenant findings with the /v1/findings filters, sort and cursor in a compact projection",
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "finding_detail",
        "description": "One finding with the graph paths that carry it, who reaches it, and its triage/VEX state",
        "annotations": {"readOnlyHint": True},
    },
]

__all__ = ["GRAPH_AGENT_TOOL_CARDS"]
