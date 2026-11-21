"""The steps every merged correlation graph takes once its nodes and edges are in."""

from __future__ import annotations

from typing import Any

from agent_bom.graph.agent_context import annotate_agent_context
from agent_bom.graph.attack_path_counts import snapshot_attack_paths_summary
from agent_bom.graph.attack_path_fusion import apply_attack_path_fusion
from agent_bom.graph.attack_path_mitre import apply_attack_path_technique_mappings
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.workload_image_runs import link_workload_images


def finish_correlated_graph(graph: UnifiedGraph) -> None:
    """Join each workload to the image it pins by digest, then annotate agent context."""
    link_workload_images(graph)
    annotate_agent_context(graph)


def analyze_correlated_paths(graph: UnifiedGraph) -> dict[str, Any]:
    """Fuse and map the merged graph's attack paths; returns the receipt's ``attack_paths`` summary."""
    apply_attack_path_fusion(graph)
    apply_attack_path_technique_mappings(graph)
    return snapshot_attack_paths_summary(graph)


__all__ = ["analyze_correlated_paths", "finish_correlated_graph"]
