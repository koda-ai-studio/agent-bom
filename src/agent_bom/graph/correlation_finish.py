"""The steps every merged correlation graph takes once its nodes and edges are in."""

from __future__ import annotations

from agent_bom.graph.agent_context import annotate_agent_context
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.workload_image_runs import link_workload_images


def finish_correlated_graph(graph: UnifiedGraph) -> None:
    """Join each workload to the image it pins by digest, then annotate agent context."""
    link_workload_images(graph)
    annotate_agent_context(graph)


__all__ = ["finish_correlated_graph"]
