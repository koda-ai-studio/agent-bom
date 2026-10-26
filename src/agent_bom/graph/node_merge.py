"""One merge-union for a node added twice, shared by every graph container."""

from __future__ import annotations

from agent_bom.core.severity import SEVERITY_RANK
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.recorded_time import merge_seen


def merge_node(existing: UnifiedNode, incoming: UnifiedNode) -> None:
    """Merge *incoming* into *existing* in place; cross-source metadata is unioned."""
    merge_seen(existing, incoming)
    existing.merge_attributes_and_risk(incoming)
    if SEVERITY_RANK.get(incoming.severity, 0) > SEVERITY_RANK.get(existing.severity, 0):
        existing.severity = incoming.severity
        existing.severity_id = incoming.severity_id
    _union(existing.data_sources, incoming.data_sources)
    _union(existing.compliance_tags, incoming.compliance_tags)
    existing.dimensions = existing.dimensions.merge(incoming.dimensions)


def _union(kept: list[str], extra: list[str]) -> None:
    seen = set(kept)
    for value in extra:
        if value not in seen:
            kept.append(value)
            seen.add(value)
