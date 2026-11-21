"""Typed attack-path count on ``/v1/graph`` stats and correlation receipts.

The surrounding objects stay open (``ReadModel`` allows extra keys); only the
count block is typed, so existing clients keep every field they read today.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from agent_bom.api.read_models._base import ReadModel


class GraphAttackPathCounts(ReadModel):
    """The one attack-path count every surface reports for a snapshot."""

    retained_count: int = Field(description="The attack-path queue's snapshot total; ``attack_path_count`` equals it.")
    assessed_count: int = Field(
        description="Candidates the analyzers evaluated before deduplication, caps and exclusions; never below retained_count."
    )
    basis: Literal["derived_graph_paths", "persisted_graph_paths", "served_graph_paths"] = Field(
        description="derived: the snapshot path index; persisted: stored path rows; served: the count the payload reported."
    )


class GraphPageStats(ReadModel):
    """``GET /v1/graph`` stats: counts and analysis status, plus the typed attack-path count."""

    attack_path_count: int | None = None
    attack_paths: GraphAttackPathCounts | None = None


class GraphCorrelationOutput(ReadModel):
    """The output graph a completed correlation receipt binds."""

    scan_id: str | None = None
    node_count: int | None = None
    edge_count: int | None = None
    attack_path_count: int | None = None
    attack_paths: GraphAttackPathCounts | None = None
    graph_digest_sha256: str | None = None


class GraphCorrelationResultManifest(ReadModel):
    """A correlation run's receipt; empty until the run completes."""

    schema_version: str | None = None
    output: GraphCorrelationOutput | None = None


__all__ = ["GraphAttackPathCounts", "GraphCorrelationOutput", "GraphCorrelationResultManifest", "GraphPageStats"]
