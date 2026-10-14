"""Shared reading of a recorded-reachability walk for REST impact and MCP reach."""

from __future__ import annotations

from typing import Any


def reach_interpretation(*, max_depth: int, direction: str = "in") -> dict[str, Any]:
    """What a recorded walk does and does not establish."""
    return {
        "basis": "recorded_reverse_reachability" if direction == "in" else "recorded_forward_reachability",
        "execution": "not_established",
        "collection_coverage": "unknown",
        "traversable_only": False,
        "max_depth": max_depth,
    }


__all__ = ["reach_interpretation"]
