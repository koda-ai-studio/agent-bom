"""Pure helpers extracted out of ``mcp_server.py`` as part of #1522 Phase 2.

These don't depend on the ``FastMCP`` instance and have narrow signatures —
safe to call from ``create_mcp_server`` without passing the server object
around. Keeping them outside the monolith makes them unit-testable and
shrinks the ~1500 LOC ``mcp_server.py`` toward its <500-LOC target.

Next extractions (tracked): registry helpers + dep-graph + tool-pipeline
were factored here. Subsequent phases will move the thin per-tool
wrappers into a schema-table registration pattern so every tool lives
next to its implementation in ``agent_bom/mcp_tools/``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agent_bom import mcp_server_runtime as _mcp_runtime

# Registry cache (module-local — was at mcp_server.py line 320-321).
_registry_cache: dict | None = None
_registry_raw_cache: str | None = None


def build_dep_graph_from_agents(agents_data: list[dict[str, Any]]):
    """Build the export graph from serialized agents; the one DepGraph builder serves both callers."""
    from agent_bom.output.graph_export import build_graph_from_scan_data

    return build_graph_from_scan_data({"agents": agents_data})


def get_registry_data() -> dict:
    """Load and cache the MCP registry JSON as a dict."""
    global _registry_cache
    registry_path = Path(__file__).parent / "mcp_registry.json"
    _registry_cache = _mcp_runtime.get_registry_data(_registry_cache, registry_path)
    if _registry_cache is None:
        raise RuntimeError("Registry cache failed to load")
    return _registry_cache


def get_registry_data_raw() -> str:
    """Load and cache the MCP registry JSON as raw text."""
    global _registry_raw_cache
    registry_path = Path(__file__).parent / "mcp_registry.json"
    _registry_raw_cache = _mcp_runtime.get_registry_data_raw(_registry_raw_cache, registry_path)
    if _registry_raw_cache is None:
        raise RuntimeError("Registry raw cache failed to load")
    return _registry_raw_cache


def reset_registry_cache_for_tests() -> None:
    """Drop the module-local registry caches (test hook)."""
    global _registry_cache, _registry_raw_cache
    _registry_cache = None
    _registry_raw_cache = None


__all__ = [
    "build_dep_graph_from_agents",
    "get_registry_data",
    "get_registry_data_raw",
    "reset_registry_cache_for_tests",
]
