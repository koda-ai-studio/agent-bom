"""Serialized code-analysis relationship rows: call graph, control flow and dependency reach.

These lists grow with every function in a project (hundreds of thousands of
control-flow edges on a large repository), so a CLI report leaves them out
unless asked. Their counts stay in the analysis ``stats`` either way.
"""

from __future__ import annotations

from typing import Any


def _call_graph(result: Any) -> list[dict]:
    return [
        {
            "caller": edge.caller,
            "callee": edge.callee,
            "file": edge.file_path,
            "line": edge.line_number,
        }
        for edge in result.call_edges
    ]


def _cfg_edges(result: Any) -> list[dict]:
    return [
        {
            "source": edge.source,
            "target": edge.target,
            "type": edge.edge_type,
            "file": edge.file_path,
            "function": edge.function_name,
        }
        for edge in result.cfg_edges
    ]


def _entrypoint_context(reach: Any) -> dict:
    if reach.entrypoint_kind == "mcp_tool":
        return {}
    return {
        "entrypoint_kind": reach.entrypoint_kind,
        "entrypoint_framework": reach.entrypoint_framework,
        "entrypoint_provenance": reach.entrypoint_provenance,
    }


def _dependency_symbol_reach(result: Any) -> list[dict]:
    return [
        {
            "entrypoint": reach.entrypoint,
            "package": reach.package,
            "module": reach.module,
            "symbol": reach.symbol,
            "file": reach.file_path,
            "line": reach.line_number,
            "call_path": reach.call_path,
            "depth": reach.depth,
            "confidence": reach.confidence,
            "ecosystem": reach.ecosystem,
            **_entrypoint_context(reach),
        }
        for reach in result.dependency_symbol_reach
    ]


def relationship_rows(result: Any, *, include: bool) -> dict:
    """The relationship lists of an ``ASTAnalysisResult``, or only the flag saying they were left out."""
    if not include:
        return {"relationships_included": False}
    return {
        "relationships_included": True,
        "call_graph": _call_graph(result),
        "cfg_edges": _cfg_edges(result),
        "dependency_symbol_reach": _dependency_symbol_reach(result),
    }
