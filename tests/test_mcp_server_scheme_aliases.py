"""MCP server ids minted by an earlier identity scheme keep resolving to the current node."""

from __future__ import annotations

from typing import Any

from agent_bom.api.graph_node_alias import resolve_snapshot_node_id
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.canonical_ids import canonical_id, mcp_server_identity_discriminator
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import EntityType


def _report(script: str) -> dict[str, Any]:
    return {
        "agents": [
            {
                "name": "claude-desktop",
                "agent_type": "claude-desktop",
                "config_path": "/home/dev/.config/claude/config.json",
                "mcp_servers": [{"name": "files", "command": "node", "args": [script], "transport": "stdio"}],
            }
        ]
    }


def _server(graph: Any) -> Any:
    servers = [node for node in graph.nodes.values() if node.entity_type == EntityType.SERVER]
    assert len(servers) == 1
    return servers[0]


def _legacy_id(server_id: str, script: str) -> str:
    current = str(server_id).rsplit(":", 1)[-1]
    legacy = canonical_id("mcp_server", mcp_server_identity_discriminator("files", "node", args=[script]))
    assert legacy != current
    return server_id[: -len(current)] + legacy


def test_mixed_case_server_old_lowercased_id_resolves(tmp_path: Any) -> None:
    script = "/srv/TeamA/server.js"
    graph = build_unified_graph_from_report(_report(script), scan_id="scan-a", tenant_id="default")
    server = _server(graph)
    legacy = _legacy_id(server.id, script)
    assert legacy in server.attributes["identity"]["aliases"]

    store = SQLiteGraphStore(tmp_path / "g.db")
    store.save_graph(graph)
    assert resolve_snapshot_node_id(store, tenant_id="default", scan_id="scan-a", node_id=legacy) == (server.id, legacy)


def test_lowercase_server_records_no_case_scheme_alias() -> None:
    graph = build_unified_graph_from_report(_report("/srv/teama/server.js"), scan_id="scan-a", tenant_id="default")
    server = _server(graph)
    # Only the agent-scoped id from before canonical server ids remains.
    assert server.attributes["identity"]["aliases"] == ["server:claude-desktop:files"]


def test_name_only_server_records_no_alias() -> None:
    report = _report("")
    report["agents"][0]["mcp_servers"] = [{"name": "files"}]
    server = _server(build_unified_graph_from_report(report, scan_id="scan-a", tenant_id="default"))
    assert "identity" not in server.attributes
