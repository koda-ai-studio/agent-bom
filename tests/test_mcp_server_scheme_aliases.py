"""MCP server ids minted by an earlier identity scheme keep resolving to the current node."""

from __future__ import annotations

from typing import Any

from agent_bom.api.graph_node_alias import resolve_snapshot_node_id
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.canonical_ids import legacy_canonical_id_v2
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
    # Frozen pre-instance spelling: no config owner scope and joined argv.
    legacy = legacy_canonical_id_v2("mcp_server", f"cmd:node:{script}")
    return "server:" + legacy


def test_mixed_case_server_old_lowercased_id_resolves(tmp_path: Any) -> None:
    script = "/srv/TeamA/server.js"
    graph = build_unified_graph_from_report(_report(script), scan_id="scan-a", tenant_id="default")
    server = _server(graph)
    legacy = _legacy_id(server.id, script)
    assert legacy in server.attributes["identity"]["aliases"]

    store = SQLiteGraphStore(tmp_path / "g.db")
    store.save_graph(graph)
    assert resolve_snapshot_node_id(store, tenant_id="default", scan_id="scan-a", node_id=legacy) == (server.id, legacy)


def test_lowercase_server_retains_prior_recipe_and_name_aliases() -> None:
    graph = build_unified_graph_from_report(_report("/srv/teama/server.js"), scan_id="scan-a", tenant_id="default")
    server = _server(graph)
    # Earlier configured and name-only graph ids remain explicit aliases.
    aliases = server.attributes["identity"]["aliases"]
    assert {"server:cfg-bc01a49e73e6:claude-desktop:files", "server:claude-desktop:files"} <= set(aliases)
    assert _legacy_id(server.id, "/srv/teama/server.js") in aliases
    assert server.id not in aliases


def test_name_only_server_keeps_previous_unscoped_alias() -> None:
    report = _report("")
    report["agents"][0]["mcp_servers"] = [{"name": "files"}]
    server = _server(build_unified_graph_from_report(report, scan_id="scan-a", tenant_id="default"))
    assert server.attributes["identity"]["aliases"] == ["server:claude-desktop:files"]
