"""A recorded alias never redirects an id that is a live node in its snapshot."""

from __future__ import annotations

import os
import sqlite3
import uuid

import pytest

from agent_bom.api.graph_node_alias import resolve_snapshot_node_id
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import EntityType


def _case_variant_servers(transport: str):
    servers = []
    for name, path in [("upper", "TeamA"), ("lower", "teama")]:
        server = {"name": name, "transport": transport}
        if transport == "sse":
            server["url"] = f"https://mcp.example.test/{path}"
        else:
            server.update(command="node", args=[f"/srv/{path}/server.js"])
        servers.append(server)
    graph = build_unified_graph_from_report(
        {"agents": [{"name": "operator", "type": "custom", "source_id": "linux-host", "mcp_servers": servers}]},
        tenant_id="t",
        scan_id="s",
    )
    nodes = graph.nodes_by_type(EntityType.SERVER)
    assert len(nodes) == 2
    return graph, next(n for n in nodes if n.label == "lower"), next(n for n in nodes if n.label == "upper")


@pytest.mark.parametrize("transport", ["sse", "stdio"])
def test_legacy_alias_cannot_redirect_existing_canonical_server(tmp_path, transport):
    graph, lower, upper = _case_variant_servers(transport)
    assert lower.id not in upper.attributes.get("identity", {}).get("aliases", [])
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(graph)
    assert resolve_snapshot_node_id(store, tenant_id="t", scan_id="s", node_id=lower.id) == (lower.id, None)


@pytest.mark.parametrize("transport", ["sse", "stdio"])
def test_persisted_alias_shadowing_a_live_node_resolves_to_itself(tmp_path, transport):
    graph, lower, upper = _case_variant_servers(transport)
    path = tmp_path / "graph.db"
    store = SQLiteGraphStore(path)
    store.save_graph(graph)
    # A snapshot written before aliases were checked against live ids.
    with sqlite3.connect(path) as conn:
        conn.execute(
            "INSERT INTO graph_node_aliases VALUES ('t', ?, ?, 'server', 'v', 's', 'z')",
            (lower.id, upper.id),
        )
        conn.execute(
            "INSERT INTO graph_node_aliases VALUES ('t', 'server:retired', ?, 'server', 'v', 's', 'z')",
            (upper.id,),
        )
    assert resolve_snapshot_node_id(store, tenant_id="t", scan_id="s", node_id=lower.id) == (lower.id, None)
    assert store.resolve_node_aliases(tenant_id="t", node_ids={lower.id}) == {}
    assert store.resolve_node_aliases(tenant_id="t", node_ids={lower.id, "server:retired"}, scan_id="s") == {"server:retired": upper.id}


def _shadow_aliases(upper) -> list[str]:
    return [*upper.attributes.get("identity", {}).get("aliases", []), "server:retired"]


@pytest.mark.parametrize("transport", ["sse", "stdio"])
def test_storage_never_records_an_alias_that_names_a_live_node(tmp_path, transport):
    graph, lower, upper = _case_variant_servers(transport)
    upper.attributes["identity"] = {**upper.attributes.get("identity", {}), "aliases": [*_shadow_aliases(upper), lower.id]}
    path = tmp_path / "graph.db"
    SQLiteGraphStore(path).save_graph(graph)
    with sqlite3.connect(path) as conn:
        recorded = {row[0] for row in conn.execute("SELECT alias_id FROM graph_node_aliases WHERE scan_id = 's'")}
    assert lower.id not in recorded
    assert "server:retired" in recorded


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="AGENT_BOM_POSTGRES_URL not set")
def test_postgres_alias_shadowing_a_live_node_resolves_to_itself() -> None:
    from agent_bom.api.postgres_common import _tenant_connection, reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore

    graph, lower, upper = _case_variant_servers("sse")
    tenant = f"alias-live-{uuid.uuid4().hex[:8]}"
    graph.tenant_id = tenant
    upper.attributes["identity"] = {**upper.attributes.get("identity", {}), "aliases": [*_shadow_aliases(upper), lower.id]}
    store = PostgresGraphStore()
    token = set_current_tenant(tenant)
    try:
        store.save_graph(graph)
        with _tenant_connection(store._pool) as conn:
            recorded = {row[0] for row in conn.execute("SELECT alias_id FROM graph_node_aliases WHERE tenant_id = %s", (tenant,))}
            assert lower.id not in recorded
            assert "server:retired" in recorded
            for alias in (lower.id, "server:retired"):
                conn.execute(
                    "INSERT INTO graph_node_aliases VALUES (%s, %s, %s, 'server', 'v', 's', 'z') ON CONFLICT DO NOTHING",
                    (tenant, alias, upper.id),
                )
        assert store.resolve_node_aliases(tenant_id=tenant, node_ids={lower.id, "server:retired"}, scan_id="s") == {
            "server:retired": upper.id
        }
        assert store.resolve_node_aliases(tenant_id=tenant, node_ids={lower.id}) == {}
    finally:
        store.delete_tenant(tenant_id=tenant)
        reset_current_tenant(token)
