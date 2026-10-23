"""On the demo estate, every node-addressed read answers a replaced id exactly as its canonical id."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from typing import Any

from fastapi.testclient import TestClient


def _aliases_on_paths(limit: int = 2) -> list[tuple[str, str]]:
    conn = sqlite3.connect(os.environ["AGENT_BOM_GRAPH_DB"])
    try:
        latest = conn.execute(
            "SELECT scan_id FROM graph_snapshots WHERE tenant_id = 'default' AND snapshot_kind = 'scan' "
            "ORDER BY created_at DESC, scan_id DESC LIMIT 1"
        ).fetchone()[0]
        hops: set[str] = set()
        for (raw,) in conn.execute("SELECT path_nodes FROM attack_paths WHERE tenant_id = 'default' AND scan_id = ?", (latest,)):
            hops.update(json.loads(raw or "[]"))
        rows = conn.execute(
            "SELECT alias_id, canonical_id FROM graph_node_aliases WHERE tenant_id = 'default' AND scan_id = ? ORDER BY alias_id", (latest,)
        ).fetchall()
    finally:
        conn.close()
    return [(alias, canonical) for alias, canonical in rows if canonical in hops and alias != canonical and "/" not in alias][:limit]


def _strip(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip(v) for k, v in value.items() if k not in {"resolved_from", "elapsed_ms", "generated_at"}}
    if isinstance(value, list):
        return [_strip(v) for v in value]
    return value


def test_demo_aliases_on_attack_paths_read_like_their_canonical_ids(demo_estate_client: TestClient) -> None:
    from agent_bom.api import stores
    from agent_bom.backpressure import reset_backpressure_for_tests
    from agent_bom.mcp_tools.graph import exposure_paths_impl

    pairs = _aliases_on_paths()
    assert pairs, "the demo estate records replaced ids on attack-path hops"
    store = stores._get_graph_store()
    for alias, canonical in pairs:
        for path, params in (
            ("/v1/graph/impact", {"node": "{}"}),
            ("/v1/graph/paths", {"source_id": "{}"}),
            ("/v1/graph/node-neighbors", {"node_id": "{}"}),
        ):
            reset_backpressure_for_tests()
            by_alias = demo_estate_client.get(path, params={k: alias for k in params})
            by_canonical = demo_estate_client.get(path, params={k: canonical for k in params})
            assert by_canonical.status_code == 200, (path, canonical, by_canonical.text)
            assert by_alias.status_code == 200, (path, alias, by_alias.text)
            assert by_alias.json()["resolved_from"] == alias
            assert _strip(by_alias.json()) == _strip(by_canonical.json()), (path, alias)

        def exposure(node_id: str) -> dict[str, Any]:
            return json.loads(asyncio.run(exposure_paths_impl(node_id=node_id, limit=50, _get_graph_store=lambda: store)))

        reset_backpressure_for_tests()
        canonical_paths = exposure(canonical)
        assert canonical_paths.get("total", 0) > 0, canonical_paths
        assert exposure(alias).get("total") == canonical_paths.get("total")
