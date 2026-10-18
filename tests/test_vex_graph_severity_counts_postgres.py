"""Postgres twin: VEX-suppressed findings stay out of stored and live severity counts."""

from __future__ import annotations

from tests.test_postgres_migrated_graph_parity import migrated_fresh_database, pytestmark  # noqa: F401
from tests.test_vex_graph_severity_counts import _suppressed_graph


def test_postgres_snapshot_and_live_counts_exclude_suppressed(migrated_fresh_database, tmp_path):  # noqa: F811
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore

    _doc, graph = _suppressed_graph(tmp_path)
    store = PostgresGraphStore()
    token = set_current_tenant("tenant-vex")
    try:
        store.save_graph(graph)
        cached = store.snapshot_stats(tenant_id="tenant-vex", scan_id="vex-scan")
        live = store.snapshot_stats(tenant_id="tenant-vex", scan_id="vex-scan", entity_types={"vulnerability"})
    finally:
        reset_current_tenant(token)
    assert cached["severity_counts"].get("high", 0) == 1
    assert live["severity_counts"].get("high", 0) == 1
