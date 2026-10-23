"""An exact or prefix name match ranks above fuzzy attribute matches, across keyset pages."""

import os
import uuid

import pytest

from agent_bom.api.graph_search_rank import decode_search_cursor
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode

NAME = "audit-evidence-staging-2"


def _rank_graph(tenant: str) -> UnifiedGraph:
    graph = UnifiedGraph(tenant_id=tenant, scan_id="snap")
    for i in range(9):
        graph.add_node(
            UnifiedNode(
                id=f"misconfig:{i}",
                entity_type=EntityType.MISCONFIGURATION,
                label=f"Failed CIS 2.1.{i} on bucket",
                severity="critical",
                risk_score=9.0,
                attributes={"resource": NAME},
            )
        )
    graph.add_node(UnifiedNode(id=f"aws:bucket:2:{NAME}-archive", entity_type=EntityType.DATA_STORE, label=f"{NAME}-archive"))
    graph.add_node(UnifiedNode(id=f"aws:bucket:1:{NAME}", entity_type=EntityType.DATA_STORE, label=NAME.upper()))
    return graph


@pytest.fixture
def store(tmp_path):
    store = SQLiteGraphStore(tmp_path / "rank.db")
    store.save_graph(_rank_graph("t"))
    return store


def test_exact_then_prefix_name_matches_rank_first(store):
    nodes, total, _cursor = store.search_nodes(tenant_id="t", scan_id="snap", query=NAME, limit=3)
    assert total == 11
    assert [node.id for node in nodes[:2]] == [f"aws:bucket:1:{NAME}", f"aws:bucket:2:{NAME}-archive"]
    assert nodes[2].entity_type == EntityType.MISCONFIGURATION


def test_keyset_pages_keep_the_rank_without_gaps_or_repeats(store):
    seen: list[str] = []
    cursor = None
    while True:
        nodes, _total, cursor = store.search_nodes(tenant_id="t", scan_id="snap", query=NAME, limit=2, cursor=cursor)
        seen.extend(node.id for node in nodes)
        if not cursor:
            break
    assert len(seen) == len(set(seen)) == 11
    assert seen[:2] == [f"aws:bucket:1:{NAME}", f"aws:bucket:2:{NAME}-archive"]


def test_id_match_ranks_first_and_a_legacy_cursor_resumes_among_other_matches(store):
    nodes, _total, _cursor = store.search_nodes(tenant_id="t", scan_id="snap", query="misconfig:4", limit=1)
    assert nodes[0].id == "misconfig:4"
    from agent_bom.api.graph_store_support import encode_graph_cursor

    legacy = encode_graph_cursor(UnifiedNode(id="n", entity_type=EntityType.PACKAGE, label="l"))
    assert decode_search_cursor(legacy)[0] == 2


_PG_URL = os.environ.get("AGENT_BOM_TEST_PG_URL")


@pytest.mark.skipif(not _PG_URL, reason="AGENT_BOM_TEST_PG_URL not set")
def test_postgres_ranks_exact_then_prefix_names_first_and_pages_stably() -> None:
    from psycopg_pool import ConnectionPool

    from agent_bom.api import postgres_common as pc
    from agent_bom.api.postgres_store import PostgresGraphStore

    tenant = f"rank-{uuid.uuid4().hex[:8]}"
    pool = ConnectionPool(conninfo=_PG_URL, min_size=1, max_size=2, open=True)
    token = pc.set_current_tenant(tenant)
    try:
        store = PostgresGraphStore(pool=pool)
        store.save_graph(_rank_graph(tenant))
        nodes, total, _cursor = store.search_nodes(tenant_id=tenant, scan_id="snap", query=NAME, limit=3)
        assert total == 11
        assert [node.id for node in nodes[:2]] == [f"aws:bucket:1:{NAME}", f"aws:bucket:2:{NAME}-archive"]
        seen: list[str] = []
        cursor = None
        while True:
            page, _total, cursor = store.search_nodes(tenant_id=tenant, scan_id="snap", query=NAME, limit=2, cursor=cursor)
            seen.extend(node.id for node in page)
            if not cursor:
                break
        assert len(seen) == len(set(seen)) == 11
        assert seen[:2] == [f"aws:bucket:1:{NAME}", f"aws:bucket:2:{NAME}-archive"]
        by_id, _total, _cursor = store.search_nodes(tenant_id=tenant, scan_id="snap", query="misconfig:4", limit=1)
        assert by_id[0].id == "misconfig:4"
    finally:
        pc.reset_current_tenant(token)
        pool.close()
