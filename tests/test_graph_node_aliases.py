"""Node ids replaced by asset canonicalization stay resolvable, per tenant."""

from __future__ import annotations

import os
import uuid

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.trace_inventory_correlation import correlate_inventory_observations
from agent_bom.graph.builder import build_unified_graph_from_report

ACCOUNT = "210987654321"
REGION = "us-east-1"
INSTANCE = "i-0a1b2c3d4e5f60718"
ARN = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/{INSTANCE}"
CANONICAL = f"cloud_resource:aws:aws_instance:{ACCOUNT}/{REGION}/{INSTANCE}"
INVENTORY_ID = f"cloud_resource:aws:ec2:instance:{INSTANCE}"


def _report() -> dict:
    return {
        "cloud_inventory": {
            "status": "ok",
            "provider": "aws",
            "account_id": ACCOUNT,
            "region": REGION,
            "instances": [{"instance_id": INSTANCE, "name": "billing-api", "region": REGION, "tags": {"environment": "prod"}}],
        },
        "cloud_audit_trail": {
            "status": "ok",
            "provider": "aws",
            "account": ACCOUNT,
            "behavioral_edges": [{"principal": "ops", "resource": ARN, "action": "StopInstances", "relationship": "invoked", "count": 1}],
        },
    }


def _graph(tenant: str, scan: str):
    graph = build_unified_graph_from_report(_report(), scan_id=scan, tenant_id=tenant)
    assert CANONICAL in graph.nodes
    return graph


def test_sqlite_aliases_resolve_within_their_tenant_only(tmp_path) -> None:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_graph("tenant-a", "scan-a"))

    assert store.resolve_node_aliases(tenant_id="tenant-a", node_ids={INVENTORY_ID, "unknown"}) == {INVENTORY_ID: CANONICAL}
    assert store.resolve_node_aliases(tenant_id="tenant-b", node_ids={INVENTORY_ID}) == {}


def test_two_tenants_with_the_same_alias_both_persist(tmp_path) -> None:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_graph("tenant-a", "scan-a"))
    store.save_graph(_graph("tenant-b", "scan-b"))

    assert store.resolve_node_aliases(tenant_id="tenant-a", node_ids={INVENTORY_ID}) == {INVENTORY_ID: CANONICAL}
    assert store.resolve_node_aliases(tenant_id="tenant-b", node_ids={INVENTORY_ID}) == {INVENTORY_ID: CANONICAL}
    store.delete_tenant(tenant_id="tenant-a")
    assert store.resolve_node_aliases(tenant_id="tenant-a", node_ids={INVENTORY_ID}) == {}
    assert store.resolve_node_aliases(tenant_id="tenant-b", node_ids={INVENTORY_ID}) == {INVENTORY_ID: CANONICAL}


def test_trace_claim_naming_a_replaced_id_binds_to_the_canonical_node(tmp_path) -> None:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_graph("tenant-a", "scan-a"))
    observation = {
        "observation_id": "obs-1",
        "tenant_id": "tenant-a",
        "surface": "imported_trace",
        "metadata": {"inventory_node_id": INVENTORY_ID, "cloud_provider": "aws", "account_id": ACCOUNT, "environment": "prod"},
    }

    binding = correlate_inventory_observations(store, tenant_id="tenant-a", scan_id="scan-a", observations=[observation])["obs-1"]

    assert binding["state"] == "exact_identifier"
    assert binding["node_id"] == CANONICAL
    assert binding["alias_of"] == INVENTORY_ID


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="AGENT_BOM_POSTGRES_URL not set")
def test_postgres_aliases_are_tenant_isolated() -> None:
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore

    store = PostgresGraphStore()
    tenant_a, tenant_b = f"alias-a-{uuid.uuid4().hex[:8]}", f"alias-b-{uuid.uuid4().hex[:8]}"

    def as_tenant(tenant: str, action):
        token = set_current_tenant(tenant)
        try:
            return action()
        finally:
            reset_current_tenant(token)

    try:
        as_tenant(tenant_a, lambda: store.save_graph(_graph(tenant_a, f"scan-{tenant_a}")))
        as_tenant(tenant_b, lambda: store.save_graph(_graph(tenant_b, f"scan-{tenant_b}")))
        assert as_tenant(tenant_a, lambda: store.resolve_node_aliases(tenant_id=tenant_a, node_ids={INVENTORY_ID})) == {
            INVENTORY_ID: CANONICAL
        }
        # Bound to tenant B, a read naming tenant A sees nothing: RLS and the predicate agree.
        assert as_tenant(tenant_b, lambda: store.resolve_node_aliases(tenant_id=tenant_a, node_ids={INVENTORY_ID})) == {}
        as_tenant(tenant_a, lambda: store.delete_tenant(tenant_id=tenant_a))
        assert as_tenant(tenant_a, lambda: store.resolve_node_aliases(tenant_id=tenant_a, node_ids={INVENTORY_ID})) == {}
        assert as_tenant(tenant_b, lambda: store.resolve_node_aliases(tenant_id=tenant_b, node_ids={INVENTORY_ID})) == {
            INVENTORY_ID: CANONICAL
        }
    finally:
        as_tenant(tenant_a, lambda: store.delete_tenant(tenant_id=tenant_a))
        as_tenant(tenant_b, lambda: store.delete_tenant(tenant_id=tenant_b))
