"""A node whose id scheme changed between snapshots is the same node, not a removal plus an addition."""

from __future__ import annotations

import os

import pytest

from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.diff_identity import snapshot_rename_map
from tests.test_postgres_migrated_graph_parity import migrated_fresh_database  # noqa: F401

TENANT = "diff-alias-tenant"


def _vm(node_id: str, *, exposed: bool, aliases: list[str] | None = None) -> UnifiedNode:
    attributes: dict = {"internet_exposed": exposed}
    if aliases:
        attributes["identity"] = {"aliases": aliases}
    return UnifiedNode(id=node_id, entity_type=EntityType.CLOUD_RESOURCE, label="vm", attributes=attributes)


def _snapshots(store) -> None:
    old = UnifiedGraph(scan_id="alias-old", tenant_id=TENANT, created_at="2026-10-01T00:00:00Z")
    for node in (
        _vm("i-legacy-1", exposed=False),
        _vm("i-legacy-2", exposed=False),
        _vm("gone", exposed=False),
        UnifiedNode(id="vuln:CVE-2026-0001", entity_type=EntityType.VULNERABILITY, label="CVE-1"),
    ):
        old.add_node(node)
    old.add_edge(UnifiedEdge(source="i-legacy-1", target="vuln:CVE-2026-0001", relationship=RelationshipType.VULNERABLE_TO))
    old.add_edge(UnifiedEdge(source="i-legacy-2", target="vuln:CVE-2026-0001", relationship=RelationshipType.VULNERABLE_TO))
    old.add_edge(UnifiedEdge(source="gone", target="vuln:CVE-2026-0001", relationship=RelationshipType.VULNERABLE_TO))
    store.save_graph(old)

    new = UnifiedGraph(scan_id="alias-new", tenant_id=TENANT, created_at="2026-10-02T00:00:00Z")
    for node in (
        _vm("aws:ec2:1", exposed=False, aliases=["i-legacy-1"]),
        _vm("aws:ec2:2", exposed=True, aliases=["i-legacy-2"]),
        _vm("fresh", exposed=False),
        UnifiedNode(id="vuln:CVE-2026-0001", entity_type=EntityType.VULNERABILITY, label="CVE-1"),
    ):
        new.add_node(node)
    new.add_edge(UnifiedEdge(source="aws:ec2:1", target="vuln:CVE-2026-0001", relationship=RelationshipType.VULNERABLE_TO))
    new.add_edge(UnifiedEdge(source="aws:ec2:2", target="vuln:CVE-2026-0001", relationship=RelationshipType.VULNERABLE_TO, confidence=0.5))
    new.add_edge(UnifiedEdge(source="fresh", target="vuln:CVE-2026-0001", relationship=RelationshipType.VULNERABLE_TO))
    store.save_graph(new)


def diff_alias_contract(store) -> None:
    _snapshots(store)
    diff = store.diff_snapshots("alias-old", "alias-new", tenant_id=TENANT)

    assert [node["id"] for node in diff["nodes_removed"]] == ["gone"]
    assert [node["id"] for node in diff["nodes_added"]] == ["fresh"]
    assert diff["nodes_changed"] == ["aws:ec2:2"]
    assert [delta["field"] for delta in diff["attribute_deltas"]["aws:ec2:2"]] == ["internet_exposed"]
    assert diff["nodes_renamed"] == {"aws:ec2:1": "i-legacy-1", "aws:ec2:2": "i-legacy-2"}
    # Removed rows keep the id the old snapshot recorded, so they still open there.
    assert diff["edges_removed"] == [("gone", "vuln:CVE-2026-0001", "vulnerable_to")]
    assert diff["edges_added"] == [("fresh", "vuln:CVE-2026-0001", "vulnerable_to")]
    changed = diff["edges_changed"]
    assert [(e["before"]["source_id"], e["after"]["source_id"]) for e in changed] == [("i-legacy-2", "aws:ec2:2")]

    edges = store.changed_edges_between_scans("alias-old", "alias-new", tenant_id=TENANT)
    assert edges["summary"] == {"added": 1, "removed": 1, "changed": 1, "unchanged": 1}
    assert [e["source_id"] for e in edges["edges_unchanged"]] == ["aws:ec2:1"]


def test_sqlite_diff_maps_aliased_ids_to_their_new_canonical_node(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore

    diff_alias_contract(SQLiteGraphStore(tmp_path / "diff.db"))


def test_rename_map_is_one_to_one_and_never_shadows_a_node_the_old_snapshot_had():
    resolved = {"a": "A", "b": "B", "c": "B", "d": "D"}
    rename = snapshot_rename_map(
        ["a", "b", "c", "d"],
        resolve=lambda ids: {i: resolved[i] for i in ids if i in resolved},
        old_live=lambda ids: {i for i in ids if i == "D"},
        new_live=lambda ids: {i for i in ids if i in {"A", "B", "D"}},
    )
    # b and c merged into B (not a rename); D already existed in the old snapshot.
    assert rename == {"a": "A"}


def test_rename_map_resolves_more_than_one_lookup_batch():
    ids = [f"old-{i:04d}" for i in range(1201)]
    calls: list[int] = []

    def resolve(batch):
        calls.append(len(batch))
        return {i: i.replace("old", "new") for i in batch}

    rename = snapshot_rename_map(ids, resolve=resolve, old_live=lambda _ids: set(), new_live=set)
    assert len(rename) == 1201 and max(calls) <= 500


def test_diff_rows_name_the_old_id_of_a_renamed_changed_node(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.graph.diff_view import diff_rows

    store = SQLiteGraphStore(tmp_path / "rows.db")
    _snapshots(store)
    rows = diff_rows(store.diff_snapshots("alias-old", "alias-new", tenant_id=TENANT))
    nodes = {(row["change"], row["id"]): row for row in rows if row["kind"] == "node"}
    assert set(nodes) == {("added", "fresh"), ("removed", "gone"), ("changed", "aws:ec2:2")}
    assert nodes[("changed", "aws:ec2:2")]["previous_id"] == "i-legacy-2"


@pytest.mark.skipif(
    not (os.environ.get("AGENT_BOM_POSTGRES_ADMIN_URL") and os.environ.get("AGENT_BOM_POSTGRES_URL")),
    reason="needs a disposable Postgres (AGENT_BOM_POSTGRES_ADMIN_URL + AGENT_BOM_POSTGRES_URL)",
)
def test_postgres_diff_maps_aliased_ids_to_their_new_canonical_node(migrated_fresh_database):  # noqa: F811
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore

    token = set_current_tenant(TENANT)
    try:
        diff_alias_contract(PostgresGraphStore())
    finally:
        reset_current_tenant(token)
