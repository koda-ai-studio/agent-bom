"""Each estate change names the vendor its collector recorded, not the scan's request label."""

from __future__ import annotations

from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode
from tests.api.test_graph_estate_changes import TENANT, by_label, client, estate, record  # noqa: F401


def _graph(scan_id: str, nodes: list[UnifiedNode]) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan_id, tenant_id=TENANT, created_at="2026-10-01T00:00:00Z")
    for node in nodes:
        graph.add_node(node)
    return graph


def _misconfig(node_id: str, vendor: str) -> UnifiedNode:
    attributes = {"cloud_provider": vendor} if vendor else {}
    return UnifiedNode(id=node_id, entity_type=EntityType.MISCONFIGURATION, label=node_id, severity="critical", attributes=attributes)


def test_highlighted_changes_carry_their_collected_vendor(estate):  # noqa: F811
    _jobs, graph_store = estate
    old = record(estate, 7, "estate", [], save_graph=False)
    new = record(estate, 8, "estate", [], save_graph=False)
    keep = UnifiedNode(id="keep", entity_type=EntityType.CLOUD_RESOURCE, label="keep")
    graph_store.save_graph(_graph(old, [keep]))
    graph_store.save_graph(
        _graph(new, [keep, _misconfig("misconfig:gcp", "gcp"), _misconfig("misconfig:sf", "snowflake"), _misconfig("misconfig:bare", "")])
    )
    with client() as http:
        body = http.get("/v1/graph/changes").json()
    row = by_label(body)["estate"]
    vendors = {item["id"]: item.get("vendor") for item in row["highlights"]["new_critical_findings"]["top"]}
    assert vendors == {"misconfig:gcp": "gcp", "misconfig:sf": "snowflake", "misconfig:bare": None}
    assert row["label_basis"] == "scan_target"


def test_a_scan_without_a_named_source_says_its_label_is_the_default(estate):  # noqa: F811
    jobs, graph_store = estate
    old = record(estate, 7, "estate", [], save_graph=False)
    new = record(estate, 8, "estate", [], save_graph=False)
    for job_id in (old, new):
        jobs.get(job_id, tenant_id=TENANT).target = None
    graph_store.save_graph(_graph(old, []))
    graph_store.save_graph(_graph(new, [_misconfig("misconfig:aws", "aws")]))
    with client() as http:
        body = http.get("/v1/graph/changes").json()
    row = by_label(body)["local-agents"]
    assert row["label_basis"] == "default_scan_request"
    assert row["changes_by_source"]["sources"][0]["vendor"] == "aws"
