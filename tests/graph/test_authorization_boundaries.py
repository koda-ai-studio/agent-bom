"""Negative evaluator receipts survive projection without creating access edges."""

from datetime import datetime, timezone

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report
from tests.test_graph_authorization_evidence_integration import _azure_inventory, _gcp_inventory


@pytest.mark.parametrize(
    "inventory,reason",
    [
        (_gcp_inventory(conditional=True), "unevaluated_allow_condition"),
        (_azure_inventory(role_state="partial"), "incomplete_required_sources"),
    ],
)
def test_unresolved_exact_request_is_persisted_as_boundary(inventory, reason, tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore

    graph = build_unified_graph_from_report({"scan_id": "boundaries", "cloud_inventory": inventory}, tenant_id="tenant:a")
    boundaries = [row for node in graph.nodes.values() for row in node.attributes.get("authorization_boundaries", [])]
    assert len(boundaries) == 1
    row = boundaries[0]
    assert row["decision"] == "indeterminate"
    assert row["action"] and row["resource"] and row["principal_id"] and row["target_node_id"]
    assert any(reason in code for code in row["reason_codes"])
    path = tmp_path / "boundaries.db"
    SQLiteGraphStore(path).save_graph(graph)
    restored = SQLiteGraphStore(path).load_graph(scan_id=graph.scan_id, tenant_id=graph.tenant_id)
    assert [r for n in restored.nodes.values() for r in n.attributes.get("authorization_boundaries", [])] == boundaries
    assert not [e for e in graph.edges if e.evidence.get("source") == "authorization-evidence"]


def test_denial_preserves_exact_deny_bindings_and_consequence():
    from agent_bom.graph.consequence.contracts import ConsequenceRequest
    from agent_bom.graph.consequence.service import assess_consequences

    inventory = _gcp_inventory()
    inventory["deny_policies"] = [
        {
            "name": "policies/project/denypolicies/protect",
            "attachment_point": "cloudresourcemanager.googleapis.com/projects/proj-1",
            "rules": [
                {
                    "denied_principals": [
                        "principal://iam.googleapis.com/projects/-/serviceAccounts/reader@proj-1.iam.gserviceaccount.com"
                    ],
                    "denied_permissions": ["storage.googleapis.com/objects.get"],
                    "exception_permissions": [],
                    "exception_principals": [],
                    "condition": None,
                }
            ],
        }
    ]
    graph = build_unified_graph_from_report({"scan_id": "deny", "cloud_inventory": inventory}, tenant_id="tenant:a")
    principal = next(n for n in graph.nodes.values() if n.attributes.get("authorization_boundaries"))
    row = principal.attributes["authorization_boundaries"][0]
    assert row["decision"] == "explicit_deny" and row["deny_binding_ids"]
    result = assess_consequences(
        graph,
        ConsequenceRequest(root_node_id=principal.id, mode="assumed_compromise", assume_control=True),
        tenant_id="tenant:a",
        at=datetime(2026, 7, 17, 12, 1, tzinfo=timezone.utc),
    )
    assert result.consequences[0].status == "blocked"
    assert result.consequences[0].deny_binding_ids == row["deny_binding_ids"]
    assert result.consequences[0].edge_ids == []  # no fabricated permission edge
    assert result.consequences[0].evidence_refs


def test_native_typed_principal_receipt_is_qualified_by_producer_node_binding():
    from agent_bom.graph.consequence.contracts import ConsequenceRequest
    from agent_bom.graph.consequence.service import assess_consequences

    graph = build_unified_graph_from_report({"scan_id": "native", "cloud_inventory": _gcp_inventory()}, tenant_id="tenant:a")
    edge = next(e for e in graph.edges if e.evidence.get("source") == "authorization-evidence")
    result = assess_consequences(
        graph,
        ConsequenceRequest(root_node_id=edge.source, mode="assumed_compromise", assume_control=True),
        tenant_id="tenant:a",
        at=datetime(2026, 7, 17, 12, 1, tzinfo=timezone.utc),
    )
    assert result.consequences[0].status == "supported"


def test_boundary_projection_accumulates_multiple_scoped_inventories_without_erasing_prior_receipts():
    from agent_bom.graph.authorization_evidence import apply_authorization_evidence

    inventory = _gcp_inventory(conditional=True)
    graph = build_unified_graph_from_report({"scan_id": "merged", "cloud_inventory": inventory}, tenant_id="tenant:a")
    principal = next(n for n in graph.nodes.values() if n.attributes.get("authorization_boundaries"))
    original = list(principal.attributes["authorization_boundaries"])
    inventory["role_definitions"][0]["permissions"] = ["storage.objects.create"]
    apply_authorization_evidence(graph, inventory)
    after = graph.nodes[principal.id].attributes["authorization_boundaries"]
    assert len(after) == 2
    assert original[0] in after
    apply_authorization_evidence(graph, inventory)
    assert graph.nodes[principal.id].attributes["authorization_boundaries"] == after
