"""Name candidates must not become graph evidence or wildcard matches."""

import pytest

from agent_bom.api.trace_explorer import correlate_findings
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.path_evidence import _evidence_tier
from agent_bom.graph.types import RelationshipType
from agent_bom.otel_ingest import ToolCallTrace, flag_vulnerable_tool_calls


def test_tool_candidate_requires_tool_evidence():
    assert correlate_findings(agent="agent", tool="unrelated", findings=[{"id": "f", "affected_agents": ["agent"]}]) == []
    assert correlate_findings(agent="other", tool="", findings=[{"id": "f", "exposed_tools": ["tool"]}]) == []
    assert correlate_findings(agent="agent", tool="tool", findings=[{"id": "f", "exposed_tools": ["tool"]}], limit=0) == []


def test_name_flags_are_candidates_even_for_an_explicit_package():
    flags = flag_vulnerable_tool_calls([ToolCallTrace("t", "s", "query", package_name="pkg")], {"pkg": ["CVE-1"]})
    assert len(flags) == 1
    assert flags[0].correlation_basis == "candidate_name"
    assert "candidate" in flags[0].reason.lower()


def test_empty_tool_does_not_match_every_package():
    assert flag_vulnerable_tool_calls([ToolCallTrace("t", "s", "")], {"pkg": ["CVE-1"]}) == []


@pytest.mark.parametrize("tier", ["static_scan", "recorded", "derived", "modeled_infrastructure", "runtime_observed"])
def test_hop_uses_canonical_tier_despite_unrelated_metadata(tier):
    edge = UnifiedEdge(
        source="a", target="b", relationship=RelationshipType.USES, evidence={"tier": tier, "comment": "iac modeled discussion"}
    )
    assert _evidence_tier(edge) == tier


def test_missing_hop_tier_is_not_inferred_from_free_text():
    edge = UnifiedEdge(source="a", target="b", relationship=RelationshipType.USES, evidence={"comment": "iac"})
    assert _evidence_tier(edge) == "legacy_unrecorded"


def test_schema_does_not_claim_demo_or_reserved_emission():
    from agent_bom.api.routes.graph_routes.schema_routes import get_graph_schema

    schema = get_graph_schema()
    nodes = {row["key"]: row for row in schema["node_kinds"]}
    edges = {row["key"]: row for row in schema["edge_kinds"]}
    assert nodes["tool_call"]["emission_status"] == "reserved"
    for key in ("inherits", "lateral_path", "shares_cred"):
        assert edges[key]["emission_status"] == "reserved"


def test_old_hop_receipt_remains_readable_without_claim_upgrade():
    from agent_bom.graph.hop_evidence import HopEvidenceReceipt

    original = {"source_node_id": "a", "target_node_id": "b", "relationship": "uses", "evidence_tier": "static_evidence"}
    receipt = HopEvidenceReceipt.model_validate(original)
    assert receipt.evidence_tier == "legacy_unrecorded"
    assert original["evidence_tier"] == "static_evidence"


def test_unknown_schema_kind_never_defaults_to_emitted():
    from agent_bom.api.routes.graph_routes.schema_routes import _graph_schema_emission_meta

    assert _graph_schema_emission_meta("future_kind", reserved={}, emitted_surfaces={})["emission_status"] == "reserved"


@pytest.mark.parametrize("counts,total", [((0, 0, 0, 0), 0), ((2, 1, 3, 4), 10), ((1, 0, 0, 0), 5)])
def test_edge_change_completeness_counts_rows(monkeypatch, counts, total):
    import asyncio
    from types import SimpleNamespace

    from agent_bom.api.routes.graph_routes import views

    kinds = ("added", "removed", "changed", "unchanged")
    payload = {f"edges_{kind}": [{} for _ in range(count)] for kind, count in zip(kinds, counts)}
    payload["summary"] = dict(zip(kinds, counts))
    payload["summary"]["added"] += total - sum(counts)
    store = SimpleNamespace(changed_edges_between_scans=object())

    async def call(method, old, new, *, tenant_id):
        assert method is store.changed_edges_between_scans
        assert (old, new, tenant_id) == ("old", "new", "tenant-a")
        return payload

    monkeypatch.setattr(views._runtime, "_get_graph_store_or_503", lambda: store)
    monkeypatch.setattr(views._runtime, "_tenant", lambda request: "tenant-a")

    async def known_snapshots(graph_store, tenant, *scan_ids):
        return scan_ids

    monkeypatch.setattr(views._runtime, "_graph_store_call", call)
    monkeypatch.setattr(views._runtime, "require_graph_snapshot_ids", known_snapshots)
    result = asyncio.run(views.get_graph_edge_changes(SimpleNamespace(), old="old", new="new"))
    assert result["completeness"]["returned"] == sum(counts)
    assert result["completeness"]["total"] == total
    assert result["completeness"]["complete"] is (sum(counts) == total)
