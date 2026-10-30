"""Fix recommendations must count shared recorded paths without claiming fixes."""

from __future__ import annotations

import pytest

from agent_bom.api.routes.graph_routes import payloads
from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode

pytestmark = pytest.mark.graph_contract("warn")


def estate():
    graph = UnifiedGraph(scan_id="scan-priorities", tenant_id="tenant-a")
    for name in ("a", "b", "c"):
        graph.add_node(UnifiedNode(id=f"agent:{name}", entity_type=EntityType.AGENT, label=name))
        graph.add_node(UnifiedNode(id=f"server:{name}", entity_type=EntityType.SERVER, label=f"MCP server {name}"))
        graph.add_edge(UnifiedEdge(source=f"agent:{name}", target=f"server:{name}", relationship=RelationshipType.USES))
    for name in ("shared", "single"):
        graph.add_node(UnifiedNode(id=f"package:{name}", entity_type=EntityType.PACKAGE, label=f"{name}@1.0"))
        graph.add_node(
            UnifiedNode(
                id=f"finding:{name}",
                entity_type=EntityType.VULNERABILITY,
                label=f"CVE-{name}",
                severity="critical",
                attributes={"fixed_version": "2.0", "finding_id": f"occurrence-{name}"},
            )
        )
        graph.add_edge(UnifiedEdge(source=f"package:{name}", target=f"finding:{name}", relationship=RelationshipType.VULNERABLE_TO))
    paths = [
        AttackPath(
            source=f"agent:{name}",
            target=f"finding:{pkg}",
            hops=[f"agent:{name}", f"server:{name}", f"package:{pkg}", f"finding:{pkg}"],
            edges=["uses", "depends_on", "vulnerable_to"],
            reachability="unknown",
            composite_risk=9,
        )
        for name, pkg in (("a", "shared"), ("b", "shared"), ("c", "single"))
    ]
    for name, pkg in (("a", "shared"), ("b", "shared"), ("c", "single")):
        graph.add_edge(UnifiedEdge(source=f"server:{name}", target=f"package:{pkg}", relationship=RelationshipType.DEPENDS_ON))
    return graph, paths


def priorities(monkeypatch, graph, paths, *, limit=8):
    monkeypatch.setattr(payloads, "resolve_snapshot_attack_paths", lambda *_args: paths)
    result = payloads._fix_first_graph_view_payload(graph, cve="", package="", agent="", limit=limit)
    assert "remediation_priorities" in result, "The fix-first view must expose shared-fix priorities before card pagination"
    return result["remediation_priorities"]


def test_shared_fix_ranks_before_single_path_and_retains_evidence(monkeypatch):
    graph, paths = estate()
    # The shared fix wins despite a larger stored score on the isolated path.
    paths[-1].composite_risk = 100
    result = priorities(monkeypatch, graph, paths, limit=1)
    assert result["schema_version"] == "graph-remediation-priorities.v1"
    assert result["assessed_paths"] == 3
    assert result["remediation_verified"] is False
    first, second = result["recommendations"]
    assert first["asset_node_id"] == "package:shared"
    assert first["finding_node_id"] == "finding:shared"
    assert first["finding_id"] == "occurrence-shared"
    assert first["fixed_version"] == "2.0"
    assert first["covered_paths"] == first["newly_covered_paths"] == 2
    assert first["critical_paths"] == 2
    assert first["unknown_reachability_paths"] == 2
    assert first["remaining_paths_after_selection"] == 1
    assert second["remaining_paths_after_selection"] == 0
    assert len(first["path_ids"]) == 2
    assert result["coverage_basis"] == "recorded_paths_touching_selected_findings"


def test_duplicate_paths_do_not_inflate_coverage_and_order_is_stable(monkeypatch):
    graph, paths = estate()
    expected = priorities(monkeypatch, graph, paths)
    actual = priorities(monkeypatch, graph, [*reversed(paths), paths[0]])
    assert actual == expected


def test_overlapping_fixes_report_marginal_coverage(monkeypatch):
    graph, paths = estate()
    graph.add_node(
        UnifiedNode(
            id="finding:extra",
            entity_type=EntityType.MISCONFIGURATION,
            label="Missing control",
            severity="high",
            attributes={"remediation": "Review and restrict this recorded permission."},
        )
    )
    graph.add_edge(UnifiedEdge(source="package:shared", target="finding:extra", relationship=RelationshipType.VULNERABLE_TO))
    # The same path includes two directly bound findings; touching either affects
    # its modeled route, so the second recommendation must not count it twice.
    paths[0].hops.extend(["package:shared", "finding:extra"])
    paths[0].edges.extend(["related_to", "vulnerable_to"])
    result = priorities(monkeypatch, graph, paths)
    extra = next(row for row in result["recommendations"] if row["finding_node_id"] == "finding:extra")
    assert extra["covered_paths"] == 1
    assert extra["newly_covered_paths"] == 0
    assert result["covered_paths"] == 3


@pytest.mark.parametrize("case", ["no_guidance", "unbound", "trace", "unlikely", "missing_node"])
def test_unqualified_paths_do_not_create_fix_recommendations(monkeypatch, case):
    graph, paths = estate()
    paths = paths[:1]
    if case == "no_guidance":
        graph.nodes["finding:shared"].attributes.clear()
    elif case == "unbound":
        graph.edges.clear()
    elif case == "trace":
        paths[0].reachability_basis = ["trace_order_correlation"]
    elif case == "unlikely":
        paths[0].reachability = "unlikely"
    else:
        del graph.nodes["agent:a"]
    result = priorities(monkeypatch, graph, paths)
    assert result["recommendations"] == []
    assert result["covered_paths"] == 0
    assert result["remediation_verified"] is False


def test_partial_graph_never_claims_complete_portfolio(monkeypatch):
    graph, paths = estate()
    graph.completeness.truncated = True
    graph.completeness.reason = "node_budget"
    result = priorities(monkeypatch, graph, paths)
    assert result["complete"] is False
    assert "node_budget" in result["limitations"]


def test_path_and_candidate_budgets_are_explicit(monkeypatch):
    from agent_bom.graph import remediation_priorities as module

    graph, paths = estate()
    monkeypatch.setattr(module, "MAX_PATHS", 1)
    result = priorities(monkeypatch, graph, paths)
    assert result["complete"] is False and "path_budget" in result["limitations"]
    assert result["assessed_paths"] == 1
    monkeypatch.setattr(module, "MAX_PATHS", 5000)
    monkeypatch.setattr(module, "MAX_CANDIDATES", 1)
    result = priorities(monkeypatch, graph, paths)
    assert result["candidate_count"] == 1 and "candidate_budget" in result["limitations"]


def test_guidance_redacts_credential_bearing_text(monkeypatch):
    import json

    graph, paths = estate()
    secret = "fixture-" + "sensitive-value"
    graph.nodes["finding:shared"].attributes = {"remediation": f"Rotate password={secret} before retrying."}
    result = priorities(monkeypatch, graph, paths)
    assert secret not in json.dumps(result)
    assert "<redacted>" in json.dumps(result)


def test_openapi_documents_the_exact_recommendation_contract(monkeypatch):
    import jsonschema

    from agent_bom.api.graph_contracts import _FIX_FIRST_VIEW_OPENAPI_RESPONSE

    graph, paths = estate()
    result = priorities(monkeypatch, graph, paths)
    schema = _FIX_FIRST_VIEW_OPENAPI_RESPONSE["content"]["application/json"]["schema"]["properties"]["remediation_priorities"]
    jsonschema.validate(result, schema)


def test_cli_fixes_reads_server_priorities_and_preserves_snapshot(monkeypatch):
    import json

    from click.testing import CliRunner

    from agent_bom.cli import main

    calls = []
    graph, paths = estate()
    result = priorities(monkeypatch, graph, paths)

    class Client:
        def __init__(self, **kwargs):
            calls.append(kwargs)

        def graph_fix_priorities(self, **kwargs):
            calls.append(kwargs)
            return {"scan_id": graph.scan_id, "tenant_id": graph.tenant_id, "remediation_priorities": result}

        def close(self):
            pass

    monkeypatch.setattr("agent_bom.cli._findings_group.AgentBomClient", Client)
    command = CliRunner().invoke(main, ["graph-paths", "fixes", "--scan-id", graph.scan_id, "--format", "json"])
    assert command.exit_code == 0, command.output
    payload = json.loads(command.output)
    assert payload["scan_id"] == graph.scan_id
    assert payload["remediation_verified"] is False
    assert payload["recommendations"][0]["covered_paths"] == 2
    assert {"scan_id": graph.scan_id} in calls


def test_tenant_scope_and_generation_qualify_http_recommendations(tmp_path, monkeypatch):
    from starlette.testclient import TestClient

    from agent_bom.api import stores
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.routes.graph_routes import views
    from agent_bom.api.server import app

    graph, paths = estate()
    graph.tenant_id = "default"
    graph.attack_paths = paths
    store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    store.save_graph(graph)
    monkeypatch.setattr(stores, "_graph_store", store)
    monkeypatch.setattr(views, "evidence_generation", lambda *args, **kwargs: None)
    response = TestClient(app).get("/v1/graph/views/fix-first", params={"scan_id": graph.scan_id})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["snapshot_generation"]
    assert result["tenant_id"] == "default"
    assert result["remediation_priorities"]["remediation_verified"] is False
    assert result["remediation_priorities"]["candidate_count"] == 2
    assert result["remediation_priorities"]["recommendations"][0]["asset_node_id"] == "package:shared"
    graph.tenant_id = "other-tenant"
    graph.scan_id = "other-snapshot"
    store.save_graph(graph)
    response = TestClient(app).get("/v1/graph/views/fix-first", params={"scan_id": graph.scan_id})
    assert response.status_code == 404


def test_http_refuses_a_generation_changed_during_recommendation_read(tmp_path, monkeypatch):
    from starlette.testclient import TestClient

    from agent_bom.api import stores
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.routes.graph_routes import views
    from agent_bom.api.server import app

    graph, paths = estate()
    graph.tenant_id = "default"
    graph.attack_paths = paths
    store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    store.save_graph(graph)
    monkeypatch.setattr(stores, "_graph_store", store)
    monkeypatch.setattr(views, "evidence_generation", lambda *args, **kwargs: None)
    real = views._fix_first_graph_view_payload

    def replace_during_read(*args, **kwargs):
        result = real(*args, **kwargs)
        graph.nodes["package:shared"].label = "replacement"
        store.save_graph(graph)
        return result

    monkeypatch.setattr(views, "_fix_first_graph_view_payload", replace_during_read)
    response = TestClient(app).get("/v1/graph/views/fix-first", params={"scan_id": graph.scan_id})
    assert response.status_code == 409, response.text
