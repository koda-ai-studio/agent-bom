"""Regression tests for evidence-bounded MITRE ATLAS mapping."""

from agent_bom.atlas import tag_blast_radius
from agent_bom.models import Agent, AgentType, BlastRadius, Package, Severity, Vulnerability


def _blast_radius(*, package: str, affected_agents: list[Agent] | None = None) -> BlastRadius:
    return BlastRadius(
        vulnerability=Vulnerability(
            id="CVE-2026-1000",
            summary="Generic dependency vulnerability",
            severity=Severity.LOW,
        ),
        package=Package(name=package, version="1.0.0", ecosystem="pypi"),
        affected_servers=[],
        affected_agents=affected_agents or [],
        exposed_credentials=[],
        exposed_tools=[],
    )


def test_generic_dependency_without_ai_path_is_not_ai_supply_chain_compromise():
    tags = tag_blast_radius(_blast_radius(package="flask"))

    assert "AML.T0010" not in tags
    assert "AML.T0010.001" not in tags


def test_agent_inventory_does_not_establish_supply_chain_compromise():
    agent = Agent(
        name="Claude Desktop",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/claude.json",
    )

    tags = tag_blast_radius(_blast_radius(package="flask", affected_agents=[agent]))

    assert "AML.T0010" not in tags
    assert "AML.T0010.001" not in tags


def test_ai_framework_name_does_not_establish_supply_chain_compromise():
    tags = tag_blast_radius(_blast_radius(package="langchain"))

    assert "AML.T0010" not in tags
    assert "AML.T0010.001" not in tags


def test_inventory_capabilities_do_not_invent_adversary_techniques():
    from agent_bom.models import MCPTool

    br = _blast_radius(package="langchain")
    br.vulnerability.severity = Severity.CRITICAL
    br.exposed_credentials = ["API_KEY"]
    br.exposed_tools = [MCPTool(name="execute_shell", description="Run commands"), MCPTool(name="read_file", description="Read files")]
    assert tag_blast_radius(br) == []


def test_explicit_catalog_bridge_preserves_weakness_applicability(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_MITRE_CATALOG_MODE", "bundled")
    monkeypatch.setenv("AGENT_BOM_ATLAS_CATALOG_MODE", "bundled")
    br = _blast_radius(
        package="langchain", affected_agents=[Agent(name="client", agent_type=AgentType.CODEX_CLI, config_path="config.json")]
    )
    br.vulnerability.cwe_ids = ["CWE-285"]
    # The bundled CAPEC bridge maps CWE-285 to T1005; ATLAS explicitly
    # references T1005 from AML.T0037. This is applicability, not execution.
    assert tag_blast_radius(br) == ["AML.T0037"]


def test_mapping_receipts_are_frozen_at_scan_time(monkeypatch):
    from agent_bom.finding import blast_radius_to_finding
    from agent_bom.scanners.package_scan import apply_framework_tags

    monkeypatch.setenv("AGENT_BOM_MITRE_CATALOG_MODE", "bundled")
    monkeypatch.setenv("AGENT_BOM_ATLAS_CATALOG_MODE", "bundled")
    br = _blast_radius(
        package="langchain", affected_agents=[Agent(name="client", agent_type=AgentType.CODEX_CLI, config_path="config.json")]
    )
    br.vulnerability.cwe_ids = ["CWE-285"]
    apply_framework_tags(br)
    original = blast_radius_to_finding(br).to_dict()["evidence"]["atlas_mapping_evidence"]
    monkeypatch.setattr("agent_bom.atlas_fetch.build_catalog", lambda: {"techniques": {}})
    assert blast_radius_to_finding(br).to_dict()["evidence"]["atlas_mapping_evidence"] == original
    receipt = original["AML.T0037"]
    assert receipt["basis"] == "catalog_weakness_association"
    assert receipt["execution_proven"] is False
    assert receipt["attack_reference"] == "T1005"
    assert len(receipt["atlas_catalog_sha256"]) == 64
    assert len(receipt["attack_catalog_sha256"]) == 64
    assert "_path" not in receipt


def test_legacy_tag_does_not_acquire_new_source_receipt(monkeypatch):
    from agent_bom.finding import blast_radius_to_finding

    monkeypatch.setenv("AGENT_BOM_MITRE_CATALOG_MODE", "bundled")
    monkeypatch.setenv("AGENT_BOM_ATLAS_CATALOG_MODE", "bundled")
    br = _blast_radius(package="langchain")
    br.vulnerability.cwe_ids = ["CWE-285"]
    br.atlas_tags = ["AML.T0037"]
    finding = blast_radius_to_finding(br).to_dict()
    assert finding["atlas_tags"] == ["AML.T0037"]
    assert "atlas_mapping_evidence" not in finding["evidence"]


def test_partial_catalog_entries_do_not_abort_or_expand_reference_matches(monkeypatch):
    monkeypatch.setattr("agent_bom.mitre_fetch.build_catalog", lambda: {"cwe_to_attack": {"CWE-285": ["T1005.001"]}})
    monkeypatch.setattr(
        "agent_bom.atlas_fetch.build_catalog",
        lambda: {
            "techniques": {
                "AML.T0037": {"attck_reference": "T1005"},
                "AML.T0053": None,
                "AML.T0055": {"attck_reference": ["T1005.001"]},
            }
        },
    )
    br = _blast_radius(
        package="langchain", affected_agents=[Agent(name="client", agent_type=AgentType.CODEX_CLI, config_path="config.json")]
    )
    br.vulnerability.cwe_ids = ["CWE-285"]
    assert tag_blast_radius(br) == []


def source_backed_report():
    from agent_bom.models import AIBOMReport, MCPServer
    from agent_bom.scanners.package_scan import apply_framework_tags

    br = _blast_radius(package="langchain")
    br.vulnerability.cwe_ids = ["CWE-285"]
    br.package.vulnerabilities = [br.vulnerability]
    server = MCPServer(name="reader", command="python", packages=[br.package])
    agent = Agent(name="reader-agent", agent_type=AgentType.CUSTOM, config_path="config.json", mcp_servers=[server])
    br.affected_agents = [agent]
    br.affected_servers = [server]
    apply_framework_tags(br)
    return AIBOMReport(agents=[agent], blast_radii=[br], scan_id="atlas-receipt")


def test_source_receipts_reconcile_across_machine_exports(monkeypatch):
    import json

    from agent_bom.output import to_cyclonedx, to_json, to_sarif, to_spdx

    monkeypatch.setenv("AGENT_BOM_MITRE_CATALOG_MODE", "bundled")
    monkeypatch.setenv("AGENT_BOM_ATLAS_CATALOG_MODE", "bundled")
    report = source_backed_report()
    payload = to_json(report)
    expected = payload["findings"][0]["evidence"]["atlas_mapping_evidence"]
    assert payload["blast_radius"][0]["atlas_mapping_evidence"] == expected
    assert to_sarif(report)["runs"][0]["results"][0]["properties"]["atlas_mapping_evidence"] == expected
    cdx = to_cyclonedx(report)
    props = [p for v in cdx["vulnerabilities"] for p in v["properties"] if p["name"] == "agent-bom:atlas-mapping-evidence"]
    assert len(props) == 1
    assert json.loads(props[0]["value"])["receipts"][0]["techniques"] == expected
    spdx = to_spdx(report)
    statements = [
        e["statement"]
        for e in spdx["@graph"]
        if e.get("type") == "Annotation" and e.get("statement", "").startswith("agent-bom:atlas-mapping-evidence=")
    ]
    assert len(statements) == 1
    assert json.loads(statements[0].split("=", 1)[1])[0]["techniques"] == expected


def test_mapping_receipts_survive_database_api_and_graph_export(monkeypatch, tmp_path):
    from starlette.testclient import TestClient

    from agent_bom.api import stores
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.server import app
    from agent_bom.api.store import SQLiteJobStore
    from agent_bom.graph.builder import build_unified_graph_from_report
    from agent_bom.output import to_json

    monkeypatch.setenv("AGENT_BOM_MITRE_CATALOG_MODE", "bundled")
    monkeypatch.setenv("AGENT_BOM_ATLAS_CATALOG_MODE", "bundled")
    payload = to_json(source_backed_report())
    expected = payload["findings"][0]["evidence"]["atlas_mapping_evidence"]
    graph = build_unified_graph_from_report(payload, scan_id="atlas-receipt", tenant_id="default")
    database = tmp_path / "graph.db"
    SQLiteGraphStore(database).save_graph(graph)
    graphs = SQLiteGraphStore(database)
    reopened = graphs.load_graph(tenant_id="default", scan_id="atlas-receipt")
    assert reopened is not None
    edges = [e for e in reopened.edges if e.evidence.get("atlas_mapping_receipts")]
    assert edges and all(e.evidence["atlas_mapping_receipts"][0]["techniques"] == expected for e in edges)
    jobs = SQLiteJobStore(str(tmp_path / "jobs.db"))
    jobs.put(
        ScanJob(job_id="atlas-receipt", status=JobStatus.DONE, created_at="2026-10-16T00:00:00Z", request=ScanRequest(), result=payload)
    )
    monkeypatch.setattr(stores, "_store", SQLiteJobStore(str(tmp_path / "jobs.db")))
    monkeypatch.setattr(stores, "_graph_store", graphs)
    client = TestClient(app)
    response = client.get("/v1/scan/atlas-receipt")
    assert response.status_code == 200
    rows = response.json()["result"]["findings"]
    assert any(row.get("evidence", {}).get("atlas_mapping_evidence") == expected for row in rows), [
        (row.get("finding_type"), list(row.get("evidence", {}))) for row in rows
    ]
    for url in ("/v1/graph?scan_id=atlas-receipt", "/v1/scan/atlas-receipt/graph-export?format=json"):
        response = client.get(url)
        assert response.status_code == 200
        exported = [e for e in response.json()["edges"] if e["evidence"].get("atlas_mapping_receipts")]
        # The export carries the persisted graph's edges, agent/server rollups included.
        assert len(exported) == len(edges)
        assert all(e["evidence"]["atlas_mapping_receipts"][0]["techniques"] == expected for e in exported)


def test_public_receipt_projection_drops_free_text_and_rejects_execution_claims(monkeypatch):
    from copy import deepcopy

    from agent_bom.finding_scope import safe_finding_response_payload

    monkeypatch.setenv("AGENT_BOM_MITRE_CATALOG_MODE", "bundled")
    monkeypatch.setenv("AGENT_BOM_ATLAS_CATALOG_MODE", "bundled")
    row = source_backed_report().to_findings()[0].to_dict()
    receipt = row["evidence"]["atlas_mapping_evidence"]["AML.T0037"]
    receipt.update(private_path="/private/hidden/config", technique_url="https://secret.example/private")
    safe = safe_finding_response_payload(row)["evidence"]["atlas_mapping_evidence"]["AML.T0037"]
    assert "private_path" not in safe
    assert safe["technique_url"] == "https://atlas.mitre.org/techniques/AML.T0037"
    for key, value in (("execution_proven", True), ("attack_catalog_sha256", "not-a-hash"), ("attack_reference", "private-secret")):
        changed = deepcopy(row)
        changed["evidence"]["atlas_mapping_evidence"]["AML.T0037"][key] = value
        assert "atlas_mapping_evidence" not in safe_finding_response_payload(changed).get("evidence", {})


def test_conflicting_catalog_receipts_stay_separate_and_order_independent():
    from copy import deepcopy

    from agent_bom.graph.edge import merge_edge_evidence

    first = {"atlas_mapping_receipts": [{"finding_ids": ["finding:a"], "techniques": {"AML.T0037": {"atlas_catalog_sha256": "a" * 64}}}]}
    second = {"atlas_mapping_receipts": [{"finding_ids": ["finding:a"], "techniques": {"AML.T0037": {"atlas_catalog_sha256": "b" * 64}}}]}
    left, right = deepcopy(first), deepcopy(second)
    merge_edge_evidence(left, second)
    merge_edge_evidence(right, first)
    assert left == right
    assert len(left["atlas_mapping_receipts"]) == 2
    merge_edge_evidence(left, {"atlas_mapping_receipts": 7})
    assert len(left["atlas_mapping_receipts"]) == 2


def test_synthetic_non_ai_inventory_does_not_qualify_for_atlas(monkeypatch):
    from agent_bom.models import MCPServer, ServerSurface

    monkeypatch.setenv("AGENT_BOM_MITRE_CATALOG_MODE", "bundled")
    monkeypatch.setenv("AGENT_BOM_ATLAS_CATALOG_MODE", "bundled")
    br = _blast_radius(package="requests")
    br.vulnerability.cwe_ids = ["CWE-285"]
    server = MCPServer(name="image", command="docker", surface=ServerSurface.CONTAINER_IMAGE)
    br.affected_servers = [server]
    br.affected_agents = [Agent(name="image:example", agent_type=AgentType.CUSTOM, config_path="image://example", mcp_servers=[server])]
    assert tag_blast_radius(br) == []


def test_package_name_alone_does_not_prove_ai_context(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_MITRE_CATALOG_MODE", "bundled")
    monkeypatch.setenv("AGENT_BOM_ATLAS_CATALOG_MODE", "bundled")
    for ecosystem in ("pypi", "npm", "maven"):
        br = _blast_radius(package="langchain")
        br.package.ecosystem = ecosystem
        br.vulnerability.cwe_ids = ["CWE-285"]
        assert tag_blast_radius(br) == []


def test_human_reports_preserve_mapping_sources_and_do_not_score_atlas(monkeypatch):
    from agent_bom.output.html.sections import _compliance_section
    from agent_bom.output.markdown import to_markdown

    monkeypatch.setenv("AGENT_BOM_MITRE_CATALOG_MODE", "bundled")
    monkeypatch.setenv("AGENT_BOM_ATLAS_CATALOG_MODE", "bundled")
    report = source_backed_report()
    finding = report.to_findings()[0]
    finding.owasp_tags = []
    finding.nist_ai_rmf_tags = []
    finding.owasp_agentic_tags = []
    finding.eu_ai_act_tags = []
    html = _compliance_section([finding])
    assert "1 applicable /" in html
    assert "no control was evaluated" in html
    receipt = finding.evidence["atlas_mapping_evidence"]["AML.T0037"]
    for rendered in (html, to_markdown(report)):
        assert "execution not established" in rendered
        assert "CWE-285" in rendered and "T1005" in rendered
        assert receipt["atlas_catalog_sha256"] in rendered
        assert receipt["attack_catalog_sha256"] in rendered


def test_catalog_without_source_digest_cannot_qualify_mapping(monkeypatch):
    monkeypatch.setattr("agent_bom.mitre_fetch.build_catalog", lambda: {"cwe_to_attack": {"CWE-285": ["T1005"]}})
    monkeypatch.setattr("agent_bom.atlas_fetch.build_catalog", lambda: {"techniques": {"AML.T0037": {"attck_reference": "T1005"}}})
    br = _blast_radius(
        package="langchain", affected_agents=[Agent(name="client", agent_type=AgentType.CODEX_CLI, config_path="config.json")]
    )
    br.vulnerability.cwe_ids = ["CWE-285"]
    assert tag_blast_radius(br) == []


def test_legacy_blast_object_without_receipt_field_remains_readable():
    from agent_bom.finding import blast_radius_to_finding

    br = _blast_radius(package="langchain")
    br.atlas_tags = ["AML.T0037"]
    del br.atlas_mapping_evidence
    finding = blast_radius_to_finding(br)
    assert finding.atlas_tags == ["AML.T0037"]
    assert "atlas_mapping_evidence" not in finding.evidence
