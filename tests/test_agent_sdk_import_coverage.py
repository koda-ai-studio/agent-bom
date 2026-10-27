"""Agent SDK imports identify packages and labels without claiming execution."""

import pytest

from agent_bom.ai_components import scan_source
from agent_bom.ai_components.models import AIComponentType
from agent_bom.ast_analyzer import analyze_project

PYTHON_SDKS = [
    ("nat", "nvidia-nat", "NVIDIA NeMo Agent Toolkit"),
    ("google.adk", "google-adk", "Google ADK"),
    ("claude_agent_sdk", "claude-agent-sdk", "Claude Agent SDK"),
    ("strands", "strands-agents", "Strands Agents"),
    ("bedrock_agentcore", "bedrock-agentcore", "Amazon Bedrock AgentCore"),
    ("azure.ai.agents", "azure-ai-agents", "Azure AI Agents"),
    ("agent_framework", "agent-framework-core", "Microsoft Agent Framework"),
]
JS_SDKS = [
    ("llamaindex", "llama-index", "LlamaIndex"),
    ("@google/adk", "google-adk", "Google ADK"),
    ("@anthropic-ai/claude-agent-sdk", "claude-agent-sdk", "Claude Agent SDK"),
    ("@strands-agents/sdk", "strands-agents", "Strands Agents"),
    ("@azure/ai-agents", "azure-ai-agents", "Azure AI Agents"),
    ("@openai/agents", "openai-agents", "OpenAI Agents"),
]


@pytest.mark.parametrize("module,package,label", PYTHON_SDKS)
@pytest.mark.parametrize("syntax", ["import {module}\n", "from {module}.tools import Tool\n"])
def test_python_sdk_component_and_ast_label(tmp_path, module, package, label, syntax):
    (tmp_path / "agent.py").write_text(syntax.format(module=module))
    components = scan_source(str(tmp_path)).components
    found = [c for c in components if c.package_name == package]
    assert len(found) == 1
    assert found[0].component_type == AIComponentType.AGENT_FRAMEWORK
    assert found[0].ecosystem == "pypi"
    assert label in analyze_project(tmp_path).frameworks_detected


@pytest.mark.parametrize("module,package,label", PYTHON_SDKS)
def test_python_near_names_do_not_match(tmp_path, module, package, label):
    (tmp_path / "agent.py").write_text(f"import {module}_helpers\nfrom app.{module} import Agent\n")
    assert package not in {c.package_name for c in scan_source(str(tmp_path)).components}
    assert label not in analyze_project(tmp_path).frameworks_detected


@pytest.mark.parametrize("module,name,label", JS_SDKS)
@pytest.mark.parametrize("syntax", ['import {{ Agent }} from "{module}";\n', 'const sdk = require("{module}/tools");\n'])
def test_javascript_sdk_component_and_ast_label(tmp_path, module, name, label, syntax):
    (tmp_path / "agent.ts").write_text(syntax.format(module=module))
    found = [c for c in scan_source(str(tmp_path)).components if c.package_name == module]
    assert len(found) == 1
    assert found[0].name == name
    assert found[0].component_type == AIComponentType.AGENT_FRAMEWORK
    assert found[0].ecosystem == "npm"
    assert label in analyze_project(tmp_path).frameworks_detected


@pytest.mark.parametrize("module,name,label", JS_SDKS)
def test_javascript_near_names_do_not_match(tmp_path, module, name, label):
    (tmp_path / "agent.ts").write_text(f'import {{ Agent }} from "{module}-helpers";\n')
    assert module not in {c.package_name for c in scan_source(str(tmp_path)).components}
    assert label not in analyze_project(tmp_path).frameworks_detected


def test_generic_cloud_clients_do_not_imply_agent_frameworks(tmp_path):
    (tmp_path / "client.py").write_text("import boto3\nimport azure.identity\nimport google.cloud\nimport anthropic\n")
    frameworks = {c.name for c in scan_source(str(tmp_path)).components if c.component_type == AIComponentType.AGENT_FRAMEWORK}
    assert frameworks == set()
    assert not analyze_project(tmp_path).frameworks_detected


@pytest.mark.parametrize(
    "module,expected",
    [("openclaw/plugin-sdk/plugin-entry", True), ("openclaw/plugin-sdk-helpers", False), ("openclaw_helpers/plugin-sdk", False)],
)
def test_openclaw_plugin_sdk_package_identity(tmp_path, module, expected):
    (tmp_path / "plugin.ts").write_text(f'import {{ definePluginEntry }} from "{module}";\n')
    found = [c for c in scan_source(str(tmp_path)).components if c.package_name == "openclaw"]
    assert bool(found) is expected
    assert ("OpenClaw" in analyze_project(tmp_path).frameworks_detected) is expected


@pytest.mark.parametrize(
    "filename,source,package",
    [
        ("agent.py", "from google.adk import Agent\n", "google-adk"),
        ("agent.ts", 'import { Agent } from "@google/adk";\n', "@google/adk"),
        ("plugin.js", 'const sdk = require("openclaw/plugin-sdk/plugin-entry");\n', "openclaw"),
    ],
)
def test_project_and_repo_inventory_preserve_sdk_evidence(tmp_path, filename, source, package):
    from agent_bom.api.repo_tree_scan import _scan_ai_inventory_stage
    from agent_bom.cli.agents._discovery_ai import _inventory_data
    from agent_bom.repo_auto_detect import expand_project_scan_targets

    (tmp_path / filename).write_text(source)
    targets = expand_project_scan_targets(tmp_path)
    assert targets.ai_inventory_paths == (str(tmp_path),)
    cli_evidence = _inventory_data(scan_source(str(tmp_path)))
    repo_evidence, agents = {}, []
    _scan_ai_inventory_stage(tmp_path, repo_evidence, agents, [], None)
    assert repo_evidence == cli_evidence
    assert package in {c["package"] for c in repo_evidence["components"]}
    assert package in {p.name for a in agents for s in a.mcp_servers for p in s.packages}
    assert all(c["file"] and c["line"] >= 1 for c in repo_evidence["components"])


@pytest.mark.parametrize(
    "filename,source,package,ecosystem",
    [("agent.py", f"import {module}\n", package, "pypi") for module, package, _ in PYTHON_SDKS]
    + [("agent.ts", f'import {{ Agent }} from "{module}";\n', module, "npm") for module, _, _ in JS_SDKS]
    + [("plugin.ts", 'import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";\n', "openclaw", "npm")],
)
def test_sdk_evidence_survives_model_graph_and_export_consumers(tmp_path, filename, source, package, ecosystem):
    from agent_bom.api.repo_tree_scan import _scan_ai_inventory_stage
    from agent_bom.db.graph_store import load_graph, open_graph_db, save_graph
    from agent_bom.graph.builder import build_unified_graph_from_report
    from agent_bom.graph.types import EntityType, RelationshipType
    from agent_bom.models import AIBOMReport
    from agent_bom.output.cyclonedx_fmt import to_cyclonedx
    from agent_bom.output.graph_evidence import graph_evidence_sections
    from agent_bom.output.html.sections_inventory import _ai_inventory_section
    from agent_bom.output.json_fmt import to_json
    from agent_bom.output.spdx2_fmt import to_spdx2

    (tmp_path / filename).write_text(source)
    inventory, agents = {}, []
    _scan_ai_inventory_stage(tmp_path, inventory, agents, [], None)
    report = AIBOMReport(agents=agents, blast_radii=[], ai_inventory_data=inventory)
    serialized = to_json(report)
    assert serialized["ai_inventory"] == inventory == graph_evidence_sections(report)["ai_inventory"]
    graph = build_unified_graph_from_report(serialized, scan_id="sdk-consumer", tenant_id="test")
    framework = next(n for n in graph.nodes_by_type(EntityType.FRAMEWORK) if n.attributes.get("package") == package)
    assert framework.attributes["ecosystem"] == ecosystem
    assert framework.attributes["file"].endswith(filename)
    assert framework.attributes["line"] == 1
    dependencies = [e.target for e in graph.edges if e.source == framework.id and e.relationship == RelationshipType.DEPENDS_ON]
    assert dependencies
    assert all(graph.nodes[n].attributes["ecosystem"] == ecosystem for n in dependencies)
    assert package in {c["name"] for c in to_cyclonedx(report)["components"]}
    assert package in {p["name"] for p in to_spdx2(report)["packages"]}
    assert inventory["components"][0]["name"] in _ai_inventory_section(report)
    with open_graph_db(tmp_path / "graph.db") as conn:
        save_graph(conn, graph)
    with open_graph_db(tmp_path / "graph.db") as conn:
        restored = load_graph(conn, tenant_id="test", scan_id="sdk-consumer")
    assert restored.nodes[framework.id].attributes == framework.attributes
    assert {e.target for e in restored.edges if e.source == framework.id and e.relationship == RelationshipType.DEPENDS_ON} == set(
        dependencies
    )
