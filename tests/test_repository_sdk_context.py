"""Python SDK imports/calls are static evidence, never runtime reach or permissions."""

import json

from agent_bom.parsers import summarize_project_inventory
from tests.test_repository_dbt_lineage import put


def test_sdk_alias_calls_relative_import_and_agent_declaration(tmp_path):
    put(tmp_path, "package.json", {"name": "app"})
    put(
        tmp_path,
        "app/main.py",
        """from openai import OpenAI as Client
from agents import Agent as Assistant
from . import helpers
client = Client(api_key='must-not-retain-placeholder')
result = client.responses.create(input='private prompt')
assistant = Assistant(name='shop')
""",
    )
    put(tmp_path, "app/helpers.py", "raise RuntimeError('do not execute')\n")
    result = summarize_project_inventory(tmp_path, {})["repository_context"].get("code")
    assert result is not None, "Static SDK context is missing"
    source = next(row for row in result["files"] if row["path"] == "app/main.py")
    assert {row["symbol"] for row in source["calls"]} >= {"openai.OpenAI", "openai.OpenAI.responses.create", "agents.Agent"}
    assert source["implementations"] == [{"name": "assistant", "symbol": "agents.Agent", "line": 6}]
    assert any(row.get("target_path") == "app/helpers.py" for row in source["imports"])
    assert "private prompt" not in json.dumps(result) and "must-not-retain" not in json.dumps(result)


def test_sdk_shadowing_dynamic_import_and_workspace_escape_are_unresolved(tmp_path):
    put(tmp_path, "package.json", {"name": "root", "workspaces": ["apps/*"]})
    put(tmp_path, "apps/one/package.json", {"name": "one"})
    put(
        tmp_path,
        "apps/one/main.py",
        """import openai as ai
from ..two import helper
ai = replacement
ai.responses.create()
__import__(dynamic_name)
""",
    )
    put(tmp_path, "apps/two/helper.py", "import boto3\n")
    result = summarize_project_inventory(tmp_path, {})["repository_context"].get("code")
    assert result is not None
    source = next(row for row in result["files"] if row["path"] == "apps/one/main.py")
    assert source["calls"] == []
    assert not any(row.get("target_path") == "apps/two/helper.py" for row in source["imports"])
    assert {r["reason"] for r in result["unresolved"]} >= {"local_import_outside_workspace", "dynamic_import_unresolved"}


def test_function_parameters_and_control_flow_do_not_invent_sdk_call_targets(tmp_path):
    put(
        tmp_path,
        "main.py",
        """import openai as ai
def unknown(ai):
    ai.responses.create()
def known():
    ai.OpenAI()
if condition:
    client = ai.OpenAI()
client.responses.create()
""",
    )
    result = summarize_project_inventory(tmp_path, {})["repository_context"].get("code")
    assert result is not None
    source = result["files"][0]
    assert [row["line"] for row in source["calls"]] == [5]
    assert result["status"] == "partial"


def test_sdk_graph_scoped_imports_and_implementation_artifacts(tmp_path):
    from agent_bom.graph.builder import build_unified_graph_from_report

    put(tmp_path, "main.py", "from agents import Agent\nassistant = Agent(name='demo')\n")
    graph = build_unified_graph_from_report({"agents": [], "project_inventory": summarize_project_inventory(tmp_path, {})})
    implementations = [n for n in graph.nodes.values() if n.attributes.get("subtype") == "agent_implementation"]
    assert len(implementations) == 1 and implementations[0].entity_type.value == "code_module"
    imports = [e for e in graph.edges if e.relationship.value == "imports"]
    assert imports and all(not edge.traversable and edge.evidence["tier"] == "static_scan" for edge in imports)
    assert not any(edge.relationship.value in {"invokes", "can_access", "has_permission"} for edge in graph.edges)


def test_reimport_delete_and_non_constructor_returns_drop_sdk_alias(tmp_path):
    put(
        tmp_path,
        "main.py",
        """import openai as ai
client = ai.OpenAI()
result = client.responses.create()
result.some_method()
import unrelated as ai
ai.OpenAI()
del client
client.responses.create()
""",
    )
    result = summarize_project_inventory(tmp_path, {})["repository_context"]["code"]
    assert [row["line"] for row in result["files"][0]["calls"]] == [2, 3]
