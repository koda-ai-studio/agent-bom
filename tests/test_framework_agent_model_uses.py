"""Each framework agent records the model(s) it uses, with provider and where it was declared."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom.ai_components.framework_agents import scan_framework_agents
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import EntityType, RelationshipType


def _scan(root: Path, files: dict[str, str]) -> dict[str, dict]:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return {agent["name"]: agent for agent in (a.to_dict() for a in scan_framework_agents(root))}


def _uses(agent: dict) -> list[tuple[str, str, str, str, int, str]]:
    return [(u["model"], u["provider"], u["declared_in"], u["file_path"], u["line_number"], u["env_var"]) for u in agent["model_uses"]]


def test_langgraph_agent_links_a_bound_chat_model_with_provider_and_line(tmp_path: Path) -> None:
    agents = _scan(
        tmp_path,
        {
            "graph.py": "from langchain_anthropic import ChatAnthropic\n"
            "from langchain.chat_models import init_chat_model\n"
            "from langgraph.prebuilt import create_react_agent\n"
            "llm = ChatAnthropic(model='claude-sonnet-4-5')\n"
            "writer = create_react_agent(llm, tools=[], name='writer')\n"
            "critic = create_react_agent(init_chat_model('openai:gpt-4o'), tools=[], name='critic')\n",
        },
    )

    assert _uses(agents["writer"]) == [("claude-sonnet-4-5", "anthropic", "code", "graph.py", 4, "")]
    assert agents["writer"]["model_uses"][0]["via"] == "ChatAnthropic(model=)"
    assert agents["writer"]["model_refs"] == ["claude-sonnet-4-5"]
    assert _uses(agents["critic"]) == [("openai:gpt-4o", "openai", "code", "graph.py", 6, "")]


def test_crewai_agent_links_its_llm_argument(tmp_path: Path) -> None:
    agents = _scan(
        tmp_path,
        {
            "crew.py": "from crewai import Agent, LLM\n"
            "writer = Agent(role='Writer', llm=LLM(model='anthropic/claude-3-5-sonnet-20241022'))\n"
            "editor = Agent(role='Editor', llm='gpt-4o')\n",
        },
    )

    assert _uses(agents["Writer"]) == [("anthropic/claude-3-5-sonnet-20241022", "anthropic", "code", "crew.py", 2, "")]
    assert _uses(agents["Editor"]) == [("gpt-4o", "openai", "code", "crew.py", 3, "")]


def test_crewai_agent_built_from_yaml_config_links_the_configured_llm(tmp_path: Path) -> None:
    agents = _scan(
        tmp_path,
        {
            "src/crew/config/agents.yaml": "researcher:\n  role: Researcher\n  goal: find things\n  llm: openai/gpt-4o-mini\n",
            "src/crew/crew.py": "from crewai import Agent\n"
            "from crewai.project import CrewBase, agent\n"
            "@CrewBase\n"
            "class Team:\n"
            "    agents_config = 'config/agents.yaml'\n"
            "    @agent\n"
            "    def researcher(self) -> Agent:\n"
            "        return Agent(config=self.agents_config['researcher'], name='researcher')\n",
        },
    )

    assert _uses(agents["researcher"]) == [("openai/gpt-4o-mini", "openai", "config", "src/crew/config/agents.yaml", 4, "")]


def test_crewai_yaml_config_outside_the_scanned_project_is_not_read(tmp_path: Path) -> None:
    outside = tmp_path / "outside.yaml"
    outside.write_text("researcher:\n  llm: gpt-4o\n", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    agents = _scan(
        project,
        {
            "crew.py": "from crewai import Agent\n"
            "class Team:\n"
            "    agents_config = '../outside.yaml'\n"
            "    def researcher(self):\n"
            "        return Agent(config=self.agents_config['researcher'], name='researcher')\n",
        },
    )

    assert agents["researcher"]["model_uses"] == []


def test_autogen_agents_link_llm_config_and_model_client(tmp_path: Path) -> None:
    agents = _scan(
        tmp_path,
        {
            "classic.py": "import os\n"
            "from autogen import AssistantAgent\n"
            "config_list = [{'model': 'gpt-4o', 'api_key': os.environ['OPENAI_API_KEY']}]\n"
            "assistant = AssistantAgent('assistant', llm_config={'config_list': config_list})\n",
            "modern.py": "from autogen_agentchat.agents import AssistantAgent\n"
            "from autogen_ext.models.anthropic import AnthropicChatCompletionClient\n"
            "planner = AssistantAgent('planner', model_client=AnthropicChatCompletionClient(model='claude-3-7-sonnet-20250219'))\n",
        },
    )

    assert _uses(agents["assistant"]) == [("gpt-4o", "openai", "config", "classic.py", 3, "")]
    assert _uses(agents["planner"]) == [("claude-3-7-sonnet-20250219", "anthropic", "code", "modern.py", 3, "")]


def test_openai_agents_sdk_links_literal_and_wrapped_models(tmp_path: Path) -> None:
    agents = _scan(
        tmp_path,
        {
            "triage.py": "from agents import Agent\n"
            "from agents.extensions.models.litellm_model import LitellmModel\n"
            "triage = Agent(name='Triage', model='gpt-4.1')\n"
            "helper = Agent(name='Helper', model=LitellmModel(model='anthropic/claude-3-5-sonnet-20240620'))\n",
        },
    )

    assert _uses(agents["Triage"]) == [("gpt-4.1", "openai", "code", "triage.py", 3, "")]
    assert _uses(agents["Helper"]) == [("anthropic/claude-3-5-sonnet-20240620", "anthropic", "code", "triage.py", 4, "")]


def test_env_selected_model_records_the_variable_name_never_its_value(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_MODEL", "secret-model-value-123")
    monkeypatch.setenv("FALLBACK_MODEL", "secret-model-value-456")
    monkeypatch.setenv("CREW_MODEL", "secret-model-value-789")
    agents = _scan(
        tmp_path,
        {
            "env_agents.py": "import os\n"
            "from agents import Agent\n"
            "MODEL = os.environ['CREW_MODEL']\n"
            "a = Agent(name='A', model=os.getenv('AGENT_MODEL'))\n"
            "b = Agent(name='B', model=os.environ.get('FALLBACK_MODEL', 'gpt-4o-mini'))\n"
            "c = Agent(name='C', model=MODEL)\n",
        },
    )

    assert _uses(agents["A"]) == [("", "", "env", "env_agents.py", 4, "AGENT_MODEL")]
    assert _uses(agents["B"]) == [("gpt-4o-mini", "openai", "env", "env_agents.py", 5, "FALLBACK_MODEL")]
    assert _uses(agents["C"]) == [("", "", "env", "env_agents.py", 3, "CREW_MODEL")]
    assert agents["A"]["model_refs"] == []
    assert agents["B"]["model_refs"] == ["gpt-4o-mini"]

    graph = build_unified_graph_from_report({"ai_inventory": {"framework_agents": list(agents.values())}, "agents": []})
    dumped = json.dumps(list(agents.values())) + json.dumps(graph.to_dict(), default=str)
    assert "secret-model-value" not in dumped
    env_edges = [e for e in graph.edges if e.relationship == RelationshipType.SERVES_MODEL and e.evidence.get("env_var") == "AGENT_MODEL"]
    assert len(env_edges) == 1
    env_model = graph.nodes[env_edges[0].target]
    assert env_model.entity_type == EntityType.MODEL
    assert env_model.label == "env:AGENT_MODEL"
    assert env_model.attributes["selected_by_env"] == "AGENT_MODEL"


def test_graph_serves_model_edge_carries_provider_and_declaration(tmp_path: Path) -> None:
    agents = _scan(
        tmp_path,
        {
            "triage.py": "from agents import Agent\ntriage = Agent(name='Triage', model='gpt-4.1')\n",
        },
    )

    graph = build_unified_graph_from_report({"ai_inventory": {"framework_agents": list(agents.values())}, "agents": []})

    edges = [e for e in graph.edges if e.relationship == RelationshipType.SERVES_MODEL]
    assert len(edges) == 1
    edge = edges[0]
    assert edge.source == agents["Triage"]["stable_id"]
    assert graph.nodes[edge.target].label == "gpt-4.1"
    assert graph.nodes[edge.target].attributes["provider"] == "openai"
    assert {k: edge.evidence[k] for k in ("model_ref", "provider", "declared_in", "file_path", "line_number", "via")} == {
        "model_ref": "gpt-4.1",
        "provider": "openai",
        "declared_in": "code",
        "file_path": "triage.py",
        "line_number": 2,
        "via": "Agent(model=)",
    }


def test_payload_without_model_uses_still_links_model_refs() -> None:
    agent = {"stable_id": "fa-1", "name": "legacy", "framework": "crewai", "model_refs": ["gpt-4o"]}

    graph = build_unified_graph_from_report({"ai_inventory": {"framework_agents": [agent]}, "agents": []})

    edges = [e for e in graph.edges if e.relationship == RelationshipType.SERVES_MODEL]
    assert [(e.source, graph.nodes[e.target].label, e.evidence["model_ref"]) for e in edges] == [("fa-1", "gpt-4o", "gpt-4o")]


def test_folded_construct_keeps_its_model_on_the_project_agent(tmp_path: Path) -> None:
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.framework_topology_projection import _add_framework_topology
    from agent_bom.graph.node import UnifiedNode

    agents = _scan(tmp_path, {"triage.py": "from agents import Agent\ntriage = Agent(name='Triage', model='gpt-4.1')\n"})
    graph = UnifiedGraph()
    graph.add_node(UnifiedNode(id="host", entity_type=EntityType.AGENT, label="project"))

    _add_framework_topology(graph, list(agents.values()), "test", host_agent_id="host")

    edges = [e for e in graph.edges if e.relationship == RelationshipType.SERVES_MODEL]
    assert [(e.source, graph.nodes[e.target].label, e.evidence["line_number"]) for e in edges] == [("host", "gpt-4.1", 2)]
    folded = graph.nodes["host"].attributes["code_agents"]
    assert [(entry["name"], [use["model"] for use in entry["model_uses"]]) for entry in folded] == [("Triage", ["gpt-4.1"])]
