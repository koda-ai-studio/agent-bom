"""A local ``agents`` package is not the OpenAI Agents SDK.

``from agents.agent import Agent`` in a repository that ships its own
``agents/`` package produced one phantom OpenAI-Agents agent per ``Agent(...)``
call, a phantom ``openai-agents`` package (later registry-resolved), and the
same "not found in requirements" warning once per call. Framework evidence now
requires the import root to resolve to the SDK: either the PyPI package is
declared, or no local module of that name shadows the import.
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.ai_components.framework_agents import scan_framework_agents
from agent_bom.ai_components.scanner import scan_source
from agent_bom.python_agents import scan_python_agents

_TEST_FILE = (
    "from agents.agent import Agent\n"
    "\n"
    "class TestMessageParams:\n"
    "    def test_basic(self):\n"
    '        return Agent(name="BasicAgent", model="claude-x")\n'
    "\n"
    "    def test_headers(self):\n"
    '        return Agent(name="HeaderAgent", model="claude-x")\n'
)


def _local_agents_project(root: Path, requirements: str | None) -> Path:
    (root / "agents").mkdir()
    (root / "agents" / "__init__.py").write_text("from .agent import Agent\n")
    (root / "agents" / "agent.py").write_text("class Agent:\n    def __init__(self, name='', model=''):\n        self.name = name\n")
    (root / "test_message_params.py").write_text(_TEST_FILE)
    if requirements is not None:
        (root / "requirements.txt").write_text(requirements)
    return root


def _framework_packages(agents) -> set[tuple[str, str]]:
    return {(pkg.name, pkg.version) for agent in agents for server in agent.mcp_servers for pkg in server.packages}


def test_local_agents_package_without_sdk_yields_no_agents(tmp_path: Path) -> None:
    root = _local_agents_project(tmp_path, "anthropic==0.40.0\n")

    agents, warnings = scan_python_agents(str(root))

    assert agents == []
    assert not [w for w in warnings if "openai-agents" in w]
    assert scan_framework_agents(root) == []
    assert not [c for c in scan_source(root).components if c.package_name == "openai-agents"]


def test_declared_sdk_keeps_detection_even_with_local_agents_dir(tmp_path: Path) -> None:
    root = _local_agents_project(tmp_path, "openai-agents==0.1.0\n")

    agents, _warnings = scan_python_agents(str(root))

    assert len(agents) == 2
    assert ("openai-agents", "0.1.0") in _framework_packages(agents)
    assert {a.framework for a in scan_framework_agents(root)} == {"openai-agents"}
    assert [c for c in scan_source(root).components if c.package_name == "openai-agents"]


def test_sdk_import_without_local_shadow_is_still_detected(tmp_path: Path) -> None:
    (tmp_path / "bot.py").write_text(_TEST_FILE)

    agents, warnings = scan_python_agents(str(tmp_path))

    assert len(agents) == 2
    assert ("openai-agents", "unknown") in _framework_packages(agents)
    assert len([w for w in warnings if "not found in requirements" in w]) == 1


def test_agent_call_without_any_framework_import_is_not_an_agent(tmp_path: Path) -> None:
    (tmp_path / "loose.py").write_text("# agents live here\nclass Agent:\n    pass\n\na = Agent(name='Loose')\n")

    agents, warnings = scan_python_agents(str(tmp_path))

    assert agents == []
    assert warnings == []
