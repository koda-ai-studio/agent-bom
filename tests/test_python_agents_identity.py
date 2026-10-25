"""Same-named framework agents defined in different files or scopes stay distinct."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agent_bom.canonical_ids import agent_graph_id_for
from agent_bom.python_agents import scan_python_agents

_FIXTURES = Path(__file__).parent / "fixtures" / "agent_frameworks"


def _project(tmp_path: Path, name: str, manifest: str) -> Path:
    root = tmp_path / "proj"
    shutil.copytree(_FIXTURES / name, root)
    (root / "requirements.txt").write_text(manifest, encoding="utf-8")
    return root


def _tools(agent) -> set[str]:
    return {tool.name for server in agent.mcp_servers for tool in server.tools}


def test_same_named_autogen_agents_in_two_files_stay_distinct(tmp_path: Path) -> None:
    root = _project(tmp_path, "autogen_same_name", "autogen-agentchat==0.4.0\n")

    agents, _ = scan_python_agents(str(root))

    assistants = [agent for agent in agents if agent.name.endswith("assistant")]
    assert len(assistants) == 2
    assert len({agent_graph_id_for(agent) for agent in assistants}) == 2
    by_file = {Path(agent.config_path).name: _tools(agent) for agent in assistants}
    assert by_file == {"app_team.py": {"team_lookup"}, "app_agent.py": {"weather_tool"}}


def test_same_named_agents_in_different_functions_of_one_file_stay_distinct(tmp_path: Path) -> None:
    root = _project(tmp_path, "agents_sdk_same_name", "openai-agents==0.1.0\n")

    agents, _ = scan_python_agents(str(root))

    helpers = [agent for agent in agents if "helper" in agent.name]
    assert len(helpers) == 3
    assert len({agent_graph_id_for(agent) for agent in helpers}) == 3
    scopes = sorted(str(agent.metadata.get("definition_scope", "")) for agent in helpers)
    assert scopes == ["", "build_billing", "build_support"]


def test_agent_identity_is_stable_across_rescans(tmp_path: Path) -> None:
    root = _project(tmp_path, "autogen_same_name", "autogen-agentchat==0.4.0\n")

    first = sorted(agent_graph_id_for(agent) for agent in scan_python_agents(str(root))[0])
    second = sorted(agent_graph_id_for(agent) for agent in scan_python_agents(str(root))[0])

    assert first == second


@pytest.mark.parametrize("parent", ["tests", "test"])
def test_project_under_a_tests_named_parent_is_still_scanned(tmp_path: Path, parent: str) -> None:
    root = tmp_path / parent / "proj"
    shutil.copytree(_FIXTURES / "autogen_same_name", root)

    agents, _ = scan_python_agents(str(root))

    assert len(agents) == 2
