"""The framework dependency check reads every pyproject dependency form."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agent_bom.python_agents import scan_python_agents

_FIXTURES = Path(__file__).parent / "fixtures" / "agent_frameworks"

_CREW_SOURCE = 'from crewai import Agent\n\nresearcher = Agent(role="researcher", goal="g", backstory="b")\n'

_PEP621 = """
[project]
name = "demo"
version = "0.1.0"
dependencies = ["crewai[tools]>=0.80.0", "requests"]
"""

_PEP621_OPTIONAL = """
[project]
name = "demo"
version = "0.1.0"
dependencies = []

[project.optional-dependencies]
agents = ["crewai[tools] == 0.86.0"]
"""

_POETRY = """
[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
crewai = {version = "^0.80.0", extras = ["tools"]}
"""

_POETRY_GROUP = """
[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.group.agents.dependencies]
crewai = "0.80.0"
"""


def _crew_project(tmp_path: Path, pyproject: str) -> Path:
    root = tmp_path / "crew"
    root.mkdir()
    (root / "crew.py").write_text(_CREW_SOURCE, encoding="utf-8")
    (root / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    return root


@pytest.mark.parametrize(
    ("pyproject", "version"),
    [
        (_PEP621, "0.80.0"),
        (_PEP621_OPTIONAL, "0.86.0"),
        (_POETRY, "0.80.0"),
        (_POETRY_GROUP, "0.80.0"),
    ],
    ids=["pep621", "pep621-optional", "poetry", "poetry-group"],
)
def test_pyproject_declared_framework_is_not_reported_missing(tmp_path: Path, pyproject: str, version: str) -> None:
    root = _crew_project(tmp_path, pyproject)

    agents, warnings = scan_python_agents(str(root))

    assert not [w for w in warnings if "not found in requirements" in w]
    packages = {(pkg.name, pkg.version) for agent in agents for server in agent.mcp_servers for pkg in server.packages}
    assert ("crewai", version) in packages


def test_framework_missing_from_pyproject_is_still_reported(tmp_path: Path) -> None:
    root = _crew_project(tmp_path, '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["requests"]\n')

    _, warnings = scan_python_agents(str(root))

    assert any("crewai" in w and "not found in requirements" in w for w in warnings)


def test_malformed_pyproject_does_not_abort_the_scan(tmp_path: Path) -> None:
    root = _crew_project(tmp_path, "[project\ndependencies = [")
    shutil.copy(_FIXTURES / "README.md", root / "README.md")

    agents, warnings = scan_python_agents(str(root))

    assert agents
    assert any("not found in requirements" in w for w in warnings)
