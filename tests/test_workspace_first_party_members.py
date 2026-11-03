"""A monorepo's own workspace packages are first-party, not undeclared dependencies.

Scanning the pydantic-ai repository reported "Framework 'pydantic-ai' ... not
found in requirements files" and added ``pydantic-ai@unknown``: the framework
is the repository itself (uv workspace root and members).
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_bom.parsers.workspace_members import first_party_package_names
from agent_bom.python_agents import scan_python_agents

_AGENT = 'from pydantic_ai import Agent\n\nagent = Agent("openai:gpt-4o", system_prompt="be brief")\n'


def _uv_monorepo(root: Path) -> None:
    (root / "pyproject.toml").write_text(
        '[project]\nname = "pydantic-ai"\nversion = "1.0.0"\n\n[tool.uv.workspace]\nmembers = ["pydantic_ai_slim", "libs/*"]\n',
        encoding="utf-8",
    )
    (root / "pydantic_ai_slim").mkdir()
    (root / "pydantic_ai_slim" / "pyproject.toml").write_text('[project]\nname = "pydantic_ai_slim"\nversion = "1.0.0"\n', encoding="utf-8")
    (root / "libs" / "graph").mkdir(parents=True)
    (root / "libs" / "graph" / "pyproject.toml").write_text('[project]\nname = "Pydantic.Graph"\n', encoding="utf-8")
    (root / "examples").mkdir()
    (root / "examples" / "bot.py").write_text(_AGENT, encoding="utf-8")


def test_uv_workspace_root_and_members_are_first_party(tmp_path: Path) -> None:
    _uv_monorepo(tmp_path)
    assert first_party_package_names(tmp_path)["pypi"] == {"pydantic-ai", "pydantic-ai-slim", "pydantic-graph"}


def test_npm_pnpm_and_cargo_workspaces_are_first_party(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"name": "@acme/root", "workspaces": {"packages": ["packages/*"]}}), encoding="utf-8")
    (tmp_path / "packages" / "core").mkdir(parents=True)
    (tmp_path / "packages" / "core" / "package.json").write_text(json.dumps({"name": "@acme/core"}), encoding="utf-8")
    (tmp_path / "pnpm-workspace.yaml").write_text("packages:\n  - 'apps/*'\n", encoding="utf-8")
    (tmp_path / "apps" / "web").mkdir(parents=True)
    (tmp_path / "apps" / "web" / "package.json").write_text(json.dumps({"name": "web-app"}), encoding="utf-8")
    (tmp_path / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/*"]\n', encoding="utf-8")
    (tmp_path / "crates" / "engine").mkdir(parents=True)
    (tmp_path / "crates" / "engine" / "Cargo.toml").write_text('[package]\nname = "engine"\nversion = "0.1.0"\n', encoding="utf-8")
    names = first_party_package_names(tmp_path)
    assert names["npm"] == {"@acme/root", "@acme/core", "web-app"}
    assert names["cargo"] == {"engine"}


def test_monorepo_framework_is_not_reported_as_undeclared(tmp_path: Path) -> None:
    _uv_monorepo(tmp_path)
    agents, warnings = scan_python_agents(str(tmp_path))
    assert agents
    assert not [w for w in warnings if "not found in requirements" in w]
    assert not [p for a in agents for s in a.mcp_servers for p in s.packages if p.version == "unknown"]


def test_third_party_framework_without_declaration_is_still_reported(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "my-bot"\nversion = "0.1.0"\n', encoding="utf-8")
    (tmp_path / "bot.py").write_text(_AGENT, encoding="utf-8")
    _agents, warnings = scan_python_agents(str(tmp_path))
    assert [w for w in warnings if "pydantic-ai" in w and "not found in requirements" in w]


def test_malformed_workspace_metadata_yields_no_first_party_names(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project\nname = ", encoding="utf-8")
    (tmp_path / "package.json").write_text("{", encoding="utf-8")
    assert first_party_package_names(tmp_path) == {"pypi": set(), "npm": set(), "cargo": set()}
