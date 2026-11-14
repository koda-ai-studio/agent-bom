"""An SDK import never adds an unpinned ``latest`` package beside the version a manifest pins."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from agent_bom.discovery.identity import consolidate_project_agents
from agent_bom.models import Agent, AgentType, MCPServer, Package, ServerSurface


def _manifest_agent(root: Path, *packages: Package) -> Agent:
    return Agent(
        name=f"project:{root.name}",
        agent_type=AgentType.CUSTOM,
        config_path=str(root),
        source="project",
        mcp_servers=[MCPServer(name=root.name, command="project", surface=ServerSurface.OTHER, packages=list(packages))],
    )


def _ai_agent(root: Path, *names: str) -> Agent:
    return Agent(
        name="ai-inventory",
        agent_type=AgentType.CUSTOM,
        config_path=str(root),
        source="ai-inventory",
        metadata={"project_root": str(root.resolve())},
        mcp_servers=[
            MCPServer(
                name="ai-inventory",
                surface=ServerSurface.AI_INVENTORY,
                packages=[Package(name=name, version="latest", ecosystem="pypi") for name in names],
            )
        ],
    )


def _versions(agents: list[Agent]) -> dict[str, list[str]]:
    seen: dict[str, list[str]] = {}
    for agent in agents:
        for server in agent.mcp_servers:
            for package in server.packages:
                seen.setdefault(f"{agent.name}:{package.name}", []).append(package.version)
    return {key: sorted(value) for key, value in seen.items()}


def test_manifest_pin_replaces_the_sdk_latest_package(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    merged = consolidate_project_agents(
        [
            _ai_agent(root, "langchain", "Langchain_Community", "openai"),
            _manifest_agent(
                root,
                Package(name="langchain", version="0.0.200", ecosystem="pypi"),
                Package(name="langchain-community", version="0.0.10", ecosystem="pypi"),
            ),
        ]
    )

    assert _versions(merged) == {
        "project:proj:langchain": ["0.0.200"],
        "project:proj:langchain-community": ["0.0.10"],
        # Imported but not declared: kept as evidence of an undeclared SDK.
        "project:proj:openai": ["latest"],
    }


def test_another_projects_pin_does_not_hide_the_sdk(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    merged = consolidate_project_agents(
        [
            _ai_agent(first, "langchain"),
            _manifest_agent(first, Package(name="requests", version="2.31.0", ecosystem="pypi")),
            _manifest_agent(second, Package(name="langchain", version="0.0.200", ecosystem="pypi")),
        ]
    )

    assert _versions(merged)["project:first:langchain"] == ["latest"]


def test_other_ecosystem_with_same_name_does_not_count_as_a_pin(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    merged = consolidate_project_agents(
        [_ai_agent(root, "openai"), _manifest_agent(root, Package(name="openai", version="4.0.0", ecosystem="npm"))]
    )

    assert _versions(merged)["project:proj:openai"] == ["4.0.0", "latest"]


def _sdk_project(tmp_path: Path) -> Path:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text("langchain==0.0.200\nrequests==2.31.0\n", encoding="utf-8")
    (project / "app.py").write_text("import langchain\nimport openai\nfrom langchain.llms import OpenAI\n", encoding="utf-8")
    return project


def test_repo_tree_scan_reports_only_the_pinned_sdk_version(tmp_path):
    from agent_bom.api.repo_tree_scan import scan_cloned_repo_tree

    project = _sdk_project(tmp_path)
    unrelated = _manifest_agent(tmp_path / "elsewhere", Package(name="openai", version="1.0.0", ecosystem="pypi"))
    agents: list[Agent] = [unrelated]
    scan_cloned_repo_tree(str(project), agents=agents, warnings=[], offline=True)

    ai_servers = [server for agent in agents for server in agent.mcp_servers if server.surface is ServerSurface.AI_INVENTORY]
    assert ai_servers, "the SDK imports were not inventoried"
    ai_versions = {package.name: package.version for server in ai_servers for package in server.packages}
    assert "langchain" not in ai_versions
    # A pin in another, unrelated project does not hide this project's undeclared import.
    assert ai_versions["openai"] == "latest"


def test_scan_reports_only_the_pinned_sdk_version(tmp_path):
    from agent_bom.cli import main
    from agent_bom.output.report_packing import load_report_document

    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text("langchain==0.0.200\nrequests==2.31.0\n", encoding="utf-8")
    (project / "app.py").write_text("import langchain\nimport openai\nfrom langchain.llms import OpenAI\n", encoding="utf-8")
    report = tmp_path / "report.json"

    result = CliRunner().invoke(
        main,
        [
            "scan",
            "-p",
            str(project),
            "--ai-inventory",
            str(project),
            "--offline",
            "--no-scan",
            "--no-discover",
            "--exit-zero",
            "-q",
            "-f",
            "json",
            "-o",
            str(report),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = load_report_document(json.loads(report.read_text(encoding="utf-8")))
    versions: dict[str, set[str]] = {}
    for agent in payload["agents"]:
        for server in agent["mcp_servers"]:
            for package in server["packages"]:
                versions.setdefault(package["name"], set()).add(package["version"])
    assert versions["langchain"] == {"0.0.200"}
    assert versions["openai"] == {"latest"}


def test_range_declared_manifest_package_replaces_the_sdk_latest_package(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    merged = consolidate_project_agents(
        [
            _ai_agent(root, "anthropic", "openai"),
            _manifest_agent(
                root,
                Package(name="anthropic", version="unknown", ecosystem="pypi"),
                Package(name="requests", version="2.31.0", ecosystem="pypi"),
            ),
        ]
    )

    assert _versions(merged) == {
        "project:proj:anthropic": ["unknown"],
        "project:proj:requests": ["2.31.0"],
        "project:proj:openai": ["latest"],
    }


def _range_project(tmp_path: Path) -> Path:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text("anthropic>=0.30\nrequests==2.31.0\n", encoding="utf-8")
    (project / "app.py").write_text("import anthropic\nimport openai\n", encoding="utf-8")
    return project


def test_repo_tree_scan_drops_the_import_copy_of_a_range_declared_package(tmp_path):
    from agent_bom.api.repo_tree_scan import scan_cloned_repo_tree

    project = _range_project(tmp_path)
    agents: list[Agent] = []
    scan_cloned_repo_tree(str(project), agents=agents, warnings=[], offline=True)

    ai_versions = {
        package.name: package.version
        for agent in agents
        for server in agent.mcp_servers
        if server.surface is ServerSurface.AI_INVENTORY
        for package in server.packages
    }
    assert "anthropic" not in ai_versions
    assert ai_versions["openai"] == "latest"


def test_scan_counts_a_range_declared_sdk_once(tmp_path):
    from agent_bom.cli import main
    from agent_bom.output.report_packing import load_report_document

    project = _range_project(tmp_path)
    report = tmp_path / "report.json"
    args = ["scan", "-p", str(project), "--ai-inventory", str(project), "--offline", "--no-scan", "--no-discover"]
    result = CliRunner().invoke(main, [*args, "--exit-zero", "-q", "-f", "json", "-o", str(report)])

    # Offline, the range stays unresolved, so the run is honestly partial.
    assert report.exists(), result.output
    payload = load_report_document(json.loads(report.read_text(encoding="utf-8")))
    packages = [
        (package["ecosystem"], package["name"], package["version"])
        for agent in payload["agents"]
        for server in agent["mcp_servers"]
        for package in server["packages"]
    ]
    anthropic = [version for _, name, version in packages if name == "anthropic"]
    assert len(anthropic) == 1, anthropic
    assert anthropic[0] != "latest"
    assert payload["summary"]["total_packages"] == len(set(packages))
