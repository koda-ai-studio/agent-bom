"""MCP ``scan`` over a project directory: ``project_path``.

A coding agent's most common request is "scan this repo". ``project_path``
runs the same project pipeline as ``config_path`` (manifests and lockfiles,
repo tree, IaC, GitHub Actions, project-scoped MCP configs) and is held to the
MCP path sandbox: the resolved path must be an existing directory inside HOME
or a configured workspace root. Traversal, symlink escapes, files, and missing
paths are refused with the typed invalid-path error rather than reported as an
empty (clean-looking) scan.
"""

from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

pytest.importorskip("mcp")

from mcp import Client  # noqa: E402
from mcp_types import CallToolResult  # noqa: E402

INVALID_PATH = "AGENTBOM_MCP_VALIDATION_INVALID_PATH"


def _call(args: dict[str, Any]) -> CallToolResult:
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server(profile="full")

    async def _run() -> CallToolResult:
        async with Client(server) as client:
            return await client.call_tool("scan", args)

    return asyncio.run(_run())


def _text(result: CallToolResult) -> str:
    return result.content[0].text  # type: ignore[union-attr]


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "workspaces"
    project = root / "proj"
    project.mkdir(parents=True)
    (project / "requirements.txt").write_text("flask==0.12.2\n")
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "requirements.txt").write_text("requests==2.19.0\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AGENT_BOM_MCP_WORKSPACE_ROOTS", str(root))
    monkeypatch.delenv("AGENT_BOM_OFFLINE", raising=False)
    monkeypatch.delenv("AGENT_BOM_VULN_DB_OFFLINE", raising=False)
    return root


@pytest.fixture
def no_vuln_lookup():
    """Keep the real discovery/extraction pipeline but skip the advisory lookup."""
    with (
        patch("agent_bom.scanners.scan_agents", new=AsyncMock(return_value=[])),
        patch("agent_bom.graph.scan_findings.surface_graph_derived_findings", return_value=None),
    ):
        yield


def test_scan_schema_advertises_project_path() -> None:
    from agent_bom.mcp_server import create_mcp_server

    tools = {t.name: t for t in asyncio.run(create_mcp_server(profile="full").list_tools())}
    scan = tools["scan"]
    prop = scan.input_schema["properties"]["project_path"]
    assert "directory" in prop["description"].lower()
    assert "AGENT_BOM_MCP_WORKSPACE_ROOTS" in prop["description"]
    assert "project_path" in (scan.description or "")


@pytest.mark.usefixtures("no_vuln_lookup")
def test_project_path_scans_manifests_and_pages_by_result_id(workspace: Path) -> None:
    result = _call({"project_path": str(workspace / "proj"), "offline": True, "no_discover": True})
    assert result.is_error is False, _text(result)
    summary = json.loads(_text(result))
    assert summary["detail"] == "summary"
    assert summary["counts"]["packages"] == 1
    assert "repo_tree" in summary["scan_sources"]
    result_id = summary["result_id"]

    page = _call({"result_id": result_id, "section": "agents", "offset": 0, "limit": 5})
    assert page.is_error is False, _text(page)
    body = json.loads(_text(page))
    packages = [pkg for agent in body["items"] for server in agent.get("mcp_servers", []) for pkg in server.get("packages", [])]
    assert [(pkg["name"], pkg["version"]) for pkg in packages] == [("flask", "0.12.2")]
    assert "requests" not in _text(page), "a sibling outside the project leaked into the scan"


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda ws: str(ws / "proj" / ".." / ".." / "outside"), id="dotdot-traversal"),
        pytest.param(lambda ws: str(ws.parent / "outside"), id="absolute-outside-root"),
        pytest.param(lambda ws: "../../outside", id="relative-traversal"),
        pytest.param(lambda ws: "/etc", id="system-dir"),
    ],
)
def test_project_path_outside_root_is_refused_with_typed_error(workspace: Path, build) -> None:
    with patch("agent_bom.discovery.discover_all") as discover:
        result = _call({"project_path": build(workspace), "offline": True, "no_discover": True})
    assert result.is_error is True
    text = _text(result)
    assert INVALID_PATH in text and "(argument: project_path)" in text
    discover.assert_not_called()


def test_refused_project_path_is_a_typed_error_without_a_logged_traceback(workspace: Path, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("DEBUG")
    result = _call({"project_path": "/etc", "offline": True, "no_discover": True})
    assert result.is_error is True and INVALID_PATH in _text(result)
    assert not [record for record in caplog.records if record.exc_info], "a refused input is not a server fault"
    assert "Traceback" not in caplog.text


def test_symlink_escaping_root_is_refused(workspace: Path) -> None:
    (workspace / "proj" / "escape").symlink_to(workspace.parent / "outside", target_is_directory=True)
    with patch("agent_bom.discovery.discover_all") as discover:
        result = _call({"project_path": str(workspace / "proj" / "escape"), "offline": True, "no_discover": True})
    assert result.is_error is True
    assert INVALID_PATH in _text(result)
    assert str(workspace.parent / "outside") not in _text(result), "resolved target outside the root must not be echoed"
    discover.assert_not_called()


@pytest.mark.parametrize("argument", ["project_path", "config_path"])
@pytest.mark.parametrize("target", ["missing", "proj/requirements.txt"])
def test_missing_or_non_directory_path_fails_closed(workspace: Path, argument: str, target: str) -> None:
    result = _call({argument: str(workspace / target), "offline": True, "no_discover": True})
    assert result.is_error is True, "an unreadable target must not read as an empty clean scan"
    text = _text(result)
    assert INVALID_PATH in text and f"(argument: {argument})" in text
    assert "no_agents_found" not in text


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_project_path_is_refused_not_treated_as_host_discovery(workspace: Path, blank: str) -> None:
    with patch("agent_bom.discovery.discover_all") as discover:
        result = _call({"project_path": blank, "offline": True})
    assert result.is_error is True
    assert "project_path must not be empty" in _text(result)
    discover.assert_not_called()


@pytest.mark.parametrize("other", [{"config_path": "proj"}, {"repo_url": "https://github.com/org/repo"}])
def test_project_path_is_exclusive_with_other_directory_targets(workspace: Path, other: dict[str, str]) -> None:
    args = {key: (str(workspace / value) if key == "config_path" else value) for key, value in other.items()}
    with patch("agent_bom.repo_scan.clone_repository_async") as clone:
        result = _call({"project_path": str(workspace / "proj"), **args, "offline": True, "no_discover": True})
    assert result.is_error is True
    assert "Provide only one of project_path, config_path, or repo_url" in _text(result)
    clone.assert_not_called()


@pytest.mark.usefixtures("no_vuln_lookup")
def test_project_discovery_runs_off_the_event_loop_and_keeps_its_warnings(workspace: Path) -> None:
    from agent_bom.discovery import discover_all as real_discover_all
    from agent_bom.scanners.state import record_coverage_warning, record_scan_warning

    seen: dict[str, Any] = {}

    def _discover(*args: Any, **kwargs: Any):
        seen["thread"] = threading.current_thread()
        try:
            asyncio.get_running_loop()
            seen["on_loop"] = True
        except RuntimeError:
            seen["on_loop"] = False
        record_scan_warning("discovery-thread-warning")
        record_coverage_warning({"kind": "parse_gap", "release": "discovery-thread-coverage", "ecosystem": "pypi", "detail": "x"})
        return real_discover_all(*args, **kwargs)

    with patch("agent_bom.discovery.discover_all", side_effect=_discover):
        result = _call({"project_path": str(workspace / "proj"), "offline": True, "no_discover": True})
    assert result.is_error is False, _text(result)
    assert seen["on_loop"] is False, "project discovery blocked the MCP event loop"
    assert seen["thread"] is not threading.main_thread()
    summary = json.loads(_text(result))
    assert "discovery-thread-warning" in summary.get("warnings", [])
    assert any(w.get("release") == "discovery-thread-coverage" for w in summary.get("coverage_warnings", []))
