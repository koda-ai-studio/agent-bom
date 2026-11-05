"""UTF-8 evidence is independent of the workstation's default encoding."""

import asyncio
import importlib
import json
from pathlib import Path

import pytest


@pytest.fixture
def windows_text_defaults(monkeypatch):
    original_read = Path.read_text
    original_write = Path.write_text

    def read(path, *args, **kwargs):
        if not args and kwargs.get("encoding") is None:
            kwargs["encoding"] = "cp1252"
        return original_read(path, *args, **kwargs)

    def write(path, text, *args, **kwargs):
        if not args and kwargs.get("encoding") is None:
            kwargs["encoding"] = "cp1252"
        return original_write(path, text, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(Path, "write_text", write)


@pytest.mark.parametrize("module_name", ["registry", "parsers", "parsers.skill_audit", "fleet_scan"])
def test_registry_loaders_preserve_bundled_unicode_with_windows_defaults(windows_text_defaults, monkeypatch, module_name):
    module = importlib.import_module("agent_bom." + module_name)
    if module_name == "parsers":
        monkeypatch.setattr(module, "_registry_cache", None)
    path = (
        Path(module.__file__).parents[1] / "mcp_registry.json"
        if module_name.startswith("parsers")
        else Path(module.__file__).with_name("mcp_registry.json")
    )
    expected = json.loads(path.read_bytes().decode("utf-8"))["servers"]
    assert expected
    assert module._load_registry() == expected


def test_mcp_server_starts_and_lists_tools_with_windows_defaults(windows_text_defaults):
    pytest.importorskip("mcp")
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server(profile="full")
    tools = asyncio.run(server.list_tools())
    assert {tool.name for tool in tools} >= {"scan", "check"}


def test_mcp_registry_resources_preserve_unicode_with_windows_defaults(windows_text_defaults, tmp_path):
    from agent_bom.mcp_server_runtime import get_registry_data, get_registry_data_raw

    path = tmp_path / "registry.json"
    value = {"servers": {"fixture": {"description": "工具 — résumé"}}}
    raw = json.dumps(value, ensure_ascii=False)
    path.write_bytes(raw.encode("utf-8"))
    assert get_registry_data(None, path) == value
    assert get_registry_data_raw(None, path) == raw


def test_spdx_text_export_preserves_unicode_with_windows_defaults(windows_text_defaults, tmp_path):
    from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package
    from agent_bom.output.spdx2_fmt import export_spdx2_tagvalue

    package = Package(name="fixture", version="1.0.0", ecosystem="npm", description="工具 — résumé")
    report = AIBOMReport(
        agents=[
            Agent(
                name="fixture",
                agent_type=AgentType.CUSTOM,
                config_path="fixture.json",
                mcp_servers=[MCPServer(name="fixture", packages=[package])],
            )
        ]
    )
    path = tmp_path / "report.spdx"
    export_spdx2_tagvalue(report, str(path))
    assert "工具 — résumé" in path.read_bytes().decode("utf-8")


def test_file_text_io_declares_encoding():
    import ast

    import agent_bom

    root = Path(agent_bom.__file__).parent
    implicit = []
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in {"read_text", "write_text"}:
                continue
            # Click's help formatter writes to its own buffer, not a file.
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "formatter":
                continue
            positional_encoding = len(node.args) >= (1 if node.func.attr == "read_text" else 2)
            if not positional_encoding and not any(keyword.arg == "encoding" for keyword in node.keywords):
                implicit.append(f"{path.relative_to(root)}:{node.lineno}")
    assert not implicit, "Locale-dependent file I/O: " + ", ".join(sorted(implicit))
