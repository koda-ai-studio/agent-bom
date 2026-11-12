"""The OpenAI MCP edition package: a remote, no-login lookup plugin.

The builder enforces the directory's documented package limits so a bad upload
fails here instead of in the portal, and keeps the listing true to the server.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import zipfile
from pathlib import Path

import pytest

from agent_bom.mcp_tools.profiles import get_profile

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "integrations" / "openai-mcp"


def _builder():
    spec = importlib.util.spec_from_file_location("build_openai_mcp_plugin_zip", ROOT / "scripts" / "build_openai_mcp_plugin_zip.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _manifest() -> dict:
    return json.loads((PLUGIN / "plugin.json").read_text(encoding="utf-8"))


def _mcp() -> dict:
    return json.loads((PLUGIN / "mcp.json").read_text(encoding="utf-8"))


def test_package_builds_with_only_allowlisted_files(tmp_path):
    builder = _builder()
    output = tmp_path / "plugin.zip"
    assert builder.main(["--output", str(output)]) == 0
    with zipfile.ZipFile(output) as archive:
        names = sorted(archive.namelist())
        assert names == ["LICENSE", "README.md", "assets/icon.png", "mcp.json", "plugin.json"]
        assert json.loads(archive.read("mcp.json")) == _mcp()
    first = output.read_bytes()
    assert builder.main(["--output", str(output)]) == 0
    assert output.read_bytes() == first, "the archive must be reproducible"


def test_declares_exactly_one_remote_server_without_credentials():
    servers = _mcp()["mcpServers"]
    assert len(servers) == 1
    server = next(iter(servers.values()))
    assert set(server) == {"type", "url"}
    assert server["type"] == "streamable-http"
    assert server["url"].startswith("https://") and server["url"].endswith("/mcp")
    assert "agent-bom-mcp.up.railway.app" not in server["url"], "the OAuth server is a different listing"


def test_test_cases_are_five_positive_three_negative_using_real_tools():
    cases = _manifest()["extensions"]["com.openai"]["review"]["test_cases"]
    assert len(cases["positive"]) == 5 and len(cases["negative"]) == 3
    tools = get_profile("public").tools
    for case in cases["positive"]:
        assert set(case) <= {"description", "prompt", "tools_triggered", "expected_behavior", "file_attachment_urls", "expected_output_url"}
        assert all(case[key].strip() for key in ("description", "prompt", "tools_triggered", "expected_behavior"))
        assert {name.strip() for name in case["tools_triggered"].split(",")} <= tools
    assert {case["tools_triggered"] for case in cases["positive"]} == tools
    for case in cases["negative"]:
        assert set(case) == {"description", "prompt"}


def test_listing_names_only_tools_the_server_registers():
    interface = _manifest()["extensions"]["com.openai"]["interface"]
    text = interface["longDescription"]
    for tool in get_profile("public").tools:
        assert f"{tool}:" in text
    for absent in ("scan", "generate_sbom", "remediate", "sign in", "log in"):
        assert f"- {absent}" not in text
    assert "no account or sign-in" in text


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("name",), "Agent BOM", "name"),
        (("name",), "agent--bom", "name"),
        (("version",), "1.0", "version"),
        (("description",), "x" * 1025, "description"),
        (("extensions", "com.openai", "interface", "displayName"), "x" * 31, "displayName"),
        (("extensions", "com.openai", "interface", "shortDescription"), "two\nlines", "shortDescription"),
        (("extensions", "com.openai", "interface", "longDescription"), "x" * 4001, "longDescription"),
        (("extensions", "com.openai", "interface", "developerName"), "x" * 81, "developerName"),
        (("extensions", "com.openai", "interface", "privacyPolicyURL"), "http://example.com/privacy", "privacyPolicyURL"),
        (("extensions", "com.openai", "interface", "supportURL"), "https://user:pw@example.com/", "supportURL"),
        (("extensions", "com.openai", "interface", "defaultPrompt"), ["a", "b", "c", "d"], "defaultPrompt"),
        (("extensions", "com.openai", "interface", "defaultPrompt"), ["Ask @agent-bom-lookup about lodash"], "defaultPrompt"),
        (("extensions", "com.openai", "interface", "defaultPrompt"), ["Same prompt", "same  prompt"], "defaultPrompt"),
        (("extensions", "com.openai", "interface", "brandColor"), "#FFFF00", "brandColor"),
        (("extensions", "com.openai", "interface", "logo"), "assets/icon.png", "./"),
        (("extensions", "com.openai", "interface", "capabilities"), ["x" * 121], "capabilities"),
        (("extensions", "com.openai", "requires_local_executor"), True, "requires_local_executor"),
        (("extensions", "com.openai", "review", "test_credentials"), {"user": "a"}, "test_credentials"),
        (("extensions", "com.openai", "review", "reviewer_instructions"), "log in as", "reviewer_instructions"),
        (("hooks",), {}, "hooks"),
        (("skills",), "./skills/", "skills"),
    ],
)
def test_manifest_violations_are_refused(path, value, message):
    builder = _builder()
    manifest = copy.deepcopy(_manifest())
    target = manifest
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(builder.PackageError, match=message):
        builder.validate_manifest(manifest, PLUGIN)


def test_review_case_counts_are_enforced():
    builder = _builder()
    manifest = copy.deepcopy(_manifest())
    manifest["extensions"]["com.openai"]["review"]["test_cases"]["positive"].pop()
    with pytest.raises(builder.PackageError, match="5 positive"):
        builder.validate_manifest(manifest, PLUGIN)
    manifest = copy.deepcopy(_manifest())
    manifest["extensions"]["com.openai"]["review"]["test_cases"]["positive"][0]["tools_triggered"] = "scan"
    with pytest.raises(builder.PackageError, match="not served"):
        builder.validate_manifest(manifest, PLUGIN)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda m: m["mcpServers"].update({"second": {"type": "streamable-http", "url": "https://b.example/mcp"}}), "exactly one"),
        (lambda m: m["mcpServers"]["agent-bom-lookup"].update({"headers": {"Authorization": "Bearer x"}}), "headers"),
        (lambda m: m["mcpServers"]["agent-bom-lookup"].update({"clientSecret": "x"}), "clientSecret"),
        (lambda m: m["mcpServers"]["agent-bom-lookup"].update({"type": "none"}), "type"),
        (lambda m: m["mcpServers"]["agent-bom-lookup"].update({"url": "http://a.example/mcp"}), "HTTPS"),
        (lambda m: m["mcpServers"]["agent-bom-lookup"].update({"url": "https://a.example/mcp?token=1"}), "query"),
        (lambda m: m["mcpServers"]["agent-bom-lookup"].update({"url": "https://a.example/other"}), "/mcp"),
        (lambda m: m["mcpServers"]["agent-bom-lookup"].update({"url": "https://agent-bom-mcp.up.railway.app/mcp"}), "OAuth"),
        (lambda m: m.update({"mcpServers": []}), "object"),
    ],
)
def test_mcp_config_violations_are_refused(mutate, message):
    builder = _builder()
    config = copy.deepcopy(_mcp())
    mutate(config)
    with pytest.raises(builder.PackageError, match=message):
        builder.validate_mcp_config(config)


def test_unlisted_files_are_refused():
    builder = _builder()
    for name in (".mcp.json", ".codex-plugin/plugin.json", "skills/x/SKILL.md", ".app.json", "hooks/hooks.json", "assets/../x.png"):
        with pytest.raises(builder.PackageError):
            builder.validate_names([name])


def test_skills_only_package_is_unchanged():
    codex = json.loads((ROOT / "integrations/codex/plugin.json").read_text(encoding="utf-8"))
    assert codex["name"] == "agent-bom"
    assert codex["extensions"]["com.openai"]["requires_local_executor"] is True
    assert not (ROOT / "integrations/codex/mcp.json").exists()
