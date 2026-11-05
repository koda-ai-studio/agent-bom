"""What the Claude and OpenAI directories check, held true against the shipped plugins."""

from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path

import pytest

from agent_bom.core.egress_hosts import DATABASE_UPDATE_HOSTS, DECLARED_HOSTS
from agent_bom.mcp_server import create_mcp_server

ROOT = Path(__file__).resolve().parents[1]
CLAUDE = ROOT / "integrations" / "claude-code"
GUARD = ROOT / "integrations" / "agent-bom-guard"
CODEX = ROOT / "integrations" / "codex"
PRIVACY = "https://koda-ai-studio.github.io/agent-bom/privacy/"
TERMS = "https://koda-ai-studio.github.io/agent-bom/terms/"

# Tools that open no socket: they read local files or the local store only.
LOCAL_ONLY_TOOLS = {"audit_integrity", "executive_brief", "exposure_paths", "inventory", "prompt_scan", "skill_scan", "skill_trust"}
# Tools that keep a result another call can read back, so they are not read-only.
PERSISTING_TOOLS = {"scan"}
HOST_LAUNCHING_TOOLS = {"tool_risk_assessment"}


def _plugin_tools() -> dict[str, object]:
    tools = {}
    for profile in ("scan", "audit"):
        tools.update({tool.name: tool for tool in asyncio.run(create_mcp_server(profile=profile).list_tools())})
    return tools


def test_every_plugin_tool_declares_every_directory_annotation() -> None:
    for name, tool in _plugin_tools().items():
        assert tool.title, name
        annotations = tool.annotations
        assert annotations is not None, name
        for hint in (annotations.read_only_hint, annotations.destructive_hint, annotations.open_world_hint):
            assert isinstance(hint, bool), name
        assert len(name) <= 64


def test_read_only_hints_match_what_each_tool_does() -> None:
    for name, tool in _plugin_tools().items():
        hints = tool.annotations
        if name in HOST_LAUNCHING_TOOLS:
            assert (hints.read_only_hint, hints.destructive_hint) == (False, True), name
        elif name in PERSISTING_TOOLS:
            assert (hints.read_only_hint, hints.destructive_hint) == (False, False), name
        else:
            assert (hints.read_only_hint, hints.destructive_hint) == (True, False), name


def test_open_world_hint_is_false_only_for_tools_without_network_access() -> None:
    for name, tool in _plugin_tools().items():
        assert tool.annotations.open_world_hint is (name not in LOCAL_ONLY_TOOLS), name


def test_scan_description_discloses_what_it_keeps() -> None:
    description = _plugin_tools()["scan"].description
    assert "Keeps a redacted copy of the result locally" in description
    assert "auto_update_db" in description


def test_server_card_annotations_match_the_live_plugin_tools() -> None:
    from agent_bom.mcp_server_metadata import build_server_card

    card = {tool["name"]: tool for tool in build_server_card(profile="full")["tools"]}
    for name, tool in _plugin_tools().items():
        assert card[name]["annotations"]["readOnlyHint"] is tool.annotations.read_only_hint, name


def _chat_home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    (home / ".claude" / "projects" / "-demo").mkdir(parents=True)
    (home / ".claude" / "projects" / "-demo" / "session.jsonl").write_text('{"message":"CANARY-CHAT"}\n')
    (home / ".claude" / "history.jsonl").write_text('{"display":"CANARY-CHAT"}\n')
    (home / ".codex" / "sessions").mkdir(parents=True)
    (home / ".codex" / "sessions" / "run.jsonl").write_text('{"message":"CANARY-CHAT"}\n')
    (home / ".claude.json").write_text(
        json.dumps(
            {
                "mcpServers": {"notes": {"command": "npx", "args": ["-y", "demo-notes-server"]}},
                "projects": {"/demo": {"history": [{"display": "CANARY-CHAT"}]}},
            }
        )
    )
    return home


@pytest.mark.parametrize(
    ("profile", "tool", "arguments"),
    [
        ("audit", "inventory", {}),
        ("audit", "tool_risk_assessment", {"live": False}),
        ("scan", "scan", {"offline": True}),
    ],
)
def test_discovery_never_opens_or_returns_chat_history(tmp_path, monkeypatch, profile, tool, arguments) -> None:
    home = _chat_home(tmp_path)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AGENT_BOM_MCP_LIVE_INTROSPECTION", "0")
    monkeypatch.chdir(tmp_path)
    opened: list[str] = []

    def record(event: str, args: tuple) -> None:
        if event == "open" and isinstance(args[0], str):
            opened.append(args[0])

    sys.addaudithook(record)
    server = create_mcp_server(profile=profile)
    start = len(opened)
    result = asyncio.run(server.call_tool(tool, arguments))
    during = opened[start:]
    opened.append("")  # the hook stays installed for the process; keep it cheap and inert

    assert "CANARY-CHAT" not in json.dumps(result, default=str)
    history = [path for path in during if re.search(r"\.claude/projects|\.claude/history|\.codex/(sessions|history)", path)]
    assert not history, history


def test_directory_profiles_do_not_offer_activity_or_history_tools() -> None:
    names = set(_plugin_tools())
    assert not {"agent_activity", "runtime_correlate"} & names


def test_directory_skills_name_no_chat_history_source() -> None:
    for skill in [*CLAUDE.glob("skills/*/SKILL.md"), *CODEX.glob("skills/*/SKILL.md")]:
        assert "session transcript" not in skill.read_text(encoding="utf-8"), skill


def test_inventory_skill_needs_no_network_tool() -> None:
    text = (CLAUDE / "skills" / "inventory" / "SKILL.md").read_text(encoding="utf-8")
    front = text.split("\n---\n", 1)[0]
    assert "outbound_http: false" in front
    assert "agent-bom__scan" not in front


def test_mcp_skills_say_what_to_do_when_their_tools_are_absent() -> None:
    for skill in CLAUDE.glob("skills/*/SKILL.md"):
        assert "If the agent-bom tools are not available here" in skill.read_text(encoding="utf-8"), skill


def test_bom_skill_limits_the_flags_its_shell_grant_allows() -> None:
    text = (CLAUDE / "skills" / "bom" / "SKILL.md").read_text(encoding="utf-8")
    assert "Use only the flags shown here" in text
    assert "--push-url" in text


@pytest.mark.parametrize(
    "manifest",
    [CLAUDE / ".claude-plugin" / "plugin.json", GUARD / ".claude-plugin" / "plugin.json"],
    ids=lambda path: path.parents[1].name,
)
def test_claude_manifests_use_the_published_legal_pages(manifest: Path) -> None:
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["privacyPolicyUrl"] == PRIVACY
    assert data["termsOfServiceUrl"] == TERMS


@pytest.mark.parametrize(
    "manifest",
    [CLAUDE / ".codex-plugin" / "plugin.json", CODEX / ".codex-plugin" / "plugin.json", CODEX / "plugin.json"],
    ids=lambda path: "/".join(path.relative_to(ROOT).parts[1:]),
)
def test_openai_manifests_use_the_published_legal_pages(manifest: Path) -> None:
    data = json.loads(manifest.read_text(encoding="utf-8"))
    interface = data.get("interface") or data["extensions"]["com.openai"]["interface"]
    assert interface["privacyPolicyURL"] == PRIVACY
    assert interface["termsOfServiceURL"] == TERMS


def test_openai_skills_package_declares_it_needs_the_desktop() -> None:
    assert json.loads((CODEX / ".codex-plugin" / "plugin.json").read_text())["requires_local_executor"] is True
    root = json.loads((CODEX / "plugin.json").read_text())
    assert root["extensions"]["com.openai"]["requires_local_executor"] is True


def test_privacy_page_discloses_the_guard_hook() -> None:
    text = (ROOT / "site-docs" / "privacy.md").read_text(encoding="utf-8")
    assert "agent-bom-guard" in text
    assert "every Bash command" in text
    assert "api.osv.dev" in text
    assert "private package" in text


def test_guard_readme_discloses_private_package_names_and_the_option_variables() -> None:
    text = (GUARD / "README.md").read_text(encoding="utf-8")
    assert "private package" in text
    assert "CLAUDE_PLUGIN_OPTION_" in text


def test_guard_description_mentions_every_warning_it_raises() -> None:
    description = json.loads((GUARD / ".claude-plugin" / "plugin.json").read_text())["description"]
    assert "piped" in description


def test_plugin_servers_do_not_forward_ambient_tokens() -> None:
    servers = json.loads((CLAUDE / ".mcp.json").read_text())["mcpServers"]
    local = json.loads((CLAUDE / ".codex-plugin" / "plugin.json").read_text())["mcpServers"]
    for server in [*servers.values(), *local.values()]:
        for name in ("GITHUB_TOKEN", "GH_TOKEN", "NVD_API_KEY"):
            assert server["env"].get(name) == "", name


def test_cli_skills_disclose_ambient_tokens() -> None:
    assert "GITHUB_TOKEN" in (CODEX / "README.md").read_text(encoding="utf-8")
    interface = json.loads((CODEX / ".codex-plugin" / "plugin.json").read_text())["interface"]
    assert "never file contents or credentials" not in interface["longDescription"]
    assert "GITHUB_TOKEN" in interface["longDescription"]


def test_codex_readme_counts_its_skills() -> None:
    assert "nine\nskills" in (CODEX / "README.md").read_text(encoding="utf-8").replace("It has nine skills", "nine\nskills")


def test_permissions_contract_lists_every_plugin_and_database_host() -> None:
    text = (ROOT / "docs" / "PERMISSIONS.md").read_text(encoding="utf-8")
    missing = sorted(host for host in DECLARED_HOSTS | DATABASE_UPDATE_HOSTS.keys() if host not in text)
    assert not missing, missing


def test_database_update_hosts_match_the_sync_sources() -> None:
    sources = "".join(
        (ROOT / "src" / "agent_bom" / "db" / name).read_text(encoding="utf-8")
        for name in ("sync_common.py", "sync.py", "sync_distributions.py", "sync_exploit_feeds.py")
    )
    used = set(re.findall(r"https://([a-zA-Z0-9.-]+\.[a-z]{2,})", sources)) - {"nvd.nist.gov"}
    assert used <= DECLARED_HOSTS | DATABASE_UPDATE_HOSTS.keys(), sorted(used - DECLARED_HOSTS - DATABASE_UPDATE_HOSTS.keys())
