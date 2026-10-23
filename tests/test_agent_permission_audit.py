"""Coding-agent permission settings audit (Claude Code settings, Codex config).

All fixtures are synthetic; no real user settings are read.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom.discovery.agent_permissions import audit_claude_code_settings, audit_codex_config
from agent_bom.models import Agent, AgentStatus, AgentType


def _types(findings: list[dict]) -> list[tuple[str, str, str]]:
    return [(f["type"], f["severity"], f["value"]) for f in findings]


# ── Claude Code ──────────────────────────────────────────────────────────────


def test_bypass_permissions_default_mode_is_high_in_user_scope():
    findings = audit_claude_code_settings({"permissions": {"defaultMode": "bypassPermissions"}}, "user")
    assert _types(findings) == [("BYPASS_PERMISSIONS_DEFAULT", "HIGH", "bypassPermissions")]
    finding = findings[0]
    assert finding["key_path"] == "permissions.defaultMode"
    assert "permissions.disableBypassPermissionsMode" in finding["recommendation"]
    assert finding["client"] == "claude-code"


def test_bypass_permissions_in_project_scope_is_medium_because_newer_versions_ignore_it():
    findings = audit_claude_code_settings({"permissions": {"defaultMode": "bypassPermissions"}}, "project")
    assert _types(findings) == [("BYPASS_PERMISSIONS_DEFAULT", "MEDIUM", "bypassPermissions")]
    assert "v2.1.257" in findings[0]["description"]


@pytest.mark.parametrize("mode", ["default", "manual", "acceptEdits", "plan", "auto", "dontAsk", 7, None])
def test_other_default_modes_are_not_flagged(mode):
    assert audit_claude_code_settings({"permissions": {"defaultMode": mode}}, "user") == []


def test_disable_bypass_mode_suppresses_bypass_finding():
    settings = {"permissions": {"defaultMode": "bypassPermissions"}}
    assert audit_claude_code_settings(settings, "user", bypass_disabled=True) == []


def test_unscoped_shell_web_and_server_wide_mcp_allows_are_medium():
    settings = {
        "permissions": {
            "allow": [
                "Bash",
                "Bash(*)",
                "PowerShell",
                "WebFetch",
                "WebFetch(domain:*)",
                "mcp__github",
                "mcp__github__*",
            ]
        }
    }
    findings = audit_claude_code_settings(settings, "user")
    assert _types(findings) == [
        ("UNSCOPED_SHELL_ALLOW", "MEDIUM", "Bash"),
        ("UNSCOPED_SHELL_ALLOW", "MEDIUM", "Bash(*)"),
        ("UNSCOPED_SHELL_ALLOW", "MEDIUM", "PowerShell"),
        ("UNSCOPED_WEB_FETCH_ALLOW", "MEDIUM", "WebFetch"),
        ("UNSCOPED_WEB_FETCH_ALLOW", "MEDIUM", "WebFetch(domain:*)"),
        ("SERVER_WIDE_MCP_ALLOW", "MEDIUM", "mcp__github"),
        ("SERVER_WIDE_MCP_ALLOW", "MEDIUM", "mcp__github__*"),
    ]
    assert all(f["key_path"] == "permissions.allow" for f in findings)
    assert "Bash(git diff *)" in findings[0]["recommendation"]
    assert "WebFetch(domain:" in findings[3]["recommendation"]


def test_scoped_and_ineffective_allow_rules_are_not_flagged():
    settings = {
        "permissions": {
            "allow": [
                "Bash(git diff:*)",
                "Bash(npm run test *)",
                "WebFetch(domain:docs.example.com)",
                "mcp__github__get_issue",
                "mcp__github__get_*",
                "mcp__*",
                "*",
                "Read",
                "Edit(./src/**)",
                42,
            ],
            "deny": ["Bash", "WebFetch", "mcp__*"],
            "ask": ["Bash(*)"],
        }
    }
    assert audit_claude_code_settings(settings, "project") == []


def test_unscoped_file_write_allow_is_low():
    findings = audit_claude_code_settings({"permissions": {"allow": ["Edit", "Write(*)"]}}, "local")
    assert _types(findings) == [
        ("UNSCOPED_FILE_WRITE_ALLOW", "LOW", "Edit"),
        ("UNSCOPED_FILE_WRITE_ALLOW", "LOW", "Write(*)"),
    ]


def test_enable_all_project_mcp_servers_is_medium():
    findings = audit_claude_code_settings({"enableAllProjectMcpServers": True}, "user")
    assert _types(findings) == [("ALL_PROJECT_MCP_SERVERS_APPROVED", "MEDIUM", "true")]
    assert "enabledMcpjsonServers" in findings[0]["recommendation"]
    assert audit_claude_code_settings({"enableAllProjectMcpServers": False}, "user") == []


def test_skip_bypass_confirmation_is_low():
    findings = audit_claude_code_settings({"skipDangerousModePermissionPrompt": True}, "user")
    assert _types(findings) == [("BYPASS_CONFIRMATION_SKIPPED", "LOW", "true")]


@pytest.mark.parametrize("settings", [{}, {"permissions": "x"}, {"permissions": {"allow": "Bash"}}, {"permissions": None}])
def test_empty_or_malformed_claude_settings_yield_no_findings(settings):
    assert audit_claude_code_settings(settings, "user") == []


def test_missing_secret_deny_rules_are_not_a_finding():
    assert audit_claude_code_settings({"permissions": {"allow": ["Bash(git status)"]}}, "user") == []


# ── Codex ────────────────────────────────────────────────────────────────────


def test_codex_never_with_danger_full_access_is_high():
    findings = audit_codex_config({"approval_policy": "never", "sandbox_mode": "danger-full-access"}, "user")
    assert _types(findings) == [("NO_APPROVAL_NO_SANDBOX", "HIGH", "approval_policy=never, sandbox_mode=danger-full-access")]
    assert findings[0]["client"] == "codex"
    assert "workspace-write" in findings[0]["recommendation"]


def test_codex_sandbox_disabled_alone_is_medium_and_never_alone_is_low():
    assert _types(audit_codex_config({"approval_policy": "on-request", "sandbox_mode": "danger-full-access"}, "user")) == [
        ("SANDBOX_DISABLED", "MEDIUM", "danger-full-access")
    ]
    assert _types(audit_codex_config({"approval_policy": "never", "sandbox_mode": "workspace-write"}, "user")) == [
        ("APPROVALS_DISABLED", "LOW", "never")
    ]


def test_codex_safe_and_granular_policies_are_not_flagged():
    assert audit_codex_config({"approval_policy": "on-request", "sandbox_mode": "workspace-write"}, "user") == []
    granular = {"granular": {"sandbox_approval": True, "rules": True, "mcp_elicitations": True}}
    assert audit_codex_config({"approval_policy": granular, "sandbox_mode": "read-only"}, "user") == []
    assert audit_codex_config({}, "user") == []


def test_codex_sandbox_network_access_is_low():
    findings = audit_codex_config({"sandbox_workspace_write": {"network_access": True}}, "user")
    assert _types(findings) == [("SANDBOX_NETWORK_ENABLED", "LOW", "true")]
    assert findings[0]["key_path"] == "sandbox_workspace_write.network_access"


def test_codex_profile_override_inherits_top_level_and_reports_profile_key_path():
    config = {
        "sandbox_mode": "danger-full-access",
        "approval_policy": "on-request",
        "profiles": {"yolo": {"approval_policy": "never"}, "same": {"model": "x"}},
    }
    findings = audit_codex_config(config, "user")
    assert _types(findings) == [
        ("SANDBOX_DISABLED", "MEDIUM", "danger-full-access"),
        ("NO_APPROVAL_NO_SANDBOX", "HIGH", "approval_policy=never, sandbox_mode=danger-full-access"),
    ]
    assert findings[1]["key_path"] == "profiles.yolo"


def test_codex_project_config_ignores_profiles():
    config = {"profiles": {"yolo": {"approval_policy": "never", "sandbox_mode": "danger-full-access"}}}
    assert audit_codex_config(config, "project") == []


# ── File collection, attachment and unified findings ─────────────────────────


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    from agent_bom.discovery import agent_permission_posture

    monkeypatch.setattr(agent_permission_posture, "managed_settings_dirs", lambda: [tmp_path / "managed"])
    return home


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_collects_user_project_local_managed_and_codex_files(fake_home, tmp_path):
    from agent_bom.discovery.agent_permission_posture import collect_permission_findings

    project = tmp_path / "repo"
    _write(fake_home / ".claude/settings.json", json.dumps({"permissions": {"defaultMode": "bypassPermissions"}}))
    _write(project / ".claude/settings.json", json.dumps({"permissions": {"allow": ["Bash"]}}))
    _write(project / ".claude/settings.local.json", json.dumps({"permissions": {"allow": ["WebFetch"]}}))
    _write(tmp_path / "managed/managed-settings.json", json.dumps({"enableAllProjectMcpServers": True}))
    _write(fake_home / ".codex/config.toml", 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n')
    _write(fake_home / ".codex/fast.config.toml", 'sandbox_mode = "danger-full-access"\n')
    _write(project / ".codex/config.toml", "[sandbox_workspace_write]\nnetwork_access = true\n")

    findings = collect_permission_findings(str(project), include_user=True)
    got = {(f["client"], f["scope"], f["type"]) for f in findings}
    assert got == {
        ("claude-code", "user", "BYPASS_PERMISSIONS_DEFAULT"),
        ("claude-code", "project", "UNSCOPED_SHELL_ALLOW"),
        ("claude-code", "local", "UNSCOPED_WEB_FETCH_ALLOW"),
        ("claude-code", "managed", "ALL_PROJECT_MCP_SERVERS_APPROVED"),
        ("codex", "user", "NO_APPROVAL_NO_SANDBOX"),
        ("codex", "profile", "SANDBOX_DISABLED"),
        ("codex", "project", "SANDBOX_NETWORK_ENABLED"),
    }
    paths = {f["config_path"] for f in findings}
    assert "~/.claude/settings.json" in paths
    assert "~/.codex/fast.config.toml" in paths
    assert ".claude/settings.local.json" in paths


def test_project_scoped_collection_skips_user_files(fake_home, tmp_path):
    from agent_bom.discovery.agent_permission_posture import collect_permission_findings

    _write(fake_home / ".claude/settings.json", json.dumps({"permissions": {"defaultMode": "bypassPermissions"}}))
    assert collect_permission_findings(str(tmp_path / "empty"), include_user=False) == []


def test_managed_disable_bypass_suppresses_user_bypass(fake_home, tmp_path):
    from agent_bom.discovery.agent_permission_posture import collect_permission_findings

    _write(fake_home / ".claude/settings.json", json.dumps({"permissions": {"defaultMode": "bypassPermissions"}}))
    _write(tmp_path / "managed/managed-settings.json", json.dumps({"permissions": {"disableBypassPermissionsMode": "disable"}}))
    assert collect_permission_findings(None, include_user=True) == []


def test_claude_config_dir_and_codex_home_overrides_are_honored(fake_home, tmp_path, monkeypatch):
    from agent_bom.discovery.agent_permission_posture import collect_permission_findings

    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "cc"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "cx"))
    _write(tmp_path / "cc/settings.json", json.dumps({"permissions": {"allow": ["Bash"]}}))
    _write(tmp_path / "cx/config.toml", 'sandbox_mode = "danger-full-access"\n')
    got = {(f["client"], f["type"]) for f in collect_permission_findings(None, include_user=True)}
    assert got == {("claude-code", "UNSCOPED_SHELL_ALLOW"), ("codex", "SANDBOX_DISABLED")}


def test_unreadable_symlinked_and_malformed_files_are_skipped(fake_home, tmp_path):
    from agent_bom.discovery.agent_permission_posture import collect_permission_findings

    target = _write(tmp_path / "elsewhere.json", json.dumps({"permissions": {"allow": ["Bash"]}}))
    (fake_home / ".claude").mkdir()
    (fake_home / ".claude/settings.json").symlink_to(target)
    _write(fake_home / ".codex/config.toml", "not = [valid toml")
    _write(tmp_path / "repo/.claude/settings.json", "{not json")
    assert collect_permission_findings(str(tmp_path / "repo"), include_user=True) == []


def test_secret_values_never_appear_in_findings(fake_home, tmp_path):
    from agent_bom.discovery.agent_permission_posture import collect_permission_findings

    secret = "sk-fixture-SECRET-value-123"
    settings = {"env": {"ANTHROPIC_API_KEY": secret}, "apiKeyHelper": secret, "permissions": {"allow": ["Bash", f"Bash(curl -H {secret})"]}}
    _write(fake_home / ".claude/settings.json", json.dumps(settings))
    findings = collect_permission_findings(None, include_user=True)
    assert [f["value"] for f in findings] == ["Bash"]
    assert secret not in json.dumps(findings)


def test_attach_adds_findings_to_existing_agent_or_a_standalone_agent(fake_home, tmp_path):
    from agent_bom.discovery.agent_permission_posture import attach_permission_findings

    _write(fake_home / ".claude/settings.json", json.dumps({"permissions": {"allow": ["Bash"]}}))
    _write(fake_home / ".codex/config.toml", 'sandbox_mode = "danger-full-access"\n')
    claude = Agent(name="claude-code", agent_type=AgentType.CLAUDE_CODE, config_path="~/.claude.json")
    agents = attach_permission_findings([claude], None)
    assert [f["type"] for f in claude.metadata["permission_findings"]] == ["UNSCOPED_SHELL_ALLOW"]
    codex = next(a for a in agents if a.agent_type == AgentType.CODEX_CLI)
    assert codex.status == AgentStatus.INSTALLED_NOT_CONFIGURED
    assert [f["type"] for f in codex.metadata["permission_findings"]] == ["SANDBOX_DISABLED"]
    assert len(agents) == 2


def test_attach_never_breaks_discovery(fake_home, monkeypatch):
    from agent_bom.discovery import agent_permission_posture

    def boom(*args, **kwargs):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(agent_permission_posture, "collect_permission_findings", boom)
    agents: list[Agent] = []
    assert agent_permission_posture.attach_permission_findings(agents, None) == []


def test_unified_findings_have_distinct_ids_severity_and_agent_asset():
    from agent_bom.discovery.agent_permission_posture import evaluate_agent_permission_posture

    rows = audit_claude_code_settings({"permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash", "Bash(*)"]}}, "user")
    for row in rows:
        row["config_path"] = "~/.claude/settings.json"
    agent = Agent(name="claude-code", agent_type=AgentType.CLAUDE_CODE, config_path="x", metadata={"permission_findings": rows})
    findings = evaluate_agent_permission_posture([agent])
    assert [f.severity for f in findings] == ["high", "medium", "medium"]
    assert len({f.id for f in findings}) == 3
    assert all(f.asset.asset_type == "agent" and f.asset.identifier == agent.canonical_id for f in findings)
    assert findings[0].evidence["key_path"] == "permissions.defaultMode"
    assert findings[0].evidence["config_path"] == "~/.claude/settings.json"
    assert findings[0].remediation_guidance
    assert [f.id for f in evaluate_agent_permission_posture([agent])] == [f.id for f in findings]


def test_discover_all_attaches_permission_findings(fake_home, tmp_path, monkeypatch):
    import agent_bom.discovery as discovery

    project = tmp_path / "repo"
    _write(project / ".claude/settings.json", json.dumps({"permissions": {"allow": ["Bash(*)"]}}))
    agents = discovery.discover_all(project_dir=str(project))
    rows = [row for a in agents for row in a.metadata.get("permission_findings", [])]
    assert [(r["scope"], r["type"]) for r in rows] == [("project", "UNSCOPED_SHELL_ALLOW")]


def test_tool_risk_assessment_reports_permission_findings_without_servers(monkeypatch, tmp_path):
    import agent_bom.discovery as discovery
    from agent_bom.mcp_tools.runtime import tool_risk_assessment_impl

    rows = audit_codex_config({"approval_policy": "never", "sandbox_mode": "danger-full-access"}, "user")
    agent = Agent(name="codex", agent_type=AgentType.CODEX_CLI, config_path="x", metadata={"permission_findings": rows})
    monkeypatch.setattr(discovery, "discover_all", lambda **kwargs: [agent])
    data = json.loads(tool_risk_assessment_impl(config_path=None, live=False, _safe_path=lambda x: x, _truncate_response=lambda x: x))
    assert data["status"] == "no_servers_found"
    assert [f["severity"] for f in data["agent_permission_findings"]] == ["high"]
    assert data["agent_permission_findings"][0]["evidence"]["permission_type"] == "NO_APPROVAL_NO_SANDBOX"


def test_cli_mcp_audit_exits_one_on_high_permission_finding(monkeypatch, tmp_path):
    from click.testing import CliRunner

    import agent_bom.discovery as discovery
    from agent_bom.cli import main

    rows = audit_claude_code_settings({"permissions": {"defaultMode": "bypassPermissions"}}, "user")
    agent = Agent(name="claude-code", agent_type=AgentType.CLAUDE_CODE, config_path="x", metadata={"permission_findings": rows})
    monkeypatch.setattr(discovery, "discover_all", lambda **kwargs: [agent])
    result = CliRunner().invoke(main, ["mcp", "audit", str(tmp_path)])
    assert result.exit_code == 1, result.output
    assert "HIGH: Claude Code permission prompts bypassed by default" in result.output


def test_scan_pipeline_seeds_permission_findings():
    from types import SimpleNamespace

    from agent_bom.cli.agents.scan_pipeline.report import _seed_findings_and_scan_id

    rows = audit_claude_code_settings({"permissions": {"allow": ["Bash"]}}, "user")
    agent = Agent(name="claude-code", agent_type=AgentType.CLAUDE_CODE, config_path="x", metadata={"permission_findings": rows})
    ctx = SimpleNamespace(cloud_provider_successes=[], cloud_provider_warnings=[], cloud_provider_failures=[])
    state = SimpleNamespace(agents=[agent], blast_radii=[], scan_sources=[], ctx=ctx)
    opts = SimpleNamespace(
        preset=None,
        reproducible=False,
        aws=False,
        aws_cis_benchmark=False,
        azure_flag=False,
        azure_cis_benchmark=False,
        gcp_flag=False,
        gcp_cis_benchmark=False,
        aws_region=None,
        aws_profile=None,
        azure_subscription=None,
        gcp_project=None,
    )
    _seed_findings_and_scan_id(opts, state)
    assert any(f.evidence.get("permission_type") == "UNSCOPED_SHELL_ALLOW" for f in state.findings)


def test_passive_audit_attach_adds_permission_findings_once():
    from agent_bom.models import AIBOMReport
    from agent_bom.scanners.mcp_audit import attach_passive_mcp_audit

    rows = audit_claude_code_settings({"permissions": {"allow": ["Bash"]}}, "user")
    agent = Agent(name="claude-code", agent_type=AgentType.CLAUDE_CODE, config_path="x", metadata={"permission_findings": rows})
    report = AIBOMReport(agents=[agent])
    attach_passive_mcp_audit(report)
    attach_passive_mcp_audit(report)
    assert [f.evidence.get("permission_type") for f in report.findings] == ["UNSCOPED_SHELL_ALLOW"]


def test_global_scan_from_home_reads_user_settings_once(fake_home, monkeypatch):
    from agent_bom.discovery.agent_permission_posture import collect_permission_findings

    _write(fake_home / ".claude/settings.json", json.dumps({"permissions": {"allow": ["Bash"]}}))
    monkeypatch.chdir(fake_home)
    assert [(f["scope"], f["type"]) for f in collect_permission_findings(None, include_user=True)] == [("user", "UNSCOPED_SHELL_ALLOW")]
