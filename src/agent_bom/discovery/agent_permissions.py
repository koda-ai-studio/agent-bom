"""Audit coding-agent permission settings for no-prompt or no-sandbox execution.

Covers Claude Code ``settings.json`` files (permission mode, allow rules,
project MCP auto-approval) and Codex ``config.toml`` (approval policy, sandbox
mode, sandbox network access, profiles). Findings follow the Cortex Code
permission-audit shape: ``severity``/``type``/``description`` plus the file
scope, key path, the non-secret value that triggered it and the safer change.

Only mode names, booleans and the exact unscoped rule strings are reported;
no other setting value is copied, so secrets in ``env`` or scoped rules never
reach a finding.
"""

from __future__ import annotations

from typing import Any

from agent_bom.parsers.skill_grants import SHELL_TOOLS, WRITE_TOOLS, unscoped_grants

CLAUDE_CODE = "claude-code"
CODEX = "codex"

_BYPASS_IGNORED_SCOPES = frozenset({"project", "local"})
_WEB_FETCH_UNSCOPED = frozenset({"domain:*"})
_WRITE_UNSCOPED = frozenset({"**", "//**"})


def _row(client: str, scope: str, severity: str, kind: str, key_path: str, value: str, description: str, fix: str) -> dict[str, Any]:
    return {
        "severity": severity,
        "type": kind,
        "client": client,
        "scope": scope,
        "key_path": key_path,
        "value": value,
        "description": description,
        "recommendation": fix,
    }


# ── Claude Code ──────────────────────────────────────────────────────────────


def audit_claude_code_settings(settings: dict, scope: str, *, bypass_disabled: bool = False) -> list[dict[str, Any]]:
    """Audit one Claude Code settings file.

    ``scope`` is ``user``, ``project``, ``local`` or ``managed``.
    ``bypass_disabled`` means a user or managed file sets
    ``permissions.disableBypassPermissionsMode`` to ``"disable"``.
    """
    if not isinstance(settings, dict):
        return []
    permissions = settings.get("permissions")
    permissions = permissions if isinstance(permissions, dict) else {}
    findings = _claude_mode_findings(permissions, scope, bypass_disabled)
    allow = permissions.get("allow")
    if isinstance(allow, list):
        findings.extend(_claude_allow_findings([rule for rule in allow if isinstance(rule, str)], scope))
    if settings.get("enableAllProjectMcpServers") is True:
        findings.append(
            _row(
                CLAUDE_CODE,
                scope,
                "MEDIUM",
                "ALL_PROJECT_MCP_SERVERS_APPROVED",
                "enableAllProjectMcpServers",
                "true",
                "Every MCP server declared in a project .mcp.json is approved without a prompt, "
                "so a cloned repository can start servers you never reviewed.",
                "Remove enableAllProjectMcpServers and list reviewed servers in enabledMcpjsonServers.",
            )
        )
    if settings.get("skipDangerousModePermissionPrompt") is True:
        findings.append(
            _row(
                CLAUDE_CODE,
                scope,
                "LOW",
                "BYPASS_CONFIRMATION_SKIPPED",
                "skipDangerousModePermissionPrompt",
                "true",
                "The confirmation dialog before bypassPermissions mode is skipped.",
                "Remove skipDangerousModePermissionPrompt so entering bypass mode stays a deliberate choice.",
            )
        )
    return findings


def _claude_mode_findings(permissions: dict, scope: str, bypass_disabled: bool) -> list[dict[str, Any]]:
    if permissions.get("defaultMode") != "bypassPermissions" or bypass_disabled:
        return []
    ignored = scope in _BYPASS_IGNORED_SCOPES
    description = (
        "Sessions start in bypassPermissions mode: Claude Code runs shell commands, edits files and "
        "fetches URLs without asking, including writes to protected paths such as .git and .claude."
    )
    if ignored:
        description += " Claude Code v2.1.257 and later ignore this value in project or local settings; earlier versions honor it."
    return [
        _row(
            CLAUDE_CODE,
            scope,
            "MEDIUM" if ignored else "HIGH",
            "BYPASS_PERMISSIONS_DEFAULT",
            "permissions.defaultMode",
            "bypassPermissions",
            description,
            'Set permissions.defaultMode to "default" (or "acceptEdits"), keep bypass for isolated containers via '
            '--permission-mode, and set permissions.disableBypassPermissionsMode to "disable".',
        )
    ]


def _claude_allow_findings(rules: list[str], scope: str) -> list[dict[str, Any]]:
    shell = set(unscoped_grants(rules, SHELL_TOOLS))
    fetch = set(unscoped_grants(rules, {"webfetch"}, _WEB_FETCH_UNSCOPED))
    write = set(unscoped_grants(rules, WRITE_TOOLS, _WRITE_UNSCOPED))
    findings = []
    for rule in rules:
        if rule in shell:
            findings.append(_allow_row(scope, "MEDIUM", "UNSCOPED_SHELL_ALLOW", rule, _SHELL_WHY, _SHELL_FIX))
        elif rule in fetch:
            findings.append(_allow_row(scope, "MEDIUM", "UNSCOPED_WEB_FETCH_ALLOW", rule, _FETCH_WHY, _FETCH_FIX))
        elif _is_server_wide_mcp_rule(rule):
            findings.append(_allow_row(scope, "MEDIUM", "SERVER_WIDE_MCP_ALLOW", rule, _MCP_WHY, _MCP_FIX))
        elif rule in write:
            findings.append(_allow_row(scope, "LOW", "UNSCOPED_FILE_WRITE_ALLOW", rule, _WRITE_WHY, _WRITE_FIX))
    return findings


_SHELL_WHY = "Every shell command runs without a permission prompt."
_SHELL_FIX = "Replace it with the commands you need, for example Bash(git diff *) or Bash(npm run test *)."
_FETCH_WHY = "Claude can fetch any URL without a prompt, an open egress path for anything it has read."
_FETCH_FIX = "Allow only the hosts you need, for example WebFetch(domain:docs.example.com)."
_MCP_WHY = "Every tool of this MCP server, including any write or delete tools, runs without a prompt."
_MCP_FIX = "Allow the specific tools you use, for example mcp__<server>__get_issue or mcp__<server>__get_*."
_WRITE_WHY = "File edits anywhere the rule reaches are accepted without a prompt."
_WRITE_FIX = "Scope the rule to the paths you edit, for example Edit(./src/**)."


def _allow_row(scope: str, severity: str, kind: str, rule: str, why: str, fix: str) -> dict[str, Any]:
    return _row(CLAUDE_CODE, scope, severity, kind, "permissions.allow", rule, f"Allow rule {rule} - {why}", fix)


def _is_server_wide_mcp_rule(rule: str) -> bool:
    """``mcp__<server>`` or ``mcp__<server>__*``; unanchored globs are ignored by Claude Code."""
    if not rule.startswith("mcp__") or "(" in rule:
        return False
    parts = rule[len("mcp__") :].split("__")
    server = parts[0]
    if not server or "*" in server:
        return False
    return len(parts) == 1 or (len(parts) == 2 and parts[1] == "*")


# ── Codex ────────────────────────────────────────────────────────────────────


def audit_codex_config(config: dict, scope: str) -> list[dict[str, Any]]:
    """Audit one Codex config file.

    ``scope`` is ``user`` (``config.toml``), ``profile`` (a
    ``<name>.config.toml`` profile file) or ``project`` (``.codex/config.toml``,
    where Codex ignores ``profiles``).
    """
    if not isinstance(config, dict):
        return []
    approval, sandbox = config.get("approval_policy"), config.get("sandbox_mode")
    findings = _codex_policy_findings(approval, sandbox, scope, "")
    workspace = config.get("sandbox_workspace_write")
    if isinstance(workspace, dict) and workspace.get("network_access") is True:
        findings.append(
            _row(
                CODEX,
                scope,
                "LOW",
                "SANDBOX_NETWORK_ENABLED",
                "sandbox_workspace_write.network_access",
                "true",
                "Commands in the workspace-write sandbox can reach the network.",
                "Set sandbox_workspace_write.network_access = false unless the work needs outbound access.",
            )
        )
    profiles = config.get("profiles") if scope != "project" else None
    if isinstance(profiles, dict):
        for name, profile in profiles.items():
            if not isinstance(profile, dict) or not ({"approval_policy", "sandbox_mode"} & profile.keys()):
                continue
            findings.extend(
                _codex_policy_findings(
                    profile.get("approval_policy", approval), profile.get("sandbox_mode", sandbox), scope, f"profiles.{name}"
                )
            )
    return findings


def _codex_policy_findings(approval: object, sandbox: object, scope: str, prefix: str) -> list[dict[str, Any]]:
    never, unsandboxed = approval == "never", sandbox == "danger-full-access"

    def key(name: str) -> str:
        return f"{prefix}.{name}" if prefix else name

    if never and unsandboxed:
        return [
            _row(
                CODEX,
                scope,
                "HIGH",
                "NO_APPROVAL_NO_SANDBOX",
                prefix or "approval_policy, sandbox_mode",
                "approval_policy=never, sandbox_mode=danger-full-access",
                "Codex runs every command with full filesystem and network access and never asks for approval.",
                'Use sandbox_mode = "workspace-write" with approval_policy = "on-request"; keep danger-full-access '
                "for isolated containers or VMs.",
            )
        ]
    if unsandboxed:
        return [
            _row(
                CODEX,
                scope,
                "MEDIUM",
                "SANDBOX_DISABLED",
                key("sandbox_mode"),
                "danger-full-access",
                "Commands run with no sandbox: full filesystem and network access, gated only by the approval policy.",
                'Set sandbox_mode = "workspace-write" (or "read-only") and grant extra writable_roots only where needed.',
            )
        ]
    if never:
        return [
            _row(
                CODEX,
                scope,
                "LOW",
                "APPROVALS_DISABLED",
                key("approval_policy"),
                "never",
                "Codex never asks for approval; the sandbox is the only boundary on what commands do.",
                'Set approval_policy = "on-request" for interactive work.',
            )
        ]
    return []
