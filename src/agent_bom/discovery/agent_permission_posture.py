"""Read coding-agent permission settings files and surface their findings.

Read-only: files are opened without following symlinks, size-capped, and only
parsed. Findings attach to the discovered Claude Code / Codex agent's
``metadata["permission_findings"]`` (a standalone agent is added when the
client has no MCP configuration) and convert to unified findings for scan
reports, the MCP audit tools and the CLI audit.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import tomllib
from pathlib import Path
from typing import Any, Optional

from agent_bom.discovery.agent_permissions import CLAUDE_CODE, CODEX, audit_claude_code_settings, audit_codex_config
from agent_bom.discovery.platform_config import _project_search_dir, _read_text_no_symlink
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import Agent, AgentStatus, AgentType

logger = logging.getLogger(__name__)

METADATA_KEY = "permission_findings"
_MAX_BYTES = 1_000_000
_CLIENT_AGENT_TYPES = {CLAUDE_CODE: AgentType.CLAUDE_CODE, CODEX: AgentType.CODEX_CLI}
_CLIENT_LABELS = {CLAUDE_CODE: "Claude Code", CODEX: "Codex"}
_MANAGED_DIRS = {
    "Darwin": "/Library/Application Support/ClaudeCode",
    "Linux": "/etc/claude-code",
    "Windows": "C:\\Program Files\\ClaudeCode",
}
_TITLES = {
    "BYPASS_PERMISSIONS_DEFAULT": "Claude Code permission prompts bypassed by default",
    "BYPASS_CONFIRMATION_SKIPPED": "Claude Code bypass-mode confirmation skipped",
    "UNSCOPED_SHELL_ALLOW": "Claude Code allows every shell command without a prompt",
    "UNSCOPED_WEB_FETCH_ALLOW": "Claude Code allows fetching any URL without a prompt",
    "SERVER_WIDE_MCP_ALLOW": "Claude Code allows every tool of an MCP server without a prompt",
    "UNSCOPED_FILE_WRITE_ALLOW": "Claude Code allows unscoped file writes without a prompt",
    "ALL_PROJECT_MCP_SERVERS_APPROVED": "Claude Code auto-approves every project MCP server",
    "NO_APPROVAL_NO_SANDBOX": "Codex runs commands with no approval and no sandbox",
    "SANDBOX_DISABLED": "Codex sandbox disabled",
    "APPROVALS_DISABLED": "Codex approvals disabled",
    "SANDBOX_NETWORK_ENABLED": "Codex sandbox network access enabled",
}
_RISK = {"HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}


def managed_settings_dirs() -> list[Path]:
    """System directories that hold Claude Code ``managed-settings.json``."""
    directory = _MANAGED_DIRS.get(platform.system())
    return [Path(directory)] if directory else []


def _claude_home() -> Path:
    return Path(os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude"))


def _codex_home() -> Path:
    return Path(os.environ.get("CODEX_HOME") or os.path.expanduser("~/.codex"))


def _load(path: Path) -> Optional[dict]:
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > _MAX_BYTES:
            return None
        text = _read_text_no_symlink(path)
        data = tomllib.loads(text) if path.suffix == ".toml" else json.loads(text)
    except (OSError, ValueError, tomllib.TOMLDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _display(path: Path, project_root: Optional[Path]) -> str:
    home = Path(os.path.expanduser("~"))
    for root, prefix in ((project_root, ""), (home, "~/")):
        if root is None:
            continue
        try:
            return prefix + path.relative_to(root).as_posix()
        except ValueError:
            continue
    return str(path)


def _claude_files(project_root: Optional[Path], include_user: bool) -> list[tuple[str, Path]]:
    files: list[tuple[str, Path]] = []
    if include_user:
        for directory in managed_settings_dirs():
            files.append(("managed", directory / "managed-settings.json"))
            drop_ins = directory / "managed-settings.d"
            if drop_ins.is_dir() and not drop_ins.is_symlink():
                files.extend(("managed", p) for p in sorted(drop_ins.glob("*.json")))
        files.append(("user", _claude_home() / "settings.json"))
    if project_root is not None:
        files.append(("project", project_root / ".claude" / "settings.json"))
        files.append(("local", project_root / ".claude" / "settings.local.json"))
    return files


def _codex_files(project_root: Optional[Path], include_user: bool) -> list[tuple[str, Path]]:
    files: list[tuple[str, Path]] = []
    if include_user:
        home = _codex_home()
        files.append(("user", home / "config.toml"))
        if home.is_dir() and not home.is_symlink():
            files.extend(("profile", p) for p in sorted(home.glob("*.config.toml")))
    if project_root is not None:
        files.append(("project", project_root / ".codex" / "config.toml"))
    return files


def _bypass_disabled(loaded: list[tuple[str, Path, dict]]) -> bool:
    for scope, _path, data in loaded:
        permissions = data.get("permissions")
        if scope in {"user", "managed"} and isinstance(permissions, dict):
            if permissions.get("disableBypassPermissionsMode") == "disable":
                return True
    return False


def collect_permission_findings(project_dir: Optional[str], *, include_user: bool) -> list[dict[str, Any]]:
    """Audit every Claude Code and Codex settings file in scope."""
    project_root = _project_search_dir(project_dir) if project_dir else (Path.cwd() if include_user else None)
    claude = _load_unique(_claude_files(project_root, include_user))
    disabled = _bypass_disabled(claude)
    findings: list[dict[str, Any]] = []
    for scope, path, data in claude:
        rows = audit_claude_code_settings(data, scope, bypass_disabled=disabled)
        findings.extend({**row, "config_path": _display(path, project_root)} for row in rows)
    for scope, path, data in _load_unique(_codex_files(project_root, include_user)):
        findings.extend({**row, "config_path": _display(path, project_root)} for row in audit_codex_config(data, scope))
    return findings


def _load_unique(files: list[tuple[str, Path]]) -> list[tuple[str, Path, dict]]:
    """Load each file once; a project rooted at home must not re-read user files."""
    seen: set[str] = set()
    loaded: list[tuple[str, Path, dict]] = []
    for scope, path in files:
        key = os.path.normcase(os.path.abspath(path))
        if key in seen:
            continue
        seen.add(key)
        data = _load(path)
        if data is not None:
            loaded.append((scope, path, data))
    return loaded


def attach_permission_findings(agents: list[Agent], project_dir: Optional[str]) -> list[Agent]:
    """Attach permission findings to discovered agents; never fails discovery."""
    try:
        findings = collect_permission_findings(project_dir, include_user=project_dir is None)
    except Exception:  # noqa: BLE001 - a settings audit must not break discovery
        logger.warning("Agent permission settings audit failed")
        return agents
    for client, agent_type in _CLIENT_AGENT_TYPES.items():
        rows = [row for row in findings if row["client"] == client]
        if not rows:
            continue
        agent = next((a for a in agents if a.agent_type == agent_type), None)
        if agent is None:
            agent = Agent(
                name=agent_type.value,
                agent_type=agent_type,
                config_path=rows[0]["config_path"],
                status=AgentStatus.INSTALLED_NOT_CONFIGURED,
            )
            agents.append(agent)
        existing = agent.metadata.get(METADATA_KEY)
        agent.metadata[METADATA_KEY] = [*(existing if isinstance(existing, list) else []), *rows]
    return agents


def evaluate_agent_permission_posture(agents: list[Agent]) -> list[Finding]:
    """Unified findings for every permission finding attached to ``agents``."""
    from agent_bom.compliance_hub import apply_hub_classification

    findings: list[Finding] = []
    for agent in agents:
        rows = agent.metadata.get(METADATA_KEY) if isinstance(agent.metadata, dict) else None
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and row.get("type") in _TITLES:
                findings.append(apply_hub_classification(_to_finding(agent, row)))
    return findings


def _to_finding(agent: Agent, row: dict[str, Any]) -> Finding:
    severity = str(row.get("severity", "LOW")).upper()
    return Finding(
        finding_type=FindingType.PROMPT_SECURITY,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name=agent.name, asset_type="agent", identifier=agent.canonical_id, location=row.get("config_path")),
        severity=severity.lower(),
        title=_TITLES[row["type"]],
        description=str(row.get("description", "")),
        remediation_guidance=str(row.get("recommendation", "")),
        owasp_tags=["LLM06"],
        owasp_agentic_tags=["ASI02", "ASI03"],
        evidence={
            "permission_type": row["type"],
            "client": _CLIENT_LABELS.get(str(row.get("client")), str(row.get("client"))),
            "scope": row.get("scope"),
            "config_path": row.get("config_path"),
            "key_path": row.get("key_path"),
            "value": row.get("value"),
            "rule": f"{row.get('key_path')}={row.get('value')}",
            "assessment_basis": "configuration",
        },
        risk_score=_RISK.get(severity, 2.5),
    )
