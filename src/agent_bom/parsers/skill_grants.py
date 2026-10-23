"""Skill capability boundaries: capability maps and Claude Code ``allowed-tools``.

A skill declares its boundary either with a ``capabilities`` /
``skill_capabilities`` map or with Claude Code's ``allowed-tools`` grants
(string, space-separated or list form). Unscoped shell, or unscoped network
fetch combined with file writes, is a broad grant worth reviewing.
"""

from __future__ import annotations

import re

import yaml

from agent_bom.parsers.skill_audit_types import SkillFinding
from agent_bom.parsers.skills import SkillMetadata

_REQUIRED_CAPABILITY_KEYS = {
    "read_findings",
    "read_inventory",
    "read_audit_log",
    "write_findings",
    "outbound_http",
    "shell_exec",
}
_ALLOWED_TOOLS_KEYS = ("allowed-tools", "allowed_tools")
_TOOL_GRANT_RE = re.compile(r"[A-Za-z_][\w.-]*(?:\([^)]*\))?")
SHELL_TOOLS = frozenset({"bash", "powershell"})
WRITE_TOOLS = frozenset({"write", "edit", "multiedit", "notebookedit"})
_UNSCOPED_ARGS = {None, "", "*", ":*"}


def parse_allowed_tools(raw_frontmatter: str) -> list[str] | None:
    """Return ``allowed-tools`` grants, or None when the key is absent."""
    try:
        data = yaml.safe_load(raw_frontmatter)
    except yaml.YAMLError:
        data = None
    if isinstance(data, dict):
        key = next((k for k in _ALLOWED_TOOLS_KEYS if k in data), None)
        if key is None:
            return None
        value = data[key]
        items = value if isinstance(value, list) else [value] if value is not None else []
        return [grant for item in items for grant in _TOOL_GRANT_RE.findall(str(item))]
    line = re.search(r"^allowed[-_]tools:[ \t]*(.*)$", raw_frontmatter, re.MULTILINE)
    return _TOOL_GRANT_RE.findall(line.group(1)) if line else None


def capability_findings(meta: SkillMetadata, source_file: str) -> list[SkillFinding]:
    """Findings for a missing, incomplete or overly broad capability boundary."""
    raw_frontmatter = meta.raw_frontmatter or ""
    if re.search(r"^\s*(?:skill_)?capabilities:\s*$", raw_frontmatter, re.MULTILINE):
        return _incomplete_capability_map(meta, source_file, raw_frontmatter)
    grants = parse_allowed_tools(raw_frontmatter)
    if grants is not None:
        return _broad_grant_findings(meta, source_file, grants)
    return [
        SkillFinding(
            severity="low",
            category="missing_capability_declaration",
            title="No explicit skill capability declaration",
            detail=(
                f"Skill '{meta.name or 'unknown'}' in {source_file} does not declare "
                "an explicit capability map. Sandboxed runtimes and Snowflake Native "
                "App deployments need declared read, write, network, and shell "
                "boundaries before a skill can be safely invoked."
            ),
            source_file=source_file,
            recommendation=(
                "Add a 'capabilities' or 'skill_capabilities' frontmatter block "
                "covering read_findings, read_inventory, read_audit_log, "
                "write_findings, outbound_http, and shell_exec."
            ),
            context="metadata",
        )
    ]


def _incomplete_capability_map(meta: SkillMetadata, source_file: str, raw_frontmatter: str) -> list[SkillFinding]:
    missing_keys = sorted(key for key in _REQUIRED_CAPABILITY_KEYS if not re.search(rf"^\s*{key}\s*:", raw_frontmatter, re.MULTILINE))
    if not missing_keys:
        return []
    return [
        SkillFinding(
            severity="low",
            category="incomplete_capability_declaration",
            title="Incomplete skill capability declaration",
            detail=(
                f"Skill '{meta.name or 'unknown'}' in {source_file} declares "
                "skill capabilities but omits: "
                f"{', '.join(missing_keys)}. Missing keys make sandbox and "
                "customer-controlled runtime policy generation ambiguous."
            ),
            source_file=source_file,
            recommendation=("Declare every required capability key explicitly and use false instead of omitting a denied capability."),
            context="metadata",
        )
    ]


def split_grant(grant: str) -> tuple[str, str | None]:
    """Split ``Tool(specifier)`` into the lower-cased tool name and specifier."""
    name, _, rest = grant.partition("(")
    arg = rest[:-1].strip() if rest.endswith(")") else None
    return name.strip().lower(), arg


def unscoped_grants(grants: list[str], names: set[str] | frozenset[str], extra_unscoped: frozenset[str] = frozenset()) -> list[str]:
    """Grants naming one of ``names`` with no specifier or a match-everything one."""
    found = []
    for grant in grants:
        name, arg = split_grant(grant)
        if name in names and (arg in _UNSCOPED_ARGS or arg in extra_unscoped):
            found.append(grant)
    return found


def _broad_grant_findings(meta: SkillMetadata, source_file: str, grants: list[str]) -> list[SkillFinding]:
    shell, fetch = unscoped_grants(grants, SHELL_TOOLS), unscoped_grants(grants, {"webfetch"})
    write = unscoped_grants(grants, WRITE_TOOLS)
    if shell and fetch:
        risk = "run any shell command and fetch arbitrary URLs, a direct execute-and-egress path,"
    elif shell:
        risk = "run any shell command"
    elif fetch and write:
        risk = "fetch arbitrary URLs and write files"
    else:
        return []
    evidence = ", ".join(shell + fetch + write)
    return [
        SkillFinding(
            severity="medium",
            category="broad_tool_grant",
            title="Broad tool grant in allowed-tools",
            detail=(
                f"Skill '{meta.name or 'unknown'}' in {source_file} declares allowed-tools "
                f"[{evidence}], which lets it {risk} without a per-call permission prompt."
            ),
            source_file=source_file,
            recommendation=(
                "Scope each grant to the commands and domains the skill needs, for example "
                "Bash(git diff:*) or WebFetch(domain:docs.example.com), and drop unused tools."
            ),
            context="metadata",
        )
    ]
