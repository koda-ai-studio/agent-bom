"""Ai components ai prompts helpers."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from agent_bom.finding import Finding
from agent_bom.security import sanitize_command_args

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport, BlastRadius

# ─── Secret redaction (no-exfiltration-by-default) ───────────────────────────
#
# Issue #3206 hard requirement #4: redact secrets before any prompt leaves the
# control plane. These patterns cover the credential shapes most likely to be
# swept into a prompt from scanned configs, env blocks, or source snippets.
# Redaction runs at every provider network boundary, so it protects local
# Ollama calls as well as remote providers.

# Prefix / block patterns, in priority order (more specific first — e.g.
# ``sk-ant-`` must run before the generic ``sk-``).
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Private key blocks (PEM)
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL), "<redacted-private-key>"),
    # Provider API keys / tokens with recognizable prefixes
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b"), "<redacted-anthropic-key>"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), "<redacted-openai-key>"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{16,}\b"), "<redacted-github-token>"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "<redacted-slack-token>"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "<redacted-aws-access-key>"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "<redacted-google-key>"),
    (re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"), "<redacted-hf-token>"),
    # Common bearer material can appear outside an Authorization header.
    (re.compile(r"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b"), "<redacted-jwt>"),
    # Database/broker URLs often carry userinfo credentials in otherwise useful
    # finding text. Remove the whole secret-bearing URL before model egress.
    (
        re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?)://[^\s'\"<>]+:[^\s'\"<>@]+@[^\s'\"<>]+"),
        "<redacted-connection-url>",
    ),
    # Bearer tokens in headers / auth strings
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}"), "Bearer <redacted-token>"),
)

# KEY=VALUE / "key": "value" assignments for secret-named variables. Handled
# separately with a value heuristic so we don't clobber credential *names*
# (e.g. ``Exposed credentials: OPENAI_API_KEY``) that appear as values.
_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b([A-Za-z0-9_]*(?:secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|credential)[A-Za-z0-9_]*)\b"
    r"(\s*[:=]\s*)(['\"]?)([^\s'\";,}]{6,})(\3)"
)

# A bare UPPER_SNAKE_CASE identifier is a variable *name*, not a secret value.
_IDENTIFIER_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _looks_like_secret_value(value: str) -> bool:
    """Heuristic: does a captured assignment value look like an actual secret?

    Rejects bare identifiers (``OPENAI_API_KEY``, ``DATABASE_URL``) that are
    names rather than values; accepts strings with real entropy.
    """
    if _IDENTIFIER_RE.match(value):
        return False
    # Real secrets mix character classes or are long — require a lowercase
    # letter or digit alongside length so ALL_CAPS words are left alone.
    return len(value) >= 6 and bool(re.search(r"[a-z0-9]", value))


def _redact_assignment(match: re.Match[str]) -> str:
    name, sep, quote, value, _ = match.groups()
    if not _looks_like_secret_value(value):
        return match.group(0)
    return f"{name}{sep}{quote}<redacted>{quote}"


def redact_secrets(text: str) -> str:
    """Scrub secret-looking material from *text* before it reaches a model.

    Idempotent and conservative: it targets recognizable credential shapes
    (API keys, tokens, private keys, ``SECRET=...`` assignments) and leaves the
    surrounding text — including credential *names* like ``OPENAI_API_KEY`` —
    intact so the model still has useful context.
    """
    if not text:
        return text
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    text = _ASSIGNMENT_PATTERN.sub(_redact_assignment, text)
    return text


# ─── Prompt builders ─────────────────────────────────────────────────────────


def _build_blast_radius_prompt(br: BlastRadius) -> str:
    """Build a prompt for analyzing a single blast radius finding."""
    agents = _bounded_prompt_list([a.name for a in br.affected_agents], item_limit=240, count_limit=5, default="None")
    creds = _bounded_prompt_list(list(br.exposed_credentials), item_limit=240, count_limit=5, default="None")
    tools = _bounded_prompt_list([t.name for t in br.exposed_tools], item_limit=240, count_limit=5, default="None")
    owasp = _bounded_prompt_list(list(br.owasp_tags), item_limit=120, count_limit=3, default="None")
    prefix = (
        "You are an AI security analyst. Analyze this vulnerability finding "
        "in the context of an AI agent's MCP (Model Context Protocol) tool chain.\n\n"
    )
    dynamic = (
        f"Vulnerability: {_bounded_prompt_text(br.vulnerability.id, 240, 'unknown')}\n"
        f"Severity: {br.vulnerability.severity.value} (CVSS: {br.vulnerability.cvss_score or 'N/A'})\n"
        f"Summary: {_bounded_prompt_text(br.vulnerability.summary, 4000, 'Unavailable')}\n"
        f"Package: {_bounded_prompt_text(br.package.name, 240, 'unknown')}@"
        f"{_bounded_prompt_text(br.package.version, 120, 'unknown')} "
        f"({_bounded_prompt_text(br.package.ecosystem, 80, 'unknown')})\n"
        f"Fixed version: {_bounded_prompt_text(br.vulnerability.fixed_version, 120, 'No fix available')}\n"
        f"Affected AI agents: {agents}\n"
        f"Exposed credentials: {creds}\n"
        f"Reachable tools: {tools}\n"
        f"OWASP LLM Top 10 tags: {owasp}\n"
        f"Risk score: {br.risk_score:.1f}/10\n\n"
    )
    suffix = (
        "Provide a concise 2-3 sentence analysis covering:\n"
        "1. Why this vulnerability matters specifically in an AI agent context\n"
        "2. How an attacker could exploit this through the agent's tool chain\n"
        "3. The specific business impact given the exposed credentials and tools\n\n"
        "Be specific about the attack path. Do not use generic language."
    )
    return _compose_bounded_prompt(prefix, dynamic, suffix)


def _build_executive_summary_prompt(report: AIBOMReport) -> str:
    """Build a prompt for generating an executive summary."""
    critical_ids = [br.vulnerability.id for br in report.blast_radii if br.vulnerability.severity.value == "critical"]
    cred_count = len({c for br in report.blast_radii for c in br.exposed_credentials})
    tool_count = len({t.name for br in report.blast_radii for t in br.exposed_tools})

    prefix = "You are a CISO's AI security advisor. Write a one-paragraph executive summary of this AI agent security scan.\n\n"
    dynamic = (
        f"Scan results:\n"
        f"- {report.total_agents} AI agent(s) scanned\n"
        f"- {report.total_servers} MCP server(s) discovered\n"
        f"- {report.total_packages} package dependencies analyzed\n"
        f"- {report.total_vulnerabilities} vulnerabilities found\n"
        f"- {len(report.critical_vulns)} critical findings\n"
        f"- {cred_count} unique credentials at risk\n"
        f"- {tool_count} unique tools in blast radius\n"
        f"- Top critical CVEs: "
        f"{_bounded_prompt_list(list(critical_ids), item_limit=240, count_limit=5, default='None')}\n\n"
    )
    suffix = (
        "Write for a non-technical executive audience. Focus on business risk, "
        "not technical details. Include a clear risk rating (Critical/High/Medium/Low) "
        "and 1-2 recommended actions. Keep to one paragraph, 4-6 sentences."
    )
    return _compose_bounded_prompt(prefix, dynamic, suffix)


def _build_threat_chain_prompt(report: AIBOMReport) -> str:
    """Build a prompt for threat chain analysis."""
    chains = []
    for br in report.blast_radii[:5]:
        agents = _bounded_prompt_list([a.name for a in br.affected_agents], item_limit=240, count_limit=2, default="none")
        tools = _bounded_prompt_list([t.name for t in br.exposed_tools], item_limit=240, count_limit=3, default="none")
        creds = _bounded_prompt_list(list(br.exposed_credentials), item_limit=240, count_limit=3, default="none")
        chains.append(
            f"- {_bounded_prompt_text(br.vulnerability.id, 240, 'unknown')} in "
            f"{_bounded_prompt_text(br.package.name, 240, 'unknown')}@"
            f"{_bounded_prompt_text(br.package.version, 120, 'unknown')} | "
            f"agents: {agents} | tools: {tools} | creds: {creds}"
        )
    omitted = max(len(report.blast_radii) - len(chains), 0)
    if omitted:
        chains.append(f"... [{omitted} additional blast-radius finding(s) omitted]")

    prefix = (
        "You are a red team AI security specialist. Analyze how an attacker could "
        "chain these vulnerabilities through an AI agent's MCP tool access to achieve "
        "maximum impact.\n\nVulnerabilities in blast radius:\n"
    )
    dynamic = f"{chr(10).join(chains)}\n\n"
    suffix = (
        "Describe 1-2 realistic attack chains (3-5 steps each) showing:\n"
        "1. Initial exploitation vector\n"
        "2. Lateral movement through MCP tools\n"
        "3. Credential exfiltration or data access\n"
        "4. Final impact\n\n"
        "Be specific about which tools and credentials are used at each step. "
        "Format as numbered steps."
    )
    return _compose_bounded_prompt(prefix, dynamic, suffix)


def _bounded_ai_text(value: object, limit: int, default: str = "") -> str:
    """Normalize untrusted model text into a bounded single string."""
    if not isinstance(value, str):
        return default
    return redact_secrets(value).strip()[:limit] or default


_MAX_AI_PROMPT_CHARS = 32_000

_PROMPT_TRUNCATION_MARKER = "\n... [prompt content omitted to enforce size limit]\n"


def _bounded_prompt_text(value: object, limit: int, default: str = "") -> str:
    """Bound one untrusted prompt field and make any truncation explicit."""
    if not isinstance(value, str):
        return default
    normalized = redact_secrets(value).strip()
    if not normalized:
        return default
    if len(normalized) <= limit:
        return normalized
    marker = "... [truncated]"
    return normalized[: max(limit - len(marker), 0)] + marker


def _bounded_prompt_list(values: list[object], *, item_limit: int, count_limit: int, default: str) -> str:
    """Render a bounded list with an auditable omitted-item marker."""
    selected = [_bounded_prompt_text(value, item_limit) for value in values[:count_limit]]
    selected = [value for value in selected if value]
    omitted = max(len(values) - count_limit, 0)
    if omitted:
        selected.append(f"... [{omitted} item(s) omitted]")
    return ", ".join(selected) or default


def _compose_bounded_prompt(prefix: str, dynamic: str, suffix: str) -> str:
    """Keep provider instructions intact while bounding untrusted dynamic input."""
    fixed_length = len(prefix) + len(suffix)
    if fixed_length >= _MAX_AI_PROMPT_CHARS:
        return (prefix + suffix)[:_MAX_AI_PROMPT_CHARS]
    budget = _MAX_AI_PROMPT_CHARS - fixed_length
    if len(dynamic) <= budget:
        return prefix + dynamic + suffix
    marker = _PROMPT_TRUNCATION_MARKER
    retained = max(budget - len(marker), 0)
    return prefix + dynamic[:retained] + marker[: budget - retained] + suffix


def _build_finding_assessment_prompt(findings: list["Finding"]) -> str:
    """Build a bounded prompt from safe finding fields, excluding raw evidence."""
    rows = []
    for finding in findings:
        rows.append(
            {
                "finding_id": finding.id,
                "type": str(getattr(finding.finding_type, "value", finding.finding_type)),
                "source": str(getattr(finding.source, "value", finding.source)),
                "severity": finding.severity,
                "title": _bounded_ai_text(finding.title, 240),
                "description": _bounded_ai_text(finding.description, 800),
                "asset": {
                    "name": _bounded_ai_text(finding.asset.name, 240),
                    "type": _bounded_ai_text(finding.asset.asset_type, 80),
                },
                "risk_score": finding.risk_score,
                "reachability": finding.reachability,
                "is_kev": finding.is_kev,
                "controls": [f"{tag.framework}:{tag.control}" for tag in finding.controls[:20]],
            }
        )
    return (
        "Classify and triage these deterministic security findings. Your output is advisory only: "
        "do not change severity, suppress findings, or invent finding IDs. Return JSON only as "
        '{"assessments":[{"finding_id":"...","classification":"...",'
        '"confidence":"high|medium|low","false_positive_likelihood":"high|medium|low",'
        '"rationale":"...","suggested_controls":["..."]}]}.\nFindings:\n' + json.dumps(rows, separators=(",", ":"))
    )


# ─── Skill file AI analysis ──────────────────────────────────────────────────

_MAX_AI_SKILL_FILES = 10

_MAX_AI_SKILL_FILE_CHARS = 6_000

_MAX_AI_SKILL_FINDINGS = 100


def _canonical_skill_source_path(value: object) -> str:
    """Return the exact bounded path representation shown to the provider."""
    return _bounded_prompt_text(value, 240, "skill-file")


def _build_skill_analysis_prompt(raw_content: dict[str, str], static_findings: list[dict]) -> str:
    """Build a prompt that sends raw skill file text + static findings to the LLM.
    The prompt asks the model to classify intent, review existing findings,
    detect new threats, and assess overall risk.
    """
    # Bound the whole request as well as each item. Static scanning still
    # covers every discovered file; this is only the optional advisory model
    # view and must not turn a large repository into one unbounded request.
    file_sections = []
    selected_files = list(raw_content.items())[:_MAX_AI_SKILL_FILES]
    for filepath, content in selected_files:
        safe_path = _canonical_skill_source_path(filepath)
        redacted_content = redact_secrets(content)
        truncated = redacted_content[:_MAX_AI_SKILL_FILE_CHARS]
        if len(redacted_content) > _MAX_AI_SKILL_FILE_CHARS:
            truncated += "\n... [truncated]"
        file_sections.append(f"### File: {safe_path}\n```\n{truncated}\n```")
    omitted_files = max(len(raw_content) - len(selected_files), 0)
    if omitted_files:
        file_sections.append(f"... [{omitted_files} additional skill file(s) omitted from advisory AI analysis]")
    files_text = "\n\n".join(file_sections)
    selected_findings: list[dict[str, str]] = []
    for finding in static_findings[:_MAX_AI_SKILL_FINDINGS]:
        selected_findings.append(
            {
                "severity": _bounded_ai_text(finding.get("severity"), 20, "unknown"),
                "category": _bounded_ai_text(finding.get("category"), 80, "unknown"),
                "title": _bounded_ai_text(finding.get("title"), 240, "Untitled finding"),
                "detail": _bounded_ai_text(finding.get("detail"), 500),
                "source_file": _bounded_ai_text(finding.get("source_file"), 240),
                "context": _bounded_ai_text(finding.get("context"), 80),
            }
        )
    findings_text = json.dumps(selected_findings, indent=2) if selected_findings else "[]"
    omitted_findings = max(len(static_findings) - len(selected_findings), 0)
    if omitted_findings:
        findings_text += f"\n... [{omitted_findings} additional static finding(s) omitted from advisory AI analysis]"
    return (
        "You are an AI security auditor specializing in analyzing skill files "
        "(also called rules files, instruction files, or CLAUDE.md / .cursorrules / "
        "copilot-instructions.md files). These are instructions that developers write "
        "for AI coding assistants — they control how the AI behaves in a project.\n\n"
        "IMPORTANT CONTEXT: A line saying 'never bind to 0.0.0.0' is a SAFETY "
        "instruction, not a risk. A line saying 'always use 0.0.0.0 for the server' "
        "is a RISKY directive. You must distinguish between warnings/safety guidance "
        "and dangerous directives.\n\n"
        "## Raw skill file content\n\n"
        f"{files_text}\n\n"
        "## Static analysis findings\n\n"
        f"{findings_text}\n\n"
        "## Your tasks\n\n"
        "(a) **Intent classification**: For each notable instruction in the files, "
        "classify it as a 'warning' (safety guidance) or 'directive' (tells the AI to do something).\n\n"
        "(b) **Review static findings**: For each static finding above, provide a verdict: "
        "'confirmed' (real risk), 'false_positive' (not actually risky), or "
        "'severity_adjusted' (real but severity should change). Explain your reasoning.\n\n"
        "(c) **Detect new threats**: Look for threats the static analysis may have missed, "
        "including: social_engineering, prompt_injection, credential_harvesting, "
        "supply_chain, permission_escalation, data_exfiltration, obfuscation.\n\n"
        "(d) **Overall risk assessment**: Rate the overall risk as 'critical', 'high', "
        "'medium', 'low', or 'safe' and provide a 2-3 sentence summary.\n\n"
        "Respond with ONLY a JSON object (no markdown fencing, no extra text) with these keys:\n"
        "- overall_risk_level: string ('critical'|'high'|'medium'|'low'|'safe')\n"
        "- summary: string (2-3 sentence overall assessment)\n"
        "- finding_reviews: list of objects, each with:\n"
        "    - title: string (matching the static finding title)\n"
        "    - verdict: 'confirmed' | 'false_positive' | 'severity_adjusted'\n"
        "    - adjusted_severity: string | null (only if severity_adjusted)\n"
        "    - reasoning: string\n"
        "    - confidence: 'high' | 'medium' | 'low' (required; missing values normalize to low)\n"
        "- new_findings: list of objects, each with:\n"
        "    - severity: 'critical' | 'high' | 'medium' | 'low'\n"
        "    - category: string (one of the threat categories above)\n"
        "    - title: string\n"
        "    - detail: string\n"
        "    - recommendation: string\n"
        "    - confidence: 'high' | 'medium' | 'low'\n"
        "    - source_file: string (must exactly match one analyzed file path)"
    )


# ─── MCP config security analysis ──────────────────────────────────────────


def _build_mcp_config_analysis_prompt(report: "AIBOMReport") -> str:
    """Build a prompt for LLM-powered MCP configuration security analysis.

    Examines the full server configuration (not individual CVEs) for
    architectural security risks.
    """
    server_configs: list[str] = []
    max_servers = 10
    total_servers = sum(len(agent.mcp_servers) for agent in report.agents)
    for agent in report.agents[:20]:
        for server in agent.mcp_servers:
            if len(server_configs) >= max_servers:
                break
            creds = _bounded_prompt_list(list(server.credential_names), item_limit=160, count_limit=20, default="none")
            tools = _bounded_prompt_list([tool.name for tool in server.tools], item_limit=240, count_limit=10, default="unknown")
            bounded_args = [_bounded_prompt_text(arg, 500) for arg in server.args[:5]]
            server_args = sanitize_command_args(bounded_args)
            server_configs.append(
                f"- Server: {_bounded_prompt_text(server.name, 240, 'unknown')}\n"
                f"  Command: {_bounded_prompt_text(server.command, 500, 'unknown')} {' '.join(server_args)}\n"
                f"  Transport: {server.transport.value}\n"
                f"  Tools: {tools}\n"
                f"  Credentials: {creds}\n"
                f"  Agent: {_bounded_prompt_text(agent.name, 240, 'unknown')} ({agent.agent_type.value})"
            )
        if len(server_configs) >= max_servers:
            break

    omitted_servers = max(total_servers - len(server_configs), 0)
    if omitted_servers:
        server_configs.insert(0, f"... [{omitted_servers} additional MCP server(s) omitted from advisory AI analysis]")

    prefix = (
        "You are an AI infrastructure security analyst specializing in MCP "
        "(Model Context Protocol) configurations. Analyze these MCP server "
        "configurations for security risks.\n\nMCP Server Configurations:\n"
    )
    dynamic = f"{chr(10).join(server_configs)}\n\n"
    suffix = (
        "Analyze for:\n"
        "1. **Missing authentication**: Servers with no credential env vars "
        "that expose write/execute tools\n"
        "2. **Overly permissive access**: Servers with filesystem write, "
        "shell exec, or database write tools\n"
        "3. **Credential exposure**: Multiple high-privilege credentials on "
        "a single server (blast radius risk)\n"
        "4. **Suspicious patterns**: AWM-generated environments (fastapi-mcp "
        "with no auth), unverified servers with critical tools\n"
        "5. **Transport risks**: SSE/HTTP servers without TLS\n\n"
        "Respond with ONLY a JSON object with these keys:\n"
        "- overall_risk: string ('Critical'|'High'|'Medium'|'Low')\n"
        "- summary: string (2-3 sentence assessment)\n"
        "- findings: list of objects, each with:\n"
        "    - severity: 'critical'|'high'|'medium'|'low'\n"
        "    - category: string (e.g. auth_missing, overpermissive, "
        "credential_exposure, awm_pattern, transport_risk)\n"
        "    - title: string\n"
        "    - detail: string\n"
        "    - recommendation: string"
    )
    return _compose_bounded_prompt(prefix, dynamic, suffix)
