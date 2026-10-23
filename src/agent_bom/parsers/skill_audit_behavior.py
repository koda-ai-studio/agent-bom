"""Behavioral and code-block scanners for skill security audits."""

from __future__ import annotations

import ast
import re

from agent_bom.ast.source_reader import parse_python_source
from agent_bom.parsers.skill_audit_code import (
    _DYNAMIC_CODE_CALLS,
    _FILE_MUTATION_CALLS,
    _JS_DYNAMIC_CODE_CALLS,
    _JS_FILE_MUTATION_CALLS,
    _JS_SUBPROCESS_CALLS,
    _JS_TS_FENCED_BLOCK_RE,
    _PYTHON_FENCED_BLOCK_RE,
    _SUBPROCESS_CALLS,
    _call_name,
    _collect_js_ts_call_names,
    _line_column,
    _open_mode_is_mutating,
)
from agent_bom.parsers.skill_audit_context import _is_prohibition_context
from agent_bom.parsers.skill_audit_patterns import _BEHAVIORAL_PATTERNS
from agent_bom.parsers.skill_audit_types import SkillFinding


def _first_actionable_match(pattern: re.Pattern, content: str) -> tuple[re.Match | None, bool]:
    """Return the first match plus whether it only survives as policy prose.

    Prefers a directive match. Falls back to the first suppressed match so the
    evidence is still reported (downgraded) rather than silently discarded.
    """
    demoted: re.Match | None = None
    for candidate in pattern.finditer(content):
        if _is_prohibition_context(content, candidate.start(), candidate.end()):
            if demoted is None:
                demoted = candidate
            continue
        return candidate, False
    return demoted, demoted is not None


def _scan_behavioral_risks(raw_content: dict[str, str]) -> list[SkillFinding]:
    """Scan full skill file text for behavioral risk patterns.

    Each file is matched against its raw bytes and against the obfuscation-
    resistant projection shared with the prompt-template scanner
    (:func:`agent_bom.parsers.prompt_scanner.normalize_for_matching` — NFKC,
    homoglyph folding, zero-width stripping, de-leeting, base64 decoding), so
    a homoglyph- or zero-width-obfuscated injection in ``CLAUDE.md`` is caught
    by the same rules that already catch it in ``system_prompt.md``. The raw
    pass runs first and wins, keeping real line numbers on plain text.

    Args:
        raw_content: Mapping of filename → full text content.

    Returns:
        List of SkillFinding with context="behavioral" (a directive) or
        "possibly_documentation" (evidence that reads as policy prose, demoted
        to low severity so the operator, not the file's author, decides).
    """
    from agent_bom.parsers.prompt_scanner import normalize_for_matching

    findings: list[SkillFinding] = []

    for filename, content in raw_content.items():
        seen_categories: set[str] = set()
        passes: list[tuple[str, str]] = [(content, "static_text")]
        normalized = normalize_for_matching(content)
        if normalized != content:
            passes.append((normalized, "normalized_text"))

        for bp in _BEHAVIORAL_PATTERNS:
            if bp.category in seen_categories:
                continue

            candidates: list[tuple[re.Match, bool, str, str, str]] = []
            for text, evidence_source in passes:
                found, demoted = _first_actionable_match(bp.pattern, text)
                severity = bp.severity
                confidence = "high" if bp.severity in {"critical", "high"} else "medium"

                if found is None and bp.weak_pattern is not None:
                    # Only a low-confidence keyword/heuristic matched. Keep the
                    # finding visible but demote it so a lone descriptive keyword
                    # cannot dominate the file's trust verdict.
                    found, demoted = _first_actionable_match(bp.weak_pattern, text)
                    if found is not None:
                        severity = bp.weak_severity
                        confidence = "low"

                if found is not None:
                    candidates.append((found, demoted, evidence_source, severity, confidence))
                    if not demoted:
                        break

            # A directive beats policy prose; a raw-text hit beats a de-obfuscated
            # one (it carries real line numbers).
            for match, demoted, evidence_source, severity, confidence in sorted(candidates, key=lambda c: c[1]):
                lines_are_real = evidence_source == "static_text"
                text = content if lines_are_real else normalized
                context = "behavioral"
                if demoted:
                    # Suppression must never delete evidence: report it at a
                    # severity that cannot drive the verdict and say why.
                    severity = "low"
                    confidence = "low"
                    context = "possibly_documentation"

                seen_categories.add(bp.category)
                snippet = match.group(0).strip()
                if len(snippet) > 120:
                    snippet = snippet[:117] + "..."
                line, column = _line_column(text, match.start()) if lines_are_real else (None, None)

                detail = f'Detected in {filename}: "{snippet}". {bp.description}'
                if not lines_are_real:
                    detail = (
                        f"Detected in {filename} after de-obfuscation (homoglyph / zero-width / "
                        f'leetspeak / base64): "{snippet}". {bp.description}'
                    )
                if demoted:
                    detail += (
                        " Reported at reduced severity: the surrounding prose reads as policy or "
                        "documentation rather than an instruction. Confirm before dismissing."
                    )

                findings.append(
                    SkillFinding(
                        severity=severity,
                        category=bp.category,
                        title=bp.title,
                        detail=detail,
                        source_file=filename,
                        recommendation=bp.description,
                        context=context,
                        evidence_source=evidence_source,
                        confidence=confidence,
                        source_line=line,
                        source_column=column,
                    )
                )
                break

    return findings


def _scan_python_ast_risks(raw_content: dict[str, str]) -> list[SkillFinding]:
    """Scan Python fenced code blocks for semantic risk patterns."""
    findings: list[SkillFinding] = []

    for filename, content in raw_content.items():
        seen_categories: set[str] = set()
        for block_match in _PYTHON_FENCED_BLOCK_RE.finditer(content):
            block = block_match.group(1)
            block_start_line, _block_column = _line_column(content, block_match.start(1))
            try:
                tree = parse_python_source(block)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue

                call_name = _call_name(node.func)
                if not call_name:
                    continue

                if call_name in _DYNAMIC_CODE_CALLS and "ast_dynamic_code_execution" not in seen_categories:
                    seen_categories.add("ast_dynamic_code_execution")
                    findings.append(
                        SkillFinding(
                            severity="high",
                            category="ast_dynamic_code_execution",
                            title="Python AST detected dynamic code execution",
                            detail=(
                                f"Detected `{call_name}` in a Python code block in {filename}. "
                                "Dynamic evaluation makes instruction surfaces harder to review and can hide unsafe behavior."
                            ),
                            source_file=filename,
                            recommendation="Remove dynamic code execution or replace it with explicit, statically reviewable logic.",
                            context="code_block",
                            evidence_source="ast_python",
                            confidence="high",
                            source_line=block_start_line + getattr(node, "lineno", 1) - 1,
                            source_column=getattr(node, "col_offset", 0) + 1,
                        )
                    )

                if call_name in _SUBPROCESS_CALLS and "ast_shell_execution" not in seen_categories:
                    seen_categories.add("ast_shell_execution")
                    findings.append(
                        SkillFinding(
                            severity="high",
                            category="ast_shell_execution",
                            title="Python AST detected shell/process execution",
                            detail=(
                                f"Detected `{call_name}` in a Python code block in {filename}. "
                                "Subprocess execution expands the skill's authority and increases command-injection risk."
                            ),
                            source_file=filename,
                            recommendation=(
                                "Avoid spawning shells or subprocesses from skills unless the action "
                                "is narrowly scoped and explicitly reviewed."
                            ),
                            context="code_block",
                            evidence_source="ast_python",
                            confidence="high",
                            source_line=block_start_line + getattr(node, "lineno", 1) - 1,
                            source_column=getattr(node, "col_offset", 0) + 1,
                        )
                    )

                is_file_mutation = call_name in _FILE_MUTATION_CALLS and (call_name != "open" or _open_mode_is_mutating(node))
                if is_file_mutation and "ast_file_mutation" not in seen_categories:
                    seen_categories.add("ast_file_mutation")
                    findings.append(
                        SkillFinding(
                            severity="medium",
                            category="ast_file_mutation",
                            title="Python AST detected file mutation",
                            detail=(
                                f"Detected mutating file operation `{call_name}` in a Python code block in {filename}. "
                                "File writes and deletions can change agent memory, repo state, or local trust boundaries."
                            ),
                            source_file=filename,
                            recommendation=(
                                "Require explicit review for file mutations and avoid write/delete flows in reusable skill instructions."
                            ),
                            context="code_block",
                            evidence_source="ast_python",
                            confidence="high",
                            source_line=block_start_line + getattr(node, "lineno", 1) - 1,
                            source_column=getattr(node, "col_offset", 0) + 1,
                        )
                    )

    return findings


def _scan_js_ts_semantic_risks(raw_content: dict[str, str]) -> list[SkillFinding]:
    """Scan JS/TS fenced code blocks for semantic risk patterns."""
    findings: list[SkillFinding] = []

    for filename, content in raw_content.items():
        seen_categories: set[str] = set()
        for match in _JS_TS_FENCED_BLOCK_RE.finditer(content):
            language_hint = match.group("language").lower()
            block = match.group("code")
            block_start_line, _block_column = _line_column(content, match.start("code"))
            call_names = _collect_js_ts_call_names(block, language_hint=language_hint)

            if _JS_DYNAMIC_CODE_CALLS & call_names and "ast_js_dynamic_code_execution" not in seen_categories:
                call_name = sorted(_JS_DYNAMIC_CODE_CALLS & call_names)[0]
                seen_categories.add("ast_js_dynamic_code_execution")
                findings.append(
                    SkillFinding(
                        severity="high",
                        category="ast_js_dynamic_code_execution",
                        title="JS/TS code analysis detected dynamic code execution",
                        detail=(
                            f"Detected `{call_name}` in a JS/TS code block in {filename}. "
                            "Dynamic evaluation makes instruction surfaces harder to review and can hide unsafe behavior."
                        ),
                        source_file=filename,
                        recommendation=(
                            "Remove dynamic code execution from skill code blocks or replace it with explicit, reviewable logic."
                        ),
                        context="code_block",
                        evidence_source="ast_js",
                        confidence="high",
                        source_line=block_start_line,
                        source_column=1,
                    )
                )

            if _JS_SUBPROCESS_CALLS & call_names and "ast_js_shell_execution" not in seen_categories:
                call_name = sorted(_JS_SUBPROCESS_CALLS & call_names)[0]
                seen_categories.add("ast_js_shell_execution")
                findings.append(
                    SkillFinding(
                        severity="high",
                        category="ast_js_shell_execution",
                        title="JS/TS code analysis detected shell/process execution",
                        detail=(
                            f"Detected `{call_name}` in a JS/TS code block in {filename}. "
                            "Process execution expands the skill's authority and increases command-injection risk."
                        ),
                        source_file=filename,
                        recommendation=(
                            "Avoid child-process execution in reusable skills unless the action is narrowly scoped and explicitly reviewed."
                        ),
                        context="code_block",
                        evidence_source="ast_js",
                        confidence="high",
                        source_line=block_start_line,
                        source_column=1,
                    )
                )

            if _JS_FILE_MUTATION_CALLS & call_names and "ast_js_file_mutation" not in seen_categories:
                call_name = sorted(_JS_FILE_MUTATION_CALLS & call_names)[0]
                seen_categories.add("ast_js_file_mutation")
                findings.append(
                    SkillFinding(
                        severity="medium",
                        category="ast_js_file_mutation",
                        title="JS/TS code analysis detected file mutation",
                        detail=(
                            f"Detected mutating file operation `{call_name}` in a JS/TS code block in {filename}. "
                            "File writes and deletions can change agent memory, repo state, or local trust boundaries."
                        ),
                        source_file=filename,
                        recommendation=(
                            "Require explicit review for JS/TS file mutations and avoid write/delete flows in reusable skill instructions."
                        ),
                        context="code_block",
                        evidence_source="ast_js",
                        confidence="high",
                        source_line=block_start_line,
                        source_column=1,
                    )
                )

    return findings


_BEHAVIOR_FAMILIES: dict[str, str] = {
    "shell_access": "code_execution",
    "dangerous_tool": "code_execution",
    "agent_delegation": "code_execution",
    "privilege_escalation": "code_execution",
    "repository_modification": "code_execution",
    "destructive_action": "code_execution",
    "financial_transaction": "code_execution",
    "ast_dynamic_code_execution": "code_execution",
    "ast_shell_execution": "code_execution",
    "ast_file_mutation": "code_execution",
    "ast_js_dynamic_code_execution": "code_execution",
    "ast_js_shell_execution": "code_execution",
    "ast_js_file_mutation": "code_execution",
    "external_url": "network_access",
    "network_exposure": "network_access",
    "messaging_capability": "network_access",
    "voice_telephony": "network_access",
    "surveillance_access": "network_access",
    "undocumented_network": "network_access",
    "prompt_coercion": "prompt_coercion",
    "confirmation_bypass": "prompt_coercion",
    "memory_poisoning": "prompt_coercion",
    "input_injection": "prompt_coercion",
    "credential_file_access": "data_access",
    "data_exfiltration": "data_access",
    "credential_exfiltration": "data_access",
    "remote_code_execution": "code_execution",
    "excessive_permissions": "data_access",
    "persistence_mechanism": "persistence",
    "broad_tool_grant": "code_execution",
    "missing_capability_declaration": "data_access",
    "incomplete_capability_declaration": "data_access",
}


def _summarize_behavioral_findings(findings: list[SkillFinding]) -> dict[str, object]:
    """Summarize findings into stable review-oriented behavior families.

    Evidence demoted to ``context="possibly_documentation"`` is counted on its
    own key rather than folded into the risk families: it is retained so an
    operator can review it, not asserted as directed behavior.
    """
    family_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    high_or_critical = 0
    possibly_documentation = 0

    for finding in findings:
        family = _BEHAVIOR_FAMILIES.get(finding.category)
        if not family:
            continue
        if finding.context == "possibly_documentation":
            possibly_documentation += 1
            continue
        family_counts[family] = family_counts.get(family, 0) + 1
        category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
        if finding.severity in {"critical", "high"}:
            high_or_critical += 1

    top_categories = [category for category, _count in sorted(category_counts.items(), key=lambda item: (-item[1], item[0]))[:5]]
    return {
        "families": family_counts,
        "top_categories": top_categories,
        "high_or_critical": high_or_critical,
        "possibly_documentation": possibly_documentation,
    }
