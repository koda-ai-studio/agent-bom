"""Instructions hidden in invisible Unicode in skill and instruction files.

Unicode tag characters and variation-selector runs render as nothing, yet a
model reads the text they encode. The shared normalisation in
``agent_bom.runtime.text_normalize`` decodes them so every pattern scanner sees
the hidden text; this module reports the hiding itself, quoting a visible
rendering of what was decoded.
"""

from __future__ import annotations

from agent_bom.parsers.skill_audit_types import SkillFinding
from agent_bom.runtime.text_normalize import HiddenPayload, hidden_payloads

_QUOTE_LIMIT = 160
_KIND_LABELS = {"tag": "Unicode tag", "variation_selector": "variation-selector"}


def visible_rendering(text: str) -> str:
    """Escape control characters and truncate, so the quote is readable."""
    rendered = "".join(char if char.isprintable() else repr(char)[1:-1] for char in text)
    return rendered if len(rendered) <= _QUOTE_LIMIT else rendered[: _QUOTE_LIMIT - 3] + "..."


def _hidden_finding(filename: str, content: str, payload: HiddenPayload, total: int) -> SkillFinding:
    line = content.count("\n", 0, payload.start) + 1
    column = payload.start - content.rfind("\n", 0, payload.start)
    others = f" {total - 1} more hidden run(s) in this file." if total > 1 else ""
    return SkillFinding(
        severity="high",
        category="hidden_instruction",
        title="Instruction hidden in invisible Unicode characters",
        detail=(
            f"{payload.end - payload.start} invisible {_KIND_LABELS[payload.kind]} characters on line {line} of {filename} "
            f'decode to: "{visible_rendering(payload.decoded)}".{others} A reviewer sees nothing here; a model reads it.'
        ),
        source_file=filename,
        recommendation="Delete the invisible characters and review the file as it is actually read, not as it renders.",
        context="behavioral",
        evidence_source="static_text",
        confidence="high",
        source_line=line,
        source_column=column,
    )


def scan_hidden_instructions(raw_content: dict[str, str]) -> list[SkillFinding]:
    """Report the first hidden payload carrying visible text in each file."""
    findings: list[SkillFinding] = []
    for filename, content in raw_content.items():
        payloads = [payload for payload in hidden_payloads(content) if payload.decoded.strip()]
        if payloads:
            findings.append(_hidden_finding(filename, content, payloads[0], len(payloads)))
    return findings
