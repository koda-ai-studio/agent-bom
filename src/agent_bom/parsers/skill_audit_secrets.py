"""Hardcoded secrets in skill and instruction files.

Runs the secret scanner's own line matchers over instruction text, so the
credential formats and placeholder rules are the ones ``agent-bom secrets``
applies to files. A finding names the secret type and line, never the value.
A value that carries a documentation marker (``EXAMPLE``, ``xxxx``, ``...``)
is reported at low severity as possible documentation rather than dropped.
"""

from __future__ import annotations

from agent_bom.parsers.skill_audit_types import SkillFinding
from agent_bom.scanners.secret_lines import TextSecret, scan_text

_RECOMMENDATION = (
    "Remove the literal credential from the instruction file, rotate it, and have the skill read it from the "
    "environment or a secret manager at run time."
)


def _secret_finding(filename: str, secret: TextSecret) -> SkillFinding:
    detail = f"{secret.secret_type} on line {secret.line_number} of {filename}. The value is not reproduced here."
    if secret.sample:
        detail += " Reported at reduced severity: the value carries a documentation sample marker. Confirm before dismissing."
    return SkillFinding(
        severity="low" if secret.sample else secret.severity,
        category="hardcoded_secret",
        title=f"Hardcoded secret: {secret.secret_type}",
        detail=detail,
        source_file=filename,
        recommendation=_RECOMMENDATION,
        context="possibly_documentation" if secret.sample else "behavioral",
        evidence_source="static_text",
        confidence="low" if secret.sample else "high",
        source_line=secret.line_number,
        source_column=1,
    )


def scan_hardcoded_secrets(raw_content: dict[str, str]) -> list[SkillFinding]:
    """Report every line of every file that holds a literal secret."""
    return [_secret_finding(filename, secret) for filename, content in raw_content.items() for secret in scan_text(content)]
