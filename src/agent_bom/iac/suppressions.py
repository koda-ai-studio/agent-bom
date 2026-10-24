"""Inline suppressions for IaC findings.

A finding is suppressed when its own line, or the line directly above it,
carries ``agent-bom: ignore[RULE-ID] <reason>`` (several ids may be
comma-separated). The reason is required: a marker without one suppresses
nothing, so every accepted exception is explained where it lives.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_bom.iac.models import IaCFinding

_MARKER = re.compile(r"agent-bom:\s*ignore\[([A-Za-z0-9_,\- ]+)\]\s*(\S.*)?")
_MAX_BYTES = 2 * 1024 * 1024


def _lines(path: Path, cache: dict[Path, list[str]]) -> list[str]:
    if path not in cache:
        try:
            cache[path] = path.read_text(encoding="utf-8", errors="replace").splitlines() if path.stat().st_size <= _MAX_BYTES else []
        except OSError:
            cache[path] = []
    return cache[path]


def _suppresses(line: str, rule_id: str) -> bool:
    match = _MARKER.search(line)
    if match is None or not (match.group(2) or "").strip():
        return False
    return rule_id.upper() in {part.strip().upper() for part in match.group(1).split(",")}


def apply_inline_suppressions(findings: list[IaCFinding], root: Path) -> tuple[list[IaCFinding], list[IaCFinding]]:
    """Split findings into (active, suppressed) by inline markers in their source files."""
    cache: dict[Path, list[str]] = {}
    active: list[IaCFinding] = []
    suppressed: list[IaCFinding] = []
    for finding in findings:
        relative = finding.repository_relative_path or finding.file_path
        lines = _lines(root / relative, cache) if relative and finding.line_number > 0 else []
        index = finding.line_number - 1
        nearby = [lines[i] for i in (index, index - 1) if 0 <= i < len(lines)]
        (suppressed if any(_suppresses(line, finding.rule_id) for line in nearby) else active).append(finding)
    return active, suppressed
