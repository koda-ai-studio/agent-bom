"""Inline exceptions for IaC findings.

A finding is suppressed when its own line, or the line directly above it,
carries ``agent-bom: ignore[RULE-ID] [expires=YYYY-MM-DD] [owner=NAME] <reason>``
(several ids may be comma-separated). The reason is required: a marker without
one suppresses nothing, so every accepted exception is explained where it
lives. A marker whose ``expires`` is malformed also suppresses nothing.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_bom.core.iac_exceptions import MAX_REASON
from agent_bom.iac.exceptions import ExceptionNotice, IaCException, InlineLookup, apply_iac_exceptions, parse_expiry
from agent_bom.iac.models import IaCFinding

_MARKER = re.compile(r"agent-bom:\s*ignore\[([A-Za-z0-9_,\- ]+)\]\s*(\S.*)?")
_METADATA = re.compile(r"^(expires|owner)=(\S+)\s*")
_MAX_BYTES = 2 * 1024 * 1024


def _lines(path: Path, cache: dict[Path, list[str]]) -> list[str]:
    if path not in cache:
        try:
            cache[path] = path.read_text(encoding="utf-8", errors="replace").splitlines() if path.stat().st_size <= _MAX_BYTES else []
        except OSError:
            cache[path] = []
    return cache[path]


def _marker_exception(line: str, finding: IaCFinding, origin: str) -> tuple[IaCException | None, ExceptionNotice | None]:
    match = _MARKER.search(line)
    if match is None or finding.rule_id.upper() not in {part.strip().upper() for part in match.group(1).split(",")}:
        return None, None
    rest = (match.group(2) or "").strip()
    metadata: dict[str, str] = {}
    while (meta := _METADATA.match(rest)) is not None:
        metadata[meta.group(1)] = meta.group(2)[:MAX_REASON]
        rest = rest[meta.end() :]
    reason = rest.strip()[:MAX_REASON]
    if not reason:
        return None, None
    base = IaCException(rule=finding.rule_id.upper(), reason=reason, source="inline", origin=origin, owner=metadata.get("owner"))
    if "expires" not in metadata:
        return base, None
    try:
        expires = parse_expiry(metadata["expires"])
    except ValueError:
        message = f"inline exception for {base.describe()} has a malformed expires={metadata['expires']!r}; it is not applied"
        return None, ExceptionNotice.about("invalid", base, message)
    return IaCException(rule=base.rule, reason=reason, source="inline", origin=origin, owner=base.owner, expires=expires), None


def inline_lookup(root: Path) -> InlineLookup:
    """Find the inline marker, if any, that a finding's source file declares for it."""
    cache: dict[Path, list[str]] = {}

    def lookup(finding: IaCFinding) -> tuple[IaCException | None, ExceptionNotice | None]:
        relative = finding.repository_relative_path or finding.file_path
        lines = _lines(root / relative, cache) if relative and finding.line_number > 0 else []
        index = finding.line_number - 1
        problem: ExceptionNotice | None = None
        for i in (index, index - 1):
            if 0 <= i < len(lines):
                found, issue = _marker_exception(lines[i], finding, f"{relative}:{i + 1}")
                if found is not None:
                    return found, None
                problem = problem or issue
        return None, problem

    return lookup


def apply_inline_suppressions(findings: list[IaCFinding], root: Path) -> tuple[list[IaCFinding], list[IaCFinding]]:
    """Split findings into (active, suppressed) by inline markers in their source files."""
    outcome = apply_iac_exceptions(findings, (), inline=inline_lookup(root))
    return outcome.active, outcome.suppressed
