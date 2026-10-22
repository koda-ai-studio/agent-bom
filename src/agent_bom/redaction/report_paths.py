"""Keep IaC file identities and references aligned when public paths are hidden."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from agent_bom.redaction.payload import _DEPTH_LIMIT
from agent_bom.security import sanitize_sensitive_payload


def prepare_iac_path_redaction(report: dict[str, Any]) -> dict[str, Any]:
    """Replace hidden paths and their references with stable opaque labels.

    Display-only basename/REDACTED labels merge distinct files when a report is
    rebuilt into a graph. Map the path and both IaC foreign keys together before
    the normal sanitizer runs. No string is exempted from secret redaction.
    Safe relative paths retain their existing IDs. Already redacted legacy
    reports cannot recover lost identity; we do not invent it.
    """
    section = report.get("iac_findings")
    hits = section.get("findings", []) if isinstance(section, dict) else []
    rows = report.get("findings", [])
    evidence = [row.get("evidence") for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
    candidates = (hits if isinstance(hits, list) else []) + [item for item in evidence if isinstance(item, dict) and item.get("iac")]
    replacements: dict[str, str] = {}
    for hit in candidates:
        if not isinstance(hit, dict):
            continue
        path = hit.get("file_path")
        if not isinstance(path, str) or not path or sanitize_sensitive_payload(path, key="file_path") == path:
            continue
        # A deterministic join key, not encryption: known paths can be guessed.
        opaque = f"<path:{uuid5(NAMESPACE_URL, 'agent-bom:iac-path:' + path)}>"
        replacements[path] = opaque
    if not replacements:
        return report

    # Also hide occurrences in descriptions and compound edge IDs. Longest first
    # prevents a parent path from consuming a more specific file coordinate.
    pattern = re.compile("|".join(re.escape(path) for path in sorted(replacements, key=len, reverse=True)))

    @lru_cache(maxsize=4096)
    def rewrite_text(value: str) -> str:
        return replacements[value] if value in replacements else pattern.sub(lambda match: replacements[match.group()], value)

    def rewrite(value: Any, depth: int = 0) -> Any:
        if depth >= _DEPTH_LIMIT:
            return "[truncated]"
        if isinstance(value, str):
            return rewrite_text(value)
        if isinstance(value, dict):
            return {key: rewrite(item, depth + 1) for key, item in value.items()}
        if isinstance(value, list | tuple | set):
            return [rewrite(item, depth + 1) for item in value]
        return value

    return rewrite(report)
