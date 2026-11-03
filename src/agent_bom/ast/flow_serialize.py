"""JSON rows for native AST flow findings (the ``flow_findings`` side block)."""

from __future__ import annotations

from typing import Any

from agent_bom.core.path_context import CONTEXT_SEVERITY, classify_path_context, context_downgrade_reason


def _path_context_fields(file_path: str, severity: str) -> dict[str, Any]:
    """Flows in documentation/example/test files are labelled and lowered to ``low``."""
    context = classify_path_context(file_path)
    if context is None:
        return {"severity": severity}
    return {"severity": CONTEXT_SEVERITY, "path_context": context, "downgrade_reason": context_downgrade_reason(context)}


def flow_finding_rows(findings: list[Any]) -> list[dict[str, Any]]:
    """Serialise ``FlowFinding`` objects (typed loosely so ``ast_models`` can import this module)."""
    return [
        {
            "category": finding.category,
            "title": finding.title,
            "detail": finding.detail,
            "file": finding.file_path,
            "line": finding.line_number,
            "entrypoint": finding.entrypoint,
            "sink": finding.sink,
            "call_path": finding.call_path,
            "source": finding.source,
            "cwe_ids": list(finding.cwe_ids),
            **({"suppression": finding.suppression} if finding.suppression else {}),
            **_path_context_fields(finding.file_path, finding.severity),
        }
        for finding in findings
    ]
