"""JSON rows for native AST flow findings (the ``flow_findings`` side block)."""

from __future__ import annotations

from typing import Any


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
            "severity": finding.severity,
            "cwe_ids": list(finding.cwe_ids),
            **({"suppression": finding.suppression} if finding.suppression else {}),
            **({"path_context": finding.path_context} if getattr(finding, "path_context", "") else {}),
            **({"downgrade_reason": finding.downgrade_reason} if getattr(finding, "downgrade_reason", "") else {}),
        }
        for finding in findings
    ]
