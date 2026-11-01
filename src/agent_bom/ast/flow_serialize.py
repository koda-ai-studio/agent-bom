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
        }
        for finding in findings
    ]
