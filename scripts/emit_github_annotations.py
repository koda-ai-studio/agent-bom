#!/usr/bin/env python3
"""Emit GitHub Actions annotations from agent-bom result files."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable


def _escape_data(value: object) -> str:
    text = str(value or "")
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(value: object) -> str:
    return _escape_data(value).replace(":", "%3A").replace(",", "%2C")


def _annotation(
    *,
    level: str,
    path: str,
    title: str,
    message: str,
    line: int | None = None,
    col: int | None = None,
) -> str:
    properties = [f"file={_escape_property(path)}"]
    if line is not None and line > 0:
        properties.append(f"line={line}")
    if col is not None and col > 0:
        properties.append(f"col={col}")
    if title:
        properties.append(f"title={_escape_property(title)}")
    return f"::{level} {','.join(properties)}::{_escape_data(message)}"


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _level(severity: str) -> str:
    """Map a finding severity to the GitHub annotation level."""
    rank = _SEVERITY_RANK.get(severity.lower(), 0)
    if rank >= 3:
        return "error"
    if rank == 2:
        return "warning"
    return "notice"


def _score_severity(value: object) -> str:
    try:
        score = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "unknown"
    if score > 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score >= 0.1 else "unknown"


def _as_int(value: object) -> int | None:
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _skills_json_annotations(data: dict[str, Any]) -> Iterable[tuple[str, str]]:
    for file_report in data.get("files", []):
        if not isinstance(file_report, dict):
            continue
        fallback_path = str(file_report.get("path") or "")
        audit = file_report.get("audit")
        if not isinstance(audit, dict):
            continue
        for finding in audit.get("findings", []):
            if not isinstance(finding, dict):
                continue
            path = str(finding.get("source_file") or fallback_path)
            if not path:
                continue
            severity = str(finding.get("severity") or "unknown")
            category = str(finding.get("category") or "skill")
            title = str(finding.get("title") or "agent-bom skill finding")
            detail = str(finding.get("detail") or title)
            yield (
                severity,
                _annotation(
                    level=_level(severity),
                    path=path,
                    line=_as_int(finding.get("source_line")),
                    col=_as_int(finding.get("source_column")),
                    title=f"agent-bom {severity.upper()} {category}",
                    message=f"{title}: {detail}",
                ),
            )


def _sarif_annotations(data: dict[str, Any]) -> Iterable[tuple[str, str]]:
    run = (data.get("runs") or [{}])[0]
    if not isinstance(run, dict):
        return
    rules = {str(rule.get("id")): rule for rule in run.get("tool", {}).get("driver", {}).get("rules", []) if isinstance(rule, dict)}
    for result in run.get("results", []):
        if not isinstance(result, dict):
            continue
        location = (result.get("locations") or [{}])[0]
        physical = location.get("physicalLocation", {}) if isinstance(location, dict) else {}
        artifact = physical.get("artifactLocation", {}) if isinstance(physical, dict) else {}
        region = physical.get("region", {}) if isinstance(physical, dict) else {}
        path = str(artifact.get("uri") or "")
        if not path:
            continue
        rule_id = str(result.get("ruleId") or "agent-bom")
        rule = rules.get(rule_id, {})
        rule_name = rule.get("name") if isinstance(rule, dict) else None
        message = str(result.get("message", {}).get("text") or rule_name or rule_id)
        rule_props = rule.get("properties", {}) if isinstance(rule, dict) else {}
        severity = _score_severity(rule_props.get("security-severity") if isinstance(rule_props, dict) else None)
        if severity == "unknown":
            severity = {"error": "high", "warning": "medium", "note": "low"}.get(str(result.get("level") or "warning"), "medium")
        yield (
            severity,
            _annotation(
                level=_level(severity),
                path=path,
                line=_as_int(region.get("startLine")) if isinstance(region, dict) else None,
                col=_as_int(region.get("startColumn")) if isinstance(region, dict) else None,
                title=f"agent-bom {rule_id}",
                message=message,
            ),
        )


def emit_annotations(path: Path, *, max_annotations: int) -> list[str]:
    """Return annotations, highest severity first, capped with a remainder notice."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return []
    if "runs" in data:
        ranked = list(_sarif_annotations(data))
    elif data.get("report_type") == "skills_scan":
        ranked = list(_skills_json_annotations(data))
    else:
        ranked = []
    ranked.sort(key=lambda item: -_SEVERITY_RANK.get(item[0].lower(), 0))
    annotations = [annotation for _severity, annotation in ranked]
    if 0 <= max_annotations < len(annotations):
        remainder = len(annotations) - max_annotations
        annotations = annotations[:max_annotations]
        annotations.append(
            f"::notice title=agent-bom::{remainder} more finding(s) in {_escape_data(path.name)} (annotation cap {max_annotations})"
        )
    return annotations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result_file", type=Path)
    parser.add_argument("--max", type=int, default=50, help="Maximum annotations to emit; -1 emits all.")
    args = parser.parse_args(argv)
    try:
        for annotation in emit_annotations(args.result_file, max_annotations=args.max):
            print(annotation)
    except Exception as exc:
        print(f"::warning::agent-bom annotation emission failed: {_escape_data(exc)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
