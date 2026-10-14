"""Report-only finding rows: prompt-scan fallback and browser-extension risk.

These rows are appended to the serialized ``findings`` array without passing
through :meth:`AIBOMReport.to_findings`, so they carry their graph node key
here, the same key the graph builder projects them onto.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agent_bom.evidence.finding_node_ids import stamp_finding_node_ids
from agent_bom.finding import FINDING_SCHEMA_VERSION
from agent_bom.security import sanitize_path_label

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport


def _stable_report_finding_id(*parts: object) -> str:
    raw = ":".join(str(part or "") for part in parts)
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"agent-bom:finding:{raw}"))


def _prompt_scan_findings(prompt_scan: dict) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for item in prompt_scan.get("findings") or []:
        if not isinstance(item, dict):
            continue
        source_file = str(item.get("source_file") or "")
        line_number = item.get("line_number")
        title = str(item.get("title") or "Prompt security finding")
        category = str(item.get("category") or "prompt_security")
        severity = str(item.get("severity") or "unknown").lower()
        findings.append(
            {
                "schema_version": FINDING_SCHEMA_VERSION,
                "id": _stable_report_finding_id("prompt_scan", source_file, line_number, title, item.get("matched_text")),
                "canonical_id": _stable_report_finding_id("prompt_scan", source_file, line_number, title, item.get("matched_text")),
                "finding_type": "PROMPT_SECURITY",
                "source": "PROMPT_SCAN",
                "asset": {
                    "name": Path(source_file).name if source_file else "prompt",
                    "asset_type": "prompt_template",
                    "identifier": source_file or None,
                    "location": sanitize_path_label(source_file) if source_file else None,
                    "stable_id": _stable_report_finding_id("prompt_asset", source_file),
                    "canonical_id": _stable_report_finding_id("prompt_asset", source_file),
                },
                "severity": severity,
                "effective_severity": severity,
                "title": title,
                "description": item.get("detail") or title,
                "category": category,
                "line_number": line_number,
                "matched_text": item.get("matched_text"),
                "remediation_guidance": item.get("recommendation"),
                "scan_sources": ["prompt_scan"],
            }
        )
    return findings


def _browser_extension_findings(browser_extensions: dict) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for item in browser_extensions.get("extensions") or []:
        if not isinstance(item, dict):
            continue
        risk_reasons = [str(reason) for reason in item.get("risk_reasons") or []]
        extension_id = str(item.get("id") or item.get("name") or "unknown")
        browser = str(item.get("browser") or "browser")
        name = str(item.get("name") or extension_id)
        severity = str(item.get("risk_level") or "unknown").lower()
        findings.append(
            {
                "schema_version": FINDING_SCHEMA_VERSION,
                "id": _stable_report_finding_id("browser_extension", browser, extension_id, item.get("version")),
                "canonical_id": _stable_report_finding_id("browser_extension", browser, extension_id, item.get("version")),
                "finding_type": "BROWSER_EXT",
                "source": "BROWSER_EXT",
                "asset": {
                    "name": name,
                    "asset_type": "browser_extension",
                    "identifier": extension_id,
                    "location": sanitize_path_label(item.get("path")) if item.get("path") else None,
                    "stable_id": _stable_report_finding_id("browser_extension_asset", browser, extension_id),
                    "canonical_id": _stable_report_finding_id("browser_extension_asset", browser, extension_id),
                },
                "severity": severity,
                "effective_severity": severity,
                "title": f"{name} browser extension risk",
                "description": "; ".join(risk_reasons) if risk_reasons else f"{name} has {severity} browser-extension risk",
                "browser": browser,
                "version": item.get("version"),
                "permissions": item.get("permissions") or [],
                "host_permissions": item.get("host_permissions") or [],
                "risk_reasons": risk_reasons,
                "remediation_guidance": "Review extension permissions and remove or restrict the extension if it is not required.",
                "scan_sources": ["browser_extensions"],
            }
        )
    return findings


def _append_side_findings(findings: list[dict[str, Any]], report: "AIBOMReport") -> None:
    """Append prompt-scan and browser-extension rows the unified stream does not already carry."""
    if report.prompt_scan_data and not any(finding.get("source") == "PROMPT_SCAN" for finding in findings if isinstance(finding, dict)):
        findings.extend(stamp_finding_node_ids(_prompt_scan_findings(report.prompt_scan_data)))
    if report.browser_extensions:
        findings.extend(stamp_finding_node_ids(_browser_extension_findings(report.browser_extensions)))


__all__ = ["_append_side_findings", "stamp_finding_node_ids"]
