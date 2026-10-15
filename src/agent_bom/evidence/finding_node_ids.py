"""Graph node ids for serialized finding rows, without importing the graph stack.

Report serialization stamps ``finding_node_id`` with the same pure function the
graph projection uses, so CLI output never needs the graph package loaded.
"""

from __future__ import annotations

from typing import Any

_BENCHMARK_SECTIONS = {
    "aws": "cis_benchmark",
    "snowflake": "snowflake_cis_benchmark",
    "azure": "azure_cis_benchmark",
    "gcp": "gcp_cis_benchmark",
    "databricks": "databricks_security",
}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def iac_misconfig_node_id(rule_id: Any, path: Any, line: Any) -> str:
    """One IaC rule hit at one file line; absent parts read ``unknown`` / ``0``, never ``None``."""
    return f"misconfig:iac:{rule_id or 'unknown'}:{path or 'unknown'}:{line or 0}"


def benchmark_misconfig_node_id(section: str, check_id: Any) -> str:
    return f"misconfig:{section}:{check_id or 'unknown'}"


def mcp_audit_node_id(finding_id: str) -> str:
    return f"misconfig:mcp_audit:{finding_id}"


def skill_audit_node_id(key: str) -> str:
    return f"misconfig:skill_audit:{key}"


def _iac_node_id(evidence: dict[str, Any]) -> str | None:
    if not evidence.get("iac"):
        return None
    return iac_misconfig_node_id(evidence.get("rule_id"), evidence.get("file_path"), evidence.get("line_number"))


def _benchmark_node_id(evidence: dict[str, Any]) -> str | None:
    section = _BENCHMARK_SECTIONS.get(_text(evidence.get("provider")).lower())
    check_id = _text(evidence.get("check_id"))
    if not evidence.get("benchmark") or not section or not check_id or _text(evidence.get("status")).upper() != "FAIL":
        return None
    return benchmark_misconfig_node_id(section, check_id)


def _is_mcp_audit(row: dict[str, Any], evidence: dict[str, Any]) -> bool:
    return row.get("source") == "MCP_SCAN" and bool(
        evidence.get("detector") == "mcp_enforcement" or evidence.get("mcp_auth_weakness") or evidence.get("mcp_tool_rule")
    )


def finding_row_node_id(row: dict[str, Any]) -> str | None:
    """The graph node a serialized finding row is projected onto."""
    finding_id = _text(row.get("id"))
    if not finding_id or not _text(row.get("finding_type")):
        return None
    evidence = _dict(row.get("evidence"))
    vuln_id = _text(row.get("vulnerability_id")) or _text(row.get("cve_id"))
    if row.get("finding_type") == "CVE" and vuln_id:
        return f"vuln:{vuln_id}"
    dedicated = _iac_node_id(evidence) or _benchmark_node_id(evidence)
    if dedicated:
        return dedicated
    if _is_mcp_audit(row, evidence):
        return mcp_audit_node_id(finding_id)
    if row.get("source") == "SKILL":
        return skill_audit_node_id(finding_id)
    source = _text(row.get("source")).lower() or "finding"
    return f"misconfig:{source}:{finding_id}"


def stamp_finding_node_ids(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fill a missing ``finding_node_id`` with the node the graph projects the row onto."""
    for row in rows:
        if isinstance(row, dict) and not row.get("finding_node_id"):
            node_id = finding_row_node_id(row)
            if node_id:
                row["finding_node_id"] = node_id
    return rows
