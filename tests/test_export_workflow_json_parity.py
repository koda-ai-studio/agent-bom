"""Every export that carries owner, SLA or workflow status says what the JSON export says.

Each format is rendered from a freshly built report: the JSON and HTML exports
stamp scan completion as ``first_seen`` on the report's own findings, so
rendering JSON first would hide a format that never anchors its SLA.

The fixture mixes the cases that decide a deadline: no first sighting (with
and without a KEV due date that beats the severity window), a persisted older
first sighting, an explicit assignment, and an unrated finding with no
deadline at all.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Mapping
from datetime import datetime, timezone

import pytest

from agent_bom.finding import Asset, Finding, FindingSource, FindingType, blast_radius_to_finding
from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability

_GENERATED_AT = datetime(2026, 11, 1, 12, tzinfo=timezone.utc)

# (cve, severity, kev_due_date, first_seen, owner, explicit sla, status)
_CASES = (
    ("CVE-2026-0001", Severity.CRITICAL, None, None, None, None, None),
    ("CVE-2026-0002", Severity.HIGH, "2026-11-20", None, None, None, None),
    ("CVE-2026-0003", Severity.CRITICAL, "2026-12-01", None, None, None, None),
    ("CVE-2026-0004", Severity.HIGH, None, "2026-06-01T00:00:00+00:00", "platform-sec", None, "in_progress"),
    ("CVE-2026-0005", Severity.HIGH, None, None, "payments-security", "2026-11-15T00:00:00+00:00", "triaged"),
    ("CVE-2026-0006", Severity.MEDIUM, None, None, None, None, None),
    ("CVE-2026-0007", Severity.LOW, "2026-11-25", None, None, None, None),
    ("CVE-2026-0008", Severity.CRITICAL, "2026-11-03", "2026-10-01T00:00:00+00:00", None, None, "open"),
    ("CVE-2026-0009", Severity.UNKNOWN, None, None, None, None, None),
)


def _report() -> AIBOMReport:
    radii: list[BlastRadius] = []
    findings = []
    agents = []
    for index, (cve, severity, kev_due, first_seen, owner, sla, status) in enumerate(_CASES):
        vuln = Vulnerability(
            id=cve,
            summary=f"Workflow parity {cve}",
            severity=severity,
            cvss_score=None,
            fixed_version="2.0.0",
            is_kev=kev_due is not None,
            kev_due_date=kev_due,
        )
        package = Package(name=f"lib-{index}", version="1.0.0", ecosystem="pypi", vulnerabilities=[vuln])
        server = MCPServer(name=f"server-{index}", packages=[package])
        agent = Agent(name=f"agent-{index}", agent_type=AgentType.CLAUDE_DESKTOP, config_path="", mcp_servers=[server])
        radius = BlastRadius(
            vulnerability=vuln,
            package=package,
            affected_servers=[server],
            affected_agents=[agent],
            exposed_credentials=[],
            exposed_tools=[],
        )
        finding = blast_radius_to_finding(radius)
        finding.first_seen = first_seen
        finding.owner = owner
        finding.sla_due_at = sla
        finding.sla_due_at_source = "explicit" if sla else None
        finding.lifecycle_status = status
        agents.append(agent)
        radii.append(radius)
        findings.append(finding)
    findings.append(
        Finding(
            finding_type=FindingType.MCP_BLOCKLIST,
            source=FindingSource.MCP_SCAN,
            asset=Asset(name="server-0", asset_type="mcp_server", identifier="server-0"),
            severity="high",
            title="Blocklisted MCP server",
            owner="mcp-platform",
            lifecycle_status="open",
        )
    )
    return AIBOMReport(agents=agents, blast_radii=radii, findings=findings, generated_at=_GENERATED_AT, tool_version="0.0.0-test")


def _expected() -> dict[str, dict[str, str | None]]:
    from agent_bom.output import to_json

    payload = to_json(_report())
    rows = {}
    for finding in payload["findings"]:
        if finding.get("cve_id"):
            rows[finding["cve_id"]] = {
                "owner": finding.get("owner"),
                "sla_due_at": finding.get("sla_due_at"),
                "sla_due_at_source": finding.get("sla_due_at_source"),
                "workflow_status": finding.get("lifecycle_status"),
            }
    assert set(rows) == {case[0] for case in _CASES}
    return rows


def test_json_fixture_covers_every_deadline_case() -> None:
    expected = _expected()
    # Non-KEV finding with no history: scan completion anchors a 7-day window.
    assert expected["CVE-2026-0001"]["sla_due_at"] == "2026-11-08T12:00:00+00:00"
    # KEV due date earlier than the severity window wins.
    assert expected["CVE-2026-0002"]["sla_due_at"] == "2026-11-20T00:00:00+00:00"
    # Severity window earlier than the KEV due date wins.
    assert expected["CVE-2026-0003"]["sla_due_at"] == "2026-11-08T12:00:00+00:00"
    # A persisted first sighting anchors the window, not this scan.
    assert expected["CVE-2026-0004"]["sla_due_at"] == "2026-07-01T00:00:00+00:00"
    assert expected["CVE-2026-0005"] == {
        "owner": "payments-security",
        "sla_due_at": "2026-11-15T00:00:00+00:00",
        "sla_due_at_source": "explicit",
        "workflow_status": "triaged",
    }
    assert expected["CVE-2026-0009"]["sla_due_at"] is None


_KEYS = ("owner", "sla_due_at", "sla_due_at_source", "workflow_status")


def _workflow(row: Mapping[str, object], keys: tuple[str, str, str, str] = _KEYS) -> dict[str, str | None]:
    """Normalize one export's workflow fields; empty means absent, and a source without a deadline is ignored."""
    owner, sla, source, status = (row.get(key) for key in keys)
    return {
        "owner": str(owner) if owner else None,
        "sla_due_at": str(sla) if sla else None,
        "sla_due_at_source": str(source) if sla and source else None,
        "workflow_status": str(status) if status else None,
    }


def _comparable(expected: dict[str, dict[str, str | None]]) -> dict[str, dict[str, str | None]]:
    return {cve: _workflow(row) for cve, row in expected.items()}


def _csv_rows() -> dict[str, dict[str, str | None]]:
    from agent_bom.output import to_csv

    rows = csv.DictReader(io.StringIO(to_csv(_report()).lstrip("\ufeff")))
    return {row["cve_id"]: _workflow(row) for row in rows if row.get("cve_id", "").startswith("CVE-")}


def _sarif_rows() -> dict[str, dict[str, str | None]]:
    from agent_bom.output import to_sarif

    results = to_sarif(_report())["runs"][0]["results"]
    props = [result.get("properties", {}) for result in results]
    return {row["advisory_id"]: _workflow(row) for row in props if str(row.get("advisory_id", "")).startswith("CVE-")}


def _ocsf_rows() -> dict[str, dict[str, str | None]]:
    from agent_bom.output.ocsf import findings_to_ocsf

    report = _report()
    events = findings_to_ocsf(report.findings, observed_at=report.generated_at)
    return {event["finding_info"]["cve"]["uid"]: _workflow(event["unmapped"]) for event in events if "cve" in event["finding_info"]}


def _cyclonedx_rows() -> dict[str, dict[str, str | None]]:
    from agent_bom.output import to_cyclonedx

    rows = {}
    for vuln in to_cyclonedx(_report())["vulnerabilities"]:
        props = vuln.get("properties", [])
        assert sum(p["name"] == "agent-bom:sla_due_at" for p in props) <= 1, vuln["id"]
        flat = {p["name"]: p["value"] for p in props}
        workflow = json.loads(flat.get("agent-bom:workflow", "{}"))
        # The workflow property and the flat SLA property must name the same deadline.
        assert workflow.get("sla_due_at") in (None, flat.get("agent-bom:sla_due_at")), vuln["id"]
        merged = {**workflow, "sla_due_at": flat.get("agent-bom:sla_due_at"), "sla_due_at_source": flat.get("agent-bom:sla_due_at_source")}
        rows[vuln["id"]] = _workflow(merged)
    return rows


def _spdx_rows() -> dict[str, dict[str, str | None]]:
    from agent_bom.output import to_spdx

    graph = to_spdx(_report())["@graph"]
    names = {node["spdxId"]: node.get("name") for node in graph if node.get("type") == "security_Vulnerability"}
    statements: dict[str, dict[str, str]] = {}
    for node in graph:
        if node.get("type") == "Annotation" and node.get("subject") in names:
            key, _, value = str(node.get("statement", "")).partition("=")
            statements.setdefault(names[node["subject"]], {})[key] = value
    keys = ("agent-bom:owner", "agent-bom:sla-due-at", "agent-bom:sla-due-at-source", "agent-bom:workflow-status")
    return {cve: _workflow(values, keys) for cve, values in statements.items()}


def _parquet_rows() -> dict[str, dict[str, str | None]]:
    pytest.importorskip("pyarrow")
    from agent_bom.output import to_arrow_table

    keys = ("owner", "sla_due_at", "sla_due_at_source", "lifecycle_status")
    rows = to_arrow_table(_report()).to_pylist()
    return {row["cve_id"]: _workflow(row, keys) for row in rows if str(row.get("cve_id") or "").startswith("CVE-")}


@pytest.mark.parametrize("name", ["csv", "sarif", "ocsf", "cyclonedx", "spdx", "parquet"])
def test_machine_export_workflow_fields_match_json(name: str) -> None:
    extract = {
        "csv": _csv_rows,
        "sarif": _sarif_rows,
        "ocsf": _ocsf_rows,
        "cyclonedx": _cyclonedx_rows,
        "spdx": _spdx_rows,
        "parquet": _parquet_rows,
    }[name]
    expected = _comparable(_expected())
    actual = extract()
    assert set(actual) == set(expected), name
    mismatches = {cve: (actual[cve], expected[cve]) for cve in expected if actual[cve] != expected[cve]}
    assert not mismatches, f"{name} disagrees with JSON: {mismatches}"


def test_markdown_sla_lines_match_json() -> None:
    from agent_bom.output import to_markdown

    document = to_markdown(_report())
    expected = _expected()
    sections = re.split(r"^### ", document, flags=re.MULTILINE)[1:]
    seen = set()
    for section in sections:
        cve = section.split(" ", 1)[0]
        if cve not in expected:
            continue
        seen.add(cve)
        due = re.search(r"^- \*\*SLA due\*\*: (.+)$", section, flags=re.MULTILINE)
        owner = re.search(r"^- \*\*Owner\*\*: (.+)$", section, flags=re.MULTILINE)
        status = re.search(r"^- \*\*Workflow status\*\*: (.+)$", section, flags=re.MULTILINE)
        assert (due.group(1) if due else None) == expected[cve]["sla_due_at"], cve
        assert (owner.group(1) if owner else None) == expected[cve]["owner"], cve
        assert (status.group(1) if status else None) == expected[cve]["workflow_status"], cve
    # Markdown details critical and high findings only.
    assert seen == {cve for cve, severity, *_ in _CASES if severity in (Severity.CRITICAL, Severity.HIGH)}


def test_pdf_and_html_headline_sla_match_json() -> None:
    from agent_bom.output import to_pdf

    expected = _expected()
    text = to_pdf(_report()).decode("latin-1", "replace")
    for cve, row in expected.items():
        if row["sla_due_at"]:
            assert row["sla_due_at"][:10] in text, cve


def test_policy_finding_workflow_fields_match_json_in_flat_exports_and_sarif() -> None:
    from agent_bom.output import to_arrow_table, to_csv, to_json, to_sarif

    policy = [row for row in to_json(_report())["findings"] if row.get("finding_type") == "MCP_BLOCKLIST"]
    assert len(policy) == 1
    expected = _workflow({**policy[0], "workflow_status": policy[0]["lifecycle_status"]})
    # A policy finding with no history is anchored to scan completion, like a CVE.
    assert expected == {
        "owner": "mcp-platform",
        "sla_due_at": "2026-12-01T12:00:00+00:00",
        "sla_due_at_source": "severity-kev/v1",
        "workflow_status": "open",
    }
    finding_id = policy[0]["id"]
    csv_row = next(row for row in csv.DictReader(io.StringIO(to_csv(_report()).lstrip("\ufeff"))) if row["finding_id"] == finding_id)
    sarif_props = next(
        result["properties"]
        for result in to_sarif(_report())["runs"][0]["results"]
        if result.get("properties", {}).get("occurrence_id") == finding_id
    )
    assert _workflow(csv_row) == expected
    assert _workflow(sarif_props) == expected
    pytest.importorskip("pyarrow")
    parquet_row = next(row for row in to_arrow_table(_report()).to_pylist() if row["finding_id"] == finding_id)
    assert _workflow(parquet_row, ("owner", "sla_due_at", "sla_due_at_source", "lifecycle_status")) == expected
