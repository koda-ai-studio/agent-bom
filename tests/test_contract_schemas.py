from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import jsonschema

from agent_bom.cli._agent_mode import error_envelope, success_envelope
from agent_bom.models import Agent, AgentStatus, AgentType, AIBOMReport
from agent_bom.output import to_json

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts" / "v1"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_contract_schemas_are_valid_draft_2020_12() -> None:
    schemas = sorted(CONTRACTS.glob("*.schema.json"))
    assert schemas, "expected versioned contract schemas"
    for schema_path in schemas:
        schema = _load(schema_path)
        jsonschema.Draft202012Validator.check_schema(schema)
        assert schema["$id"].endswith(f"/{schema_path.name}")


def test_contract_examples_match_their_schema() -> None:
    examples = sorted((CONTRACTS / "examples").glob("*.minimal.json"))
    assert examples, "expected contract example fixtures"
    for example_path in examples:
        schema_path = CONTRACTS / example_path.name.replace(".minimal.json", ".schema.json")
        assert schema_path.exists(), f"missing schema for {example_path.name}"
        jsonschema.validate(_load(example_path), _load(schema_path))


def test_scan_report_serializer_matches_contract_schema() -> None:
    """Guard the public scan-report contract boundary.

    The Python/UI model uses ``agent_type``. The v1 scan report keeps ``type``
    as a compatibility alias so old and new consumers can validate safely.
    """
    report = AIBOMReport(
        agents=[
            Agent(
                name="demo-agent",
                agent_type=AgentType.CLAUDE_DESKTOP,
                config_path="/tmp/claude.json",
                status=AgentStatus.CONFIGURED,
            )
        ],
        generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        scan_id="scan-contract-001",
        tool_version="0.81.3",
    )

    payload = to_json(report)
    jsonschema.validate(payload, _load(CONTRACTS / "scan-report.schema.json"))

    agent_payload = payload["agents"][0]
    assert agent_payload["agent_type"] == "claude-desktop"
    assert agent_payload["type"] == "claude-desktop"


def test_agent_mode_envelopes_match_contract_schema() -> None:
    schema = _load(CONTRACTS / "agent-mode-envelope.schema.json")
    report = _load(CONTRACTS / "examples" / "scan-report.minimal.json")

    jsonschema.validate(
        success_envelope(command="agents", report_json=report, exit_code=0),
        schema,
    )
    jsonschema.validate(
        error_envelope(command="agents", message="invalid command", exit_code=2, error_type="usage"),
        schema,
    )


def test_scan_report_helper_findings_match_contract_schema() -> None:
    """Prompt and browser helper findings must stay inside the v1 finding contract."""
    report = AIBOMReport(
        generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        scan_id="scan-contract-helper-findings",
        tool_version="0.81.3",
        prompt_scan_data={
            "files_scanned": 1,
            "prompt_files": ["system.prompt"],
            "findings": [
                {
                    "source_file": "system.prompt",
                    "line_number": 1,
                    "title": "Prompt injection pattern",
                    "category": "prompt_injection",
                    "severity": "high",
                    "detail": "Prompt contains override language.",
                    "matched_text": "ignore previous instructions",
                    "recommendation": "Remove override instructions from the prompt.",
                }
            ],
            "passed": False,
        },
        browser_extensions={
            "extensions": [
                {
                    "id": "risk-ext",
                    "name": "Risk Extension",
                    "version": "1.0.0",
                    "browser": "chrome",
                    "permissions": ["debugger"],
                    "host_permissions": ["<all_urls>"],
                    "risk_level": "critical",
                    "risk_reasons": ["Critical permission: debugger"],
                    "path": "/tmp/risk-ext",
                }
            ],
            "total": 1,
            "critical_count": 1,
            "high_count": 0,
        },
    )

    payload = to_json(report)
    jsonschema.validate(payload, _load(CONTRACTS / "scan-report.schema.json"))

    helper_sources = {"PROMPT_SCAN", "BROWSER_EXT"}
    helper_findings = [finding for finding in payload["findings"] if finding.get("source") in helper_sources]
    assert {finding["source"] for finding in helper_findings} == helper_sources
    assert all(finding["schema_version"] == "1" for finding in helper_findings)


def test_scan_report_contract_anchors_unified_finding_identity() -> None:
    schema = _load(CONTRACTS / "scan-report.schema.json")
    finding_schema = schema["properties"]["findings"]["items"]

    assert {
        "schema_version",
        "id",
        "canonical_id",
        "finding_type",
        "source",
        "asset",
        "severity",
        "title",
    } <= set(finding_schema["required"])
    assert {
        "id",
        "canonical_id",
        "finding_type",
        "source",
        "asset",
        "severity",
        "title",
        "evidence",
    } <= set(finding_schema["properties"])


def test_scan_report_contract_accepts_agent_type_without_legacy_type() -> None:
    payload = _load(CONTRACTS / "examples" / "scan-report.minimal.json")
    payload["agents"][0].pop("type")

    jsonschema.validate(payload, _load(CONTRACTS / "scan-report.schema.json"))


def test_demo_scan_report_matches_contract_schema(tmp_path) -> None:
    """A real report with blast-radius rows and coverage warnings validates.

    The serializer test above builds an empty report, so ``blast_radius``
    (schema ``"2"`` since 0.111.0) and scan-wide ``coverage_warnings`` rows
    (``kind`` instead of ``ecosystem``/``reason``/``detail``) never reached
    the contract. The bundled demo exercises both.
    """
    from click.testing import CliRunner

    from agent_bom.cli import main

    out = tmp_path / "demo.json"
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--demo", "--offline", "-f", "json", "-o", str(out), "--quiet"])
    assert out.exists(), result.output
    report = _load(out)
    assert report["blast_radius"], "demo report should carry blast-radius rows"
    assert all(row["schema_version"] == "2" for row in report["blast_radius"])
    jsonschema.validate(report, _load(CONTRACTS / "scan-report.schema.json"))
    schema = _load(CONTRACTS / "scan-report.schema.json")
    scan_wide = {
        "release": "remote:osv",
        "kind": "remote_lookup_error",
        "ecosystems": ["npm", "pypi"],
        "package_count": 3,
        "reasons": ["unavailable"],
    }
    jsonschema.validate({**report, "coverage_warnings": [scan_wide]}, schema)
