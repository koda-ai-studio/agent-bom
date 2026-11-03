"""Documentation, example and test paths are lower-confidence context.

Findings there stay visible, carry ``path_context`` + ``downgrade_reason``, are
lowered to ``low`` and therefore never trip the default ``--fail-on-severity``
gate. ``--fail-on-severity low`` still gates them.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from rich.console import Console

from agent_bom.ast_models import FlowFinding
from agent_bom.cli.agents._context import ScanContext
from agent_bom.cli.agents._post import compute_exit_code
from agent_bom.core.path_context import classify_path_context
from agent_bom.models import AIBOMReport, Severity
from agent_bom.sast import _parse_sarif_findings
from agent_bom.scanners.secret_models import SecretFinding
from agent_bom.scanners.secret_path_context import apply_path_context
from agent_bom.secret_scanner import scan_secrets

# Assembled at runtime so no real-shaped secret is committed.
_PASSWORD = "Pr0d" + "Passw0rd" + "!x9"


@pytest.mark.parametrize(
    "path, expected",
    [
        ("docs/guide.md", "documentation"),
        ("docs/zh-CN/guide.js", "documentation"),
        ("README.md", "documentation"),
        ("README.zh-CN.md", "documentation"),
        ("packages/core/CHANGELOG.md", "documentation"),
        ("site-docs/howto.yaml", "documentation"),
        ("guide.rst", "documentation"),
        ("examples/gulpfile.js", "example"),
        ("example/server.py", "example"),
        ("samples/app/config.yaml", "example"),
        ("tests/unit/test_x.py", "test"),
        ("src/__tests__/client.js", "test"),
        ("pkg/fixtures/db.yaml", "test"),
        ("pkg/client_test.go", "test"),
        ("lib/client.spec.ts", "test"),
        ("lib/client.test.js", "test"),
        ("src/app.py", None),
        ("src/docs_builder.py", None),
        ("config/settings.yaml", None),
        ("gulpfile.js", None),
        ("", None),
    ],
)
def test_classify_path_context(path: str, expected: str | None) -> None:
    assert classify_path_context(path) == expected


def _write(root: Path, rel: str, text: str) -> None:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def test_secret_findings_in_docs_and_examples_are_labelled_and_lowered(tmp_path: Path) -> None:
    line = f'password = "{_PASSWORD}"\n'
    _write(tmp_path, "src/settings.py", line)
    _write(tmp_path, "docs/config.md", line)
    _write(tmp_path, "README.md", line)
    _write(tmp_path, "docs/ja/README.md", line)
    _write(tmp_path, "examples/app.py", line)

    result = scan_secrets(tmp_path)
    by_file = {f.file_path: f for f in result.findings}

    assert set(by_file) == {
        "src/settings.py",
        str(Path("docs/config.md")),
        "README.md",
        str(Path("docs/ja/README.md")),
        str(Path("examples/app.py")),
    }
    production = by_file["src/settings.py"]
    assert (production.severity, production.path_context, production.downgrade_reason) == ("high", None, None)
    for rel, context in [
        ("docs/config.md", "documentation"),
        ("README.md", "documentation"),
        ("docs/ja/README.md", "documentation"),
        ("examples/app.py", "example"),
    ]:
        finding = by_file[str(Path(rel))]
        assert finding.severity == "low", rel
        assert finding.path_context == context, rel
        assert finding.downgrade_reason and context in finding.downgrade_reason, rel
        row = finding.to_dict()
        assert row["path_context"] == context
        assert row["severity"] == "low"
    assert _PASSWORD not in str(result.to_dict())


def test_live_validated_credential_in_docs_keeps_its_severity() -> None:
    finding = SecretFinding(
        file_path="docs/setup.md",
        line_number=3,
        secret_type="GitHub Token",
        severity="critical",
        matched_preview="[CREDENTIAL_REDACTED]",
        category="credential",
        validation_status="valid",
    )
    [kept] = apply_path_context("docs/setup.md", [finding])
    assert kept.severity == "critical"
    assert kept.path_context == "documentation"
    assert kept.downgrade_reason is None


def test_ast_flow_in_example_is_low_and_labelled_through_the_unified_stream() -> None:
    flow = FlowFinding(
        category="tainted_command_execution",
        title="Tool input reaches shell execution",
        detail="input reaches exec",
        file_path="examples/gulpfile.js",
        line_number=4,
        entrypoint="build",
        sink="child_process.exec",
    )

    production = FlowFinding(
        category="tainted_command_execution",
        title="Tool input reaches shell execution",
        detail="input reaches exec",
        file_path="src/server.js",
        line_number=4,
        entrypoint="build",
        sink="child_process.exec",
    )
    from agent_bom.ast.flow_serialize import flow_finding_rows

    rows = flow_finding_rows([flow, production])
    assert (rows[0]["severity"], rows[0]["path_context"]) == ("low", "example")
    assert rows[1]["severity"] == "critical" and "path_context" not in rows[1]
    report = AIBOMReport(ai_inventory_data={"ast_analysis": {"flow_findings": rows}}, scan_sources=["ast_analysis"])
    by_file = {f.asset.location: f for f in report.to_findings()}
    assert by_file["examples/gulpfile.js"].severity == "low"
    assert by_file["examples/gulpfile.js"].evidence["path_context"] == "example"
    assert "example" in by_file["examples/gulpfile.js"].evidence["downgrade_reason"]
    assert by_file["src/server.js"].severity == "critical"
    assert "path_context" not in by_file["src/server.js"].evidence


def _sarif(uri: str) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "semgrep", "rules": [{"id": "js.exec", "properties": {"security-severity": "8.0"}}]}},
                "results": [
                    {
                        "ruleId": "js.exec",
                        "level": "error",
                        "message": {"text": "exec of user input"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 3}}}],
                    }
                ],
            }
        ],
    }


def test_sarif_findings_in_examples_are_low_and_labelled() -> None:
    [example], *_ = _parse_sarif_findings(_sarif("examples/gulpfile.js"))
    [production], *_ = _parse_sarif_findings(_sarif("lib/core.js"))
    assert example.severity == Severity.LOW
    assert example.path_context == "example"
    assert production.severity == Severity.HIGH
    assert production.path_context is None


def _exit_code(report: AIBOMReport, threshold: str) -> int:
    ctx = ScanContext(con=Console(), quiet=True, report=report)
    return compute_exit_code(
        ctx,
        fail_on_severity=threshold,
        warn_on_severity=None,
        fail_on_kev=False,
        fail_if_ai_risk=False,
        push_url=None,
        push_api_key=None,
        quiet=True,
    )


def _secret_report(rel: str, tmp_path: Path) -> AIBOMReport:
    _write(tmp_path, rel, f'password = "{_PASSWORD}"\n')
    return AIBOMReport(ai_inventory_data={"secrets": scan_secrets(tmp_path).to_dict()})


def test_doc_context_secret_does_not_trip_the_default_gate(tmp_path: Path) -> None:
    report = _secret_report("docs/install.md", tmp_path)
    assert [f.severity for f in report.to_findings()] == ["low"]
    assert _exit_code(report, "high") == 0
    assert _exit_code(report, "low") == 1


def test_production_secret_still_trips_the_default_gate(tmp_path: Path) -> None:
    report = _secret_report("src/settings.py", tmp_path)
    assert _exit_code(report, "high") == 1
