"""Job summary, PR comment and annotation output of the GitHub Action."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from scripts.action_report import COMMENT_MARKER, load_rows, render_comment, render_summary
from scripts.emit_github_annotations import emit_annotations

ROOT = Path(__file__).resolve().parents[1]
STEPS = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))["runs"]["steps"]


def _sarif(tmp_path: Path, results: list[tuple[str, float, str, int, dict]]) -> Path:
    rules = [{"id": rule, "properties": {"security-severity": str(score)}} for rule, score, *_ in results]
    payload = {
        "runs": [
            {
                "tool": {"driver": {"name": "agent-bom", "rules": rules}},
                "results": [
                    {
                        "ruleId": rule,
                        "message": {"text": f"finding {rule}"},
                        "properties": props,
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}],
                    }
                    for rule, _score, uri, line, props in results
                ],
            }
        ]
    }
    path = tmp_path / "results.sarif"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _mixed(tmp_path: Path) -> Path:
    return _sarif(
        tmp_path,
        [
            ("LOW-1", 2.5, "a.tf", 1, {}),
            ("HIGH-small", 7.5, "b.tf", 2, {"risk_score": 3.0}),
            ("CRIT-1", 9.5, "c.tf", 3, {"remediation_guidance": "Set acl = private"}),
            ("HIGH-wide", 7.5, "d.tf", 4, {"risk_score": 8.0, "exposed_credentials": ["AWS_KEY"]}),
            ("MED-1", 5.5, "e.tf", 5, {}),
        ],
    )


def test_rows_rank_by_severity_then_blast_radius(tmp_path: Path) -> None:
    rows = load_rows(_mixed(tmp_path))
    assert [row["rule"] for row in rows] == ["CRIT-1", "HIGH-wide", "HIGH-small", "MED-1", "LOW-1"]
    assert rows[0]["location"] == "c.tf:3"
    assert rows[0]["fix"] == "Set acl = private"


def test_summary_lists_top_findings_with_location_rule_and_fix(tmp_path: Path) -> None:
    rows = load_rows(_mixed(tmp_path))
    summary = render_summary(rows, exit_code="1", scan_type="scan", result_file="results.sarif", limit=2)
    table = [line for line in summary.splitlines() if line.startswith("| ")]
    assert table[0] == "| Severity | Location | Rule | Finding | Fix |"
    assert table[1].startswith("| CRITICAL | c.tf:3 | CRIT-1 |") and "Set acl = private" in table[1]
    assert table[2].startswith("| HIGH | d.tf:4 | HIGH-wide |")
    assert len(table) == 3
    assert "3 more finding(s)" in summary
    assert "1 critical, 2 high, 1 medium, 1 low" in summary


def test_summary_for_a_clean_scan_says_so(tmp_path: Path) -> None:
    summary = render_summary(load_rows(_sarif(tmp_path, [])), exit_code="0", scan_type="iac", result_file="")
    assert "Clean: no findings" in summary
    assert "No findings." in summary


def test_comment_is_sorted_and_links_the_project(tmp_path: Path) -> None:
    body = render_comment(load_rows(_mixed(tmp_path)), exit_code="1")
    assert body.startswith(COMMENT_MARKER)
    assert "https://github.com/koda-ai-studio/agent-bom" in body
    assert "msaad00" not in body
    assert body.index("CRIT-1") < body.index("HIGH-wide") < body.index("LOW-1")


def test_comment_cells_cannot_break_the_table(tmp_path: Path) -> None:
    path = _sarif(tmp_path, [("R|1", 9.5, "x`y.tf", 1, {"remediation_guidance": "a\nb | <script>"})])
    body = render_comment(load_rows(path), exit_code="1")
    row = next(line for line in body.splitlines() if line.startswith("| CRITICAL"))
    assert "<script>" not in row and "\n" not in row and "R\\|1" in row


def test_report_json_findings_are_ranked_too(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_text(
        json.dumps(
            {
                "findings": [
                    {"severity": "low", "title": "minor", "asset": {"location": "a"}, "evidence": {}},
                    {
                        "severity": "critical",
                        "title": "public bucket",
                        "asset": {"location": "main.tf"},
                        "evidence": {"rule_id": "TF-SEC-002", "line_number": 3},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    rows = load_rows(path)
    assert rows[0]["rule"] == "TF-SEC-002" and rows[0]["location"] == "main.tf:3"


# ── Annotations ─────────────────────────────────────────────────────────────


def test_annotation_level_follows_severity_and_highest_come_first(tmp_path: Path) -> None:
    annotations = emit_annotations(_mixed(tmp_path), max_annotations=50)
    levels = [annotation.split(" ", 1)[0] for annotation in annotations]
    assert levels == ["::error", "::error", "::error", "::warning", "::notice"]
    assert "c.tf" in annotations[0]


def test_annotation_cap_reports_how_many_more_are_in_the_result(tmp_path: Path) -> None:
    annotations = emit_annotations(_mixed(tmp_path), max_annotations=2)
    assert len(annotations) == 3
    assert annotations[-1].startswith("::notice")
    assert "3 more finding(s)" in annotations[-1] and "results.sarif" in annotations[-1]


# ── Wiring in action.yml ────────────────────────────────────────────────────


def _step(name: str) -> dict:
    return next(step for step in STEPS if step.get("name") == name)


def test_job_summary_renders_top_findings_every_run() -> None:
    script = next(step for step in STEPS if step.get("id") == "scan")["run"]
    assert 'scripts/action_report.py" summary' in script


def test_pr_comment_defaults_to_auto_and_degrades_without_write_permission() -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    assert action["inputs"]["pr-comment"]["default"] == "auto"
    step = _step("Post PR comment with findings summary")
    assert "inputs.pr-comment != 'false'" in step["if"]
    assert 'scripts/action_report.py" comment' in step["run"]
    assert "pull-requests: write" in step["run"]
    assert "msaad00" not in step["run"]


def test_annotation_cap_is_an_input() -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    assert action["inputs"]["max-annotations"]["default"] == "50"
    assert '--max "$INPUT_MAX_ANNOTATIONS"' in _step("Emit finding annotations")["run"]
