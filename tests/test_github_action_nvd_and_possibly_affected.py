"""Action contract: the NVD key reaches the DB refresh, and possibly-affected results never count or gate."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from tests.test_github_action_args import ACTION, SCAN_STEP, _run_scan_step, action_args

ROOT = Path(__file__).resolve().parents[1]
STEPS = ACTION["runs"]["steps"]
PAGE = ROOT / "site-docs" / "integrations" / "github-action.md"


def test_nvd_api_key_input_is_optional_and_documented_as_a_secret() -> None:
    spec = ACTION["inputs"]["nvd-api-key"]
    assert "secrets.NVD_API_KEY" in spec["description"] and "${{" not in spec["description"]
    assert spec.get("default", "") == ""
    assert "secrets.NVD_API_KEY" in spec["description"]
    assert "${{" not in spec["description"]


def test_nvd_api_key_reaches_only_the_scan_step_as_an_env_var() -> None:
    carriers = [step.get("id") or step.get("name") for step in STEPS if "NVD_API_KEY" in (step.get("env") or {})]
    assert carriers == ["scan"]
    # A job-level NVD_API_KEY keeps working when the input is not set.
    assert SCAN_STEP["env"]["NVD_API_KEY"] == "${{ inputs.nvd-api-key || env.NVD_API_KEY }}"
    for step in STEPS:
        script = str(step.get("run", ""))
        assert "nvd-api-key" not in script and "NVD_API_KEY" not in script, step.get("name")
        assert "nvd-api-key" not in str(step.get("with") or {}), step.get("name")


def test_default_db_refresh_uses_the_default_sources_which_include_nvd() -> None:
    from agent_bom.db.sync import DEFAULT_SYNC_SOURCES

    args = action_args()
    assert "--auto-update-db" in args
    assert not any(arg.startswith("--db-source") for arg in args), args
    assert "nvd" in DEFAULT_SYNC_SOURCES


def _sarif(results: list[dict]) -> dict:
    rules = [
        {"id": "CVE-2026-0001", "properties": {"security-severity": "8.1"}},
        {"id": "CVE-2026-109618", "properties": {"security-severity": "9.8"}},
    ]
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "agent-bom", "rules": rules}}, "results": results}]}


_CONFIRMED = {"ruleId": "CVE-2026-0001", "level": "error", "message": {"text": "confirmed"}}
_POSSIBLY = {
    "ruleId": "CVE-2026-109618",
    "level": "note",
    "message": {"text": "php8.2-cli 8.2.29-1~deb12u1 possibly affected; verify against the distribution's advisory"},
    "properties": {"verdict": "possibly_affected", "verdict_reason": "distro_backport_unverified"},
}


def test_possibly_affected_sarif_results_are_not_counted_as_vulnerabilities(tmp_path: Path) -> None:
    outputs = _run_scan_step(tmp_path, {"severity-threshold": "high"}, _sarif([_CONFIRMED, _POSSIBLY]), 1)
    assert outputs["vuln_count"] == "1", outputs
    assert outputs["scan_status"] == "violations"
    assert outputs["sarif_file"].endswith(".sarif")


def test_only_possibly_affected_results_with_a_passing_cli_is_clean(tmp_path: Path) -> None:
    outputs = _run_scan_step(tmp_path, {"severity-threshold": "high"}, _sarif([_POSSIBLY]), 0)
    assert outputs["vuln_count"] == "0", outputs
    assert outputs["scan_status"] == "clean"
    assert outputs["posture_grade"] == "A"


def test_badge_does_not_count_possibly_affected_results(tmp_path: Path) -> None:
    import json

    _run_scan_step(tmp_path, {"badge": "badge.json"}, _sarif([_POSSIBLY]), 0)
    badge = json.loads((tmp_path / "badge.json").read_text())
    assert badge["message"] == "clean", badge


def test_action_page_documents_the_key_and_the_possibly_affected_rule() -> None:
    text = PAGE.read_text(encoding="utf-8")
    assert "nvd-api-key: ${{ secrets.NVD_API_KEY }}" in text
    section = text.split("## Possibly affected distro packages", 1)
    assert len(section) == 2
    assert re.search(r"not\s+counted", section[1].split("\n## ", 1)[0])
    blocks = [yaml.safe_load(b) for b in re.findall(r"```ya?ml\n(.*?)```", text, flags=re.S)]
    assert any("nvd-api-key" in str(block) for block in blocks)


def _report_module():
    from scripts import action_report

    return action_report


def test_summary_lists_possibly_affected_apart_from_confirmed_findings(tmp_path: Path) -> None:
    import json

    report = _report_module()
    sarif = tmp_path / "r.sarif"
    sarif.write_text(json.dumps(_sarif([_CONFIRMED, _POSSIBLY])))
    rows = report.load_rows(sarif)
    text = report.render_summary(rows, exit_code="1", scan_type="scan", result_file=str(sarif))
    assert "**Findings:** 1 (0 critical, 1 high, 0 medium, 0 low)" in text
    assert "Failed: 1 finding(s)" in text
    assert "**Possibly affected:** 1" in text and "not counted" in text
    assert "php8.2-cli 8.2.29-1~deb12u1" in text
    comment = report.render_comment(rows, exit_code="1")
    assert "**Findings:** 1 (0 critical, 1 high" in comment and "**Possibly affected:** 1" in comment


def test_summary_without_possibly_affected_is_unchanged(tmp_path: Path) -> None:
    import json

    report = _report_module()
    sarif = tmp_path / "r.sarif"
    sarif.write_text(json.dumps(_sarif([_CONFIRMED])))
    text = report.render_summary(report.load_rows(sarif), exit_code="1", scan_type="scan", result_file=str(sarif))
    assert "Possibly affected" not in text


def test_json_report_possibly_affected_rows_are_separated(tmp_path: Path) -> None:
    import json

    report = _report_module()
    path = tmp_path / "r.json"
    row = {
        "id": "CVE-2026-109618",
        "verdict": "possibly_affected",
        "reason": "distro_backport_unverified",
        "detail": "distro package php8.2-cli 8.2.29-1~deb12u1 ships php; verify against the distribution's advisory",
        "severity": "critical",
        "upstream_fixed_version": "8.2.35",
        "package": {"name": "php8.2-cli", "version": "8.2.29-1~deb12u1"},
    }
    data = {"findings": [{"severity": "high", "title": "confirmed", "vulnerability_id": "CVE-2026-0001"}], "possibly_affected": [row]}
    path.write_text(json.dumps(data))
    text = report.render_summary(report.load_rows(path), exit_code="0", scan_type="scan", result_file=str(path))
    assert "**Findings:** 1 (0 critical, 1 high" in text and "**Possibly affected:** 1" in text
    assert "`CVE-2026-109618`: distro package php8.2-cli 8.2.29-1~deb12u1 ships php" in text


def test_possibly_affected_annotation_is_a_notice_not_an_error(tmp_path: Path) -> None:
    import json

    from scripts.emit_github_annotations import emit_annotations

    located = {"locations": [{"physicalLocation": {"artifactLocation": {"uri": "Dockerfile"}, "region": {"startLine": 3}}}]}
    sarif = tmp_path / "r.sarif"
    sarif.write_text(json.dumps(_sarif([{**_CONFIRMED, **located}, {**_POSSIBLY, **located}])))
    annotations = emit_annotations(sarif, max_annotations=50)
    assert annotations[0].startswith("::error ") and "CVE-2026-0001" in annotations[0]
    assert annotations[1].startswith("::notice ") and "possibly affected" in annotations[1]
