"""Am I affected? for an id no declaration or local feed knows, answered from stored findings.

A fresh install has no local advisory DB, yet its stored scans already carry
the findings (the demo's top attack path is CVE-2023-4863 on pillow). The
answer then comes from those findings: provenance ``scan``, never complete,
and never a ``not_affected`` verdict it cannot back with a range.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom.db import schema
from agent_bom.db.advisory_affected_local import local_affected_answer
from agent_bom.scanners.advisory_affected import STORED_FINDINGS_REASON, page_answer, stored_findings_answer


def _report(scan_id: str, server: str, packages: list[dict]) -> dict:
    return {
        "scan_id": scan_id,
        "scan_completed_at": "2026-10-25T08:00:00+00:00",
        "agents": [{"name": "etl-agent", "mcp_servers": [{"name": server, "packages": packages}]}],
    }


def _pillow(version: str, vulns: list[dict]) -> dict:
    return {"name": "pillow", "version": version, "ecosystem": "pypi", "purl": f"pkg:pypi/pillow@{version}", "vulnerabilities": vulns}


_WEBP = {
    "id": "GHSA-j7hp-h8jx-5ppr",
    "aliases": ["CVE-2023-4863"],
    "severity": "high",
    "fixed_version": "10.0.1",
    "summary": "libwebp heap overflow",
}


def _reports() -> list[dict]:
    return [
        _report("scan-etl", "etl-server", [_pillow("9.0.0", [_WEBP]), {"name": "requests", "version": "2.31.0", "ecosystem": "pypi"}]),
        _report("scan-img", "image-server", [_pillow("10.2.0", [])]),
    ]


def test_answers_from_stored_findings_by_alias_with_patch_target() -> None:
    answer = stored_findings_answer("cve-2023-4863", _reports())

    assert answer is not None
    assert answer["advisory"]["id"] == "CVE-2023-4863"
    assert answer["advisory"]["source"] == "scan"
    assert "GHSA-j7hp-h8jx-5ppr" in answer["advisory"]["aliases"]
    assert answer["advisory"]["severity"] == "high"
    assert answer["advisory"]["fixed_versions"] == ["10.0.1"]
    brief = [(r["asset_label"], r["package"]["name"], r["installed_version"], r["fixed_version"], r["verdict"]) for r in answer["rows"]]
    assert brief == [("etl-server", "pillow", "9.0.0", "10.0.1", "affected")]
    assert answer["rows"][0]["provenance"] == "scan"
    assert answer["rows"][0]["graph"]["package_node_id"]
    # Without a range record the answer cannot call pillow 10.2.0 clean.
    assert answer["summary"]["not_affected"] == 0
    assert answer["summary"]["affected"] == 1 and answer["summary"]["reports_examined"] == 2
    assert answer["complete"] is False
    assert answer["incomplete_reason"] == STORED_FINDINGS_REASON
    page = page_answer(answer, tenant_id="t1")
    assert page["warnings"] == [STORED_FINDINGS_REASON]
    assert page["incomplete_reason"] == STORED_FINDINGS_REASON


def test_answers_by_the_finding_id_itself() -> None:
    answer = stored_findings_answer("GHSA-j7hp-h8jx-5ppr", _reports())
    assert answer is not None and answer["summary"]["affected"] == 1


def test_unreferenced_id_stays_unknown() -> None:
    assert stored_findings_answer("CVE-2099-0001", _reports()) is None
    assert stored_findings_answer("CVE-2023-4863", []) is None


def test_local_cli_and_mcp_answer_uses_the_same_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(schema, "DB_PATH", tmp_path / "absent" / "vulns.db")
    monkeypatch.setattr("agent_bom.db.advisory_affected_local.local_advisory", lambda _id: None)
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps({"ai_bom_version": "1.0", **_reports()[0]}))
    answer = local_affected_answer("CVE-2023-4863", [report_path])
    assert answer is not None and answer["advisory"]["source"] == "scan"
    assert [(r["package"]["name"], r["fixed_version"]) for r in answer["rows"]] == [("pillow", "10.0.1")]
    assert local_affected_answer("CVE-2099-0001", [report_path]) is None
