"""``db advisory affected`` falls back to the last scan persisted in the local control plane."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.store import SQLiteJobStore
from agent_bom.cli import main

_WEBP = {"id": "GHSA-j7hp-h8jx-5ppr", "aliases": ["CVE-2023-4863"], "severity": "high", "fixed_version": "10.0.1", "summary": "webp"}


def _report() -> dict:
    return {
        "scan_id": "persisted-scan",
        "scan_completed_at": "2026-10-25T08:00:00+00:00",
        "agents": [
            {
                "name": "etl-agent",
                "mcp_servers": [
                    {
                        "name": "etl-server",
                        "packages": [{"name": "pillow", "version": "9.0.0", "ecosystem": "pypi", "vulnerabilities": [_WEBP]}],
                    }
                ],
            }
        ],
    }


@pytest.fixture
def state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    monkeypatch.delenv("AGENT_BOM_TENANT_ID", raising=False)
    monkeypatch.setattr("agent_bom.history.HISTORY_DIR", None, raising=False)
    monkeypatch.setattr("agent_bom.db.schema.DB_PATH", tmp_path / "db" / "vulns.db")
    return tmp_path


def _persist(state: Path) -> None:
    from agent_bom.cli._tenant import resolve_cli_tenant_id

    now = datetime.now(timezone.utc).isoformat()
    SQLiteJobStore(str(state / "control-plane.db")).put(
        ScanJob(
            job_id="persisted-scan",
            tenant_id=resolve_cli_tenant_id(),
            request=ScanRequest(),
            triggered_by="quickstart",
            status=JobStatus.DONE,
            created_at=now,
            started_at=now,
            completed_at=now,
            result=_report(),
        )
    )


def test_finds_the_cve_in_the_last_persisted_scan(state: Path) -> None:
    _persist(state)

    result = CliRunner().invoke(main, ["db", "advisory", "affected", "CVE-2023-4863"])

    assert "etl-server" in result.output, result.output
    assert "pillow@9.0.0" in result.output


def test_unknown_id_explains_how_to_persist_a_scan(state: Path) -> None:
    result = CliRunner().invoke(main, ["db", "advisory", "affected", "CVE-2023-4863"])

    assert result.exit_code == 1
    assert "--save" in result.output
    assert "--report" in result.output
