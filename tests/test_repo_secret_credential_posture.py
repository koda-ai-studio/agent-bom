"""A repository secret must be named (file, never value) and reach the credential dimension."""

from __future__ import annotations

from pathlib import Path

import pytest

_SECRET_BLOCK = {
    "findings": [
        {
            "file": "settings.py",
            "line": 1,
            "type": "Hardcoded password",
            "severity": "high",
            "preview": "[SECRET_REDACTED]",
            "category": "secret",
        },
        {"file": "notes.txt", "line": 4, "type": "Email address", "severity": "low", "preview": "[REDACTED]", "category": "pii"},
    ],
    "total": 2,
    "by_category": {"secret": 1, "pii": 1},
}


def test_secret_warning_names_the_file_not_the_value() -> None:
    from agent_bom.api.repo_tree_scan import secret_scan_warning

    warning = secret_scan_warning(_SECRET_BLOCK, location="repository")
    assert "settings.py:1" in warning
    assert "REDACTED" not in warning


def test_credential_dimension_counts_repository_secrets() -> None:
    from agent_bom.evidence.posture_inputs import _credential_dimension, posture_inputs_from_report
    from agent_bom.models import AIBOMReport

    report = AIBOMReport([], [])
    report.ai_inventory_data = {"secrets": _SECRET_BLOCK}
    inputs = posture_inputs_from_report(report)
    assert inputs.repository_secret_locations == ["settings.py:1"]
    dim = _credential_dimension(inputs, 0.2)
    assert dim.score < 100
    assert "No credential exposure" not in dim.details
    assert "settings.py" in dim.details


def test_credential_dimension_stays_clean_without_secrets() -> None:
    from agent_bom.evidence.posture_inputs import _credential_dimension, posture_inputs_from_report
    from agent_bom.models import AIBOMReport

    dim = _credential_dimension(posture_inputs_from_report(AIBOMReport([], [])), 0.2)
    assert dim.score == 100
    assert dim.details == "No credential exposure detected"


@pytest.mark.asyncio
async def test_mcp_pipeline_keeps_the_repository_secret_inventory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.mcp_server_scan import consume_repo_tree_inventory, run_scan_pipeline

    async def _no_vulns(agents, **_kwargs):
        return []

    monkeypatch.setattr("agent_bom.scanners.scan_agents", _no_vulns)
    # Assembled at runtime so no secret-shaped literal is committed.
    (tmp_path / "settings.py").write_text('DB_PASSWORD = "' + "Zq" + "x7Lm9" + "Pw4rT2vK8n" + '"\n')
    (tmp_path / "requirements.txt").write_text("requests==2.19.1\n")
    _agents, _b, warnings, _s = await run_scan_pipeline(
        safe_path=lambda v: Path(v), config_path=str(tmp_path), no_discover=True, offline=True
    )
    inventory = consume_repo_tree_inventory()
    assert inventory is not None
    assert [f["file"] for f in inventory["secrets"]["findings"]] == ["settings.py"]
    assert any("settings.py:1" in w for w in warnings)
    assert consume_repo_tree_inventory() is None
