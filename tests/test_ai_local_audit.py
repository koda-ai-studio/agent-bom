"""The CLI's durable AI record: the same fields as the API, hash-chained in the format `runtime audit --verify-chain` reads."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from agent_bom.ai_components import local_audit
from agent_bom.ai_components.call_audit import AICallRecord
from agent_bom.audit_integrity import verify_audit_jsonl_chain


def _record(**overrides: object) -> AICallRecord:
    values: dict = {
        "task": "triage",
        "provider": "ollama",
        "model": "ollama/qwen2.5:3b",
        "tenant_id": "local",
        "actor": "cli",
        "model_digest": "357c53fb",
        "prompt_sha256": "a" * 64,
        "response_sha256": "b" * 64,
        "prompt_tokens": 5,
        "completion_tokens": 3,
        "latency_ms": 12.5,
        "outcome": "ok",
        "guard_rejected": True,
        "guard_reason": "hard_rule",
    }
    values.update(overrides)
    return AICallRecord(**values)


@pytest.fixture()
def log_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.delenv("AGENT_BOM_AUDIT_HMAC_KEY", raising=False)
    return local_audit.local_ai_audit_path()


def test_records_every_field_the_api_records_and_verify_chain_accepts_them(log_path: Path) -> None:
    local_audit.append_local_ai_call(_record())
    local_audit.append_local_ai_call(_record(outcome="failed"))
    lines = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert len(lines) == 2
    first = lines[0]
    for field in _record().to_details():
        assert f"ai_{field}" in first, field
    assert first["ai_prompt_sha256"] == "a" * 64 and first["ai_guard_rejected"] is True
    assert lines[1]["prev_hash"] == first["record_hash"]
    result = verify_audit_jsonl_chain(log_path)
    assert result["verified"] == 2 and result["tampered"] == 0


def test_the_chain_continues_across_separate_processes(log_path: Path) -> None:
    code = (
        "from agent_bom.ai_components.local_audit import append_local_ai_call as a; "
        "from agent_bom.ai_components.call_audit import AICallRecord as R; "
        "a(R(task='triage', provider='ollama', model='m', outcome='ok'))"
    )
    env = {"AGENT_BOM_STATE_DIR": str(log_path.parents[1]), "PYTHONPATH": "src", "PATH": "/usr/bin:/bin"}
    for _ in range(2):
        subprocess.run([sys.executable, "-c", code], check=True, env=env, cwd=Path(__file__).resolve().parents[1])
    local_audit.append_local_ai_call(_record())
    result = verify_audit_jsonl_chain(log_path)
    assert result["verified"] == 3 and result["tampered"] == 0


def test_an_edited_record_is_detected(log_path: Path) -> None:
    local_audit.append_local_ai_call(_record())
    local_audit.append_local_ai_call(_record())
    lines = log_path.read_text().splitlines()
    log_path.write_text("\n".join([lines[0].replace('"ok"', '"failed"'), lines[1]]) + "\n")
    assert verify_audit_jsonl_chain(log_path)["tampered"] >= 1


def test_a_removed_record_is_detected(log_path: Path) -> None:
    for _ in range(3):
        local_audit.append_local_ai_call(_record())
    lines = log_path.read_text().splitlines()
    log_path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert verify_audit_jsonl_chain(log_path)["tampered"] >= 1


def test_only_hashes_reach_the_file(log_path: Path) -> None:
    planted = "ghp_" + "L" * 36
    local_audit.append_local_ai_call(_record(guard_reason=planted, model=f"m {planted}"))
    assert planted not in log_path.read_text()
    assert log_path.stat().st_mode & 0o077 == 0


def test_opt_out_writes_nothing(log_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_AI_LOCAL_AUDIT", "0")
    assert local_audit.ensure_local_ai_audit() is False
    assert not log_path.exists()


def test_an_unwritable_log_warns_and_never_raises(
    log_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def boom(*_args: object, **_kwargs: object) -> None:
        raise OSError("read-only file system")

    monkeypatch.setattr(local_audit, "_append", boom)
    local_audit.local_ai_call_sink(_record())
    assert "local AI audit" in caplog.text


def test_the_cli_scan_registers_the_log_only_when_ai_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import patch

    from agent_bom.cli.agents.scan_pipeline import policy

    class _Opts:
        ai_enrich = True
        ai_model = "ollama/m"
        ai_deterministic = True
        ai_gate_findings = False

    class _Ctx:
        _skill_result_obj = None
        _skill_audit_obj = None

    class _State:
        ctx = _Ctx()
        report = object()

    with patch("agent_bom.ai_enrich.run_ai_enrichment_sync"), patch.object(local_audit, "ensure_local_ai_audit") as ensure:
        policy._run_ai_enrichment(_Opts(), _State())
    ensure.assert_called_once()
