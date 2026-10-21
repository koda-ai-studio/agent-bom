"""The isolated native export must bound subprocesses and protect credentials."""

import json
import os
import sys
from pathlib import Path

import pytest

from agent_bom.cloud import native_inventory_cli as cli


def test_subprocess_returns_only_json_not_provider_stderr():
    result = cli._run_json([sys.executable, "-c", 'import sys, json; print("private", file=sys.stderr); print(json.dumps(dict(ok=True)))'])
    assert result == {"ok": True}


@pytest.mark.parametrize(
    "program",
    [
        'import sys; print("private-secret", file=sys.stderr); sys.exit(1)',
        'print("private-secret" * 10000)',
    ],
)
def test_subprocess_failure_or_overflow_never_returns_raw_output(program):
    with pytest.raises(ValueError) as error:
        cli._run_json([sys.executable, "-c", program], max_bytes=100)
    assert "private-secret" not in str(error.value)


def test_subprocess_deadline():
    with pytest.raises(ValueError, match="timed out"):
        cli._run_json([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1)


def private_file(tmp_path: Path) -> Path:
    path = tmp_path / "key.json"
    path.write_text('{"workspace": "demo", "token_id": "private"}')
    path.chmod(0o600)
    return path


def test_credential_cannot_be_overwritten_by_report(tmp_path):
    path = private_file(tmp_path)
    with pytest.raises(ValueError, match="paths"):
        cli._credential(path, path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX credential permissions")
def test_credential_requires_private_mode(tmp_path):
    path = private_file(tmp_path)
    path.chmod(0o644)
    with pytest.raises(ValueError, match="0600"):
        cli._credential(path, tmp_path / "report.json")


@pytest.mark.parametrize("status,code", [("ok", 0), ("partial", 2)])
def test_parent_invokes_named_module_and_publishes_private_hashed_report(tmp_path, monkeypatch, status, code):
    credential = private_file(tmp_path)
    output = tmp_path / "report.json"
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return {"status": status, "reconcile_absent": False}

    monkeypatch.setattr(cli, "_run_json", run)
    args = ["modal", "--account", "demo", "--credential-file", str(credential), "--output", str(output)]
    assert cli.main(args) == code
    assert calls[0][1:3] == ["-m", "agent_bom.cloud.native_inventory_cli"]
    assert calls[0][-1] == "--worker"
    report = json.loads(output.read_text())
    assert report["status"] == status and report["evidence_sha256"]
    assert not report["reconcile_absent"]
    assert "private" not in output.read_text()
    if os.name != "nt":
        assert output.stat().st_mode & 0o777 == 0o600
