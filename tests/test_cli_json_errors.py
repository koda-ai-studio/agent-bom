"""Under JSON logging every CLI error, usage error and progress line on stderr is one JSON object."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import click
import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "ordinary-python-app"


def _env(tmp_path: Path, **extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("AGENT_BOM_")}
    env.update(
        {
            "HOME": str(tmp_path / "home"),
            "AGENT_BOM_STATE_DIR": str(tmp_path / "state"),
            "PYTHONPATH": str(ROOT / "src"),
            "AGENT_BOM_SKIP_UPDATE_CHECK": "1",
            "NO_COLOR": "1",
        }
    )
    env.update(extra)
    return env


def _run(tmp_path: Path, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agent_bom", *args],
        cwd=tmp_path,
        env=_env(tmp_path, **env),
        capture_output=True,
        text=True,
        timeout=240,
    )


def _events(stderr: str) -> list[dict]:
    events = []
    for line in stderr.splitlines():
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pytest.fail(f"stderr line is not JSON: {line!r}\n--- stderr ---\n{stderr[-3000:]}")
    return events


def _single_error(stderr: str) -> dict:
    errors = [event for event in _events(stderr) if event["level"] == "ERROR"]
    assert len(errors) == 1, stderr
    return errors[0]


@pytest.mark.parametrize(
    ("args", "needle"),
    [
        (("scan", "--log-json", "--no-such-flag"), "No such option"),
        (("--log-json", "scan", "--format", "nonsense"), "No such option"),
        (("scan", "--log-json", "--format", "nonsense"), "nonsense"),
        (("scan", "--log-json", "--fail-on-severity"), "requires an argument"),
        (("scan", "--log-json", "--push-url", "https://example.invalid", "--offline"), "cannot be combined with --offline"),
    ],
    ids=["no-such-option", "flag-before-command", "bad-parameter", "missing-value", "usage-error"],
)
def test_usage_errors_are_one_json_error_and_keep_exit_2(tmp_path: Path, args: tuple[str, ...], needle: str) -> None:
    proc = _run(tmp_path, *args)

    assert proc.returncode == 2, proc.stderr
    assert proc.stdout == ""
    error = _single_error(proc.stderr)
    assert needle in error["msg"]
    assert error["context"]["exit_code"] == 2
    assert error["context"]["error_type"] == "usage"


def test_env_var_turns_usage_errors_into_json(tmp_path: Path) -> None:
    proc = _run(tmp_path, "scan", "--no-such-flag", AGENT_BOM_LOG_JSON="1")

    assert proc.returncode == 2
    assert "No such option" in _single_error(proc.stderr)["msg"]


def test_click_exception_is_json_with_its_exit_code(tmp_path: Path) -> None:
    proc = _run(tmp_path, "scan", "--log-json", "--repo", "file:///etc", "-f", "json", "-o", str(tmp_path / "r.json"))

    assert proc.returncode == 1, proc.stderr
    error = _single_error(proc.stderr)
    assert "scheme 'file' is not allowed" in error["msg"]
    assert error["context"]["exit_code"] == 1


def test_plain_usage_errors_are_unchanged_without_json(tmp_path: Path) -> None:
    proc = _run(tmp_path, "scan", "--no-such-flag")

    assert proc.returncode == 2
    assert "Error: No such option" in proc.stderr and "--no-such-flag" in proc.stderr
    assert not proc.stderr.lstrip().startswith("{")


def test_uncaught_exception_is_one_sanitized_json_error(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    from agent_bom.cli._entry import make_entry_point

    @click.command("boom")
    @click.option("--log-json", is_flag=True)
    def boom(log_json: bool) -> None:
        raise RuntimeError("upstream failed: token=s3cr3t-value at /srv/agent/state.db")

    monkeypatch.setattr(sys, "argv", ["agent-bom", "--log-json"])
    monkeypatch.setenv("AGENT_BOM_SKIP_UPDATE_CHECK", "1")
    with pytest.raises(SystemExit) as exc:
        make_entry_point(lambda: boom, "agent-bom")()

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    error = _single_error(captured.err)
    assert "upstream failed" in error["msg"]
    assert "s3cr3t-value" not in captured.err
    assert "/srv/agent" not in captured.err
    assert error["context"]["error_type"] == "RuntimeError"


def _python_image_tar(tmp_path: Path) -> Path:
    metadata = b"Metadata-Version: 2.1\nName: requests\nVersion: 2.19.0\n"
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w:") as tf:
        info = tarfile.TarInfo("usr/lib/python3.11/site-packages/requests-2.19.0.dist-info/METADATA")
        info.size = len(metadata)
        tf.addfile(info, io.BytesIO(metadata))
    layer_bytes = layer.getvalue()
    manifest = json.dumps([{"Config": "config.json", "RepoTags": ["jsonlog:test"], "Layers": ["l0/layer.tar"]}]).encode()
    config = json.dumps({"architecture": "amd64", "os": "linux", "history": []}).encode()
    path = tmp_path / "image.tar"
    with tarfile.open(path, mode="w:") as outer:
        for name, data in (("l0/layer.tar", layer_bytes), ("manifest.json", manifest), ("config.json", config)):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            outer.addfile(info, io.BytesIO(data))
    return path


@pytest.mark.parametrize("quiet", [False, True], ids=["progress", "quiet"])
def test_image_tar_scan_under_log_json_writes_only_json(tmp_path: Path, quiet: bool) -> None:
    tar = _python_image_tar(tmp_path)
    proc = _run(
        tmp_path,
        "image",
        "--tar",
        str(tar),
        "--log-json",
        *(["-q"] if quiet else []),
        "-f",
        "json",
        "-o",
        str(tmp_path / "r.json"),
        AGENT_BOM_OFFLINE="1",
    )

    assert proc.stdout == ""
    events = _events(proc.stderr)
    if not quiet:
        assert any(event["logger"] == "agent_bom.progress" for event in events), proc.stderr[-2000:]
    assert json.loads((tmp_path / "r.json").read_text())


@pytest.mark.parametrize("fmt", ["console", "json"])
def test_code_scan_under_log_json_writes_only_json(tmp_path: Path, fmt: str) -> None:
    out = tmp_path / "code.json"
    args = ["code", str(FIXTURE), "--log-json", "-f", fmt, *(["-o", str(out)] if fmt == "json" else [])]
    proc = _run(tmp_path, *args)

    assert proc.returncode == 0, proc.stderr
    events = _events(proc.stderr)
    assert any(event["logger"] == "agent_bom.progress" for event in events), proc.stderr[-2000:]
    if fmt == "json":
        assert proc.stdout == ""
        assert json.loads(out.read_text())


def test_fs_scan_under_log_json_writes_only_json(tmp_path: Path) -> None:
    proc = _run(tmp_path, "fs", str(FIXTURE), "--log-json", "-f", "json", "-o", str(tmp_path / "r.json"), AGENT_BOM_OFFLINE="1")

    assert proc.stdout == ""
    assert any(event["logger"] == "agent_bom.progress" for event in _events(proc.stderr)), proc.stderr[-2000:]
