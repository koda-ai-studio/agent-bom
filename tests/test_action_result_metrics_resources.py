"""Result readers close descriptors on success and malformed input."""

from __future__ import annotations

import builtins
import runpy
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    ("contents", "expected_grade"),
    [(' {"posture_grade": "C", "blast_radius": [{"severity": "critical"}]}', "C"), ("invalid JSON", "unknown")],
)
def test_action_result_metrics_closes_input(tmp_path, monkeypatch, capsys, contents, expected_grade):
    result = tmp_path / "result.json"
    result.write_text(contents, encoding="utf-8")
    monkeypatch.setenv("RESULT_FILE", str(result))
    monkeypatch.setenv("VULN_COUNT", "1")
    original_open = builtins.open
    streams = []

    def tracked_open(path, *args, **kwargs):
        stream = original_open(path, *args, **kwargs)
        if str(path) == str(result):
            streams.append(stream)
        return stream

    monkeypatch.setattr(builtins, "open", tracked_open)
    try:
        runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "action_result_metrics.py"))
        assert f"posture_grade={expected_grade}" in capsys.readouterr().out
        assert len(streams) == 1
        assert streams[0].closed
    finally:
        for stream in streams:
            stream.close()
