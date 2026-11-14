"""`scan -f json` keeps schema 1.0 in 0.115 and announces the 0.116 default only to a person at a terminal."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent_bom.cli.agents.scan_pipeline import report_format_notice as notice


def _opts(**overrides) -> SimpleNamespace:
    values = {"output_format": "json", "output": "report.json", "quiet": False, "log_json": False, "agent_mode": False}
    return SimpleNamespace(**{**values, **overrides})


@pytest.fixture
def terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(notice, "_interactive", lambda: True)
    monkeypatch.setattr(notice, "_format_chosen", lambda: False)


def test_interactive_json_file_prints_one_stderr_line(terminal, capsys) -> None:
    notice.notice_report_schema_default(_opts())
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.count("\n") == 1
    assert "0.116" in captured.err and "--report-format v2" in captured.err


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"quiet": True}, id="quiet"),
        pytest.param({"log_json": True}, id="log-json"),
        pytest.param({"agent_mode": True}, id="agent-mode"),
        pytest.param({"output": None}, id="stdout"),
        pytest.param({"output": "-"}, id="dash-stdout"),
        pytest.param({"output": "/dev/null"}, id="null-device"),
        pytest.param({"output_format": "sarif", "output": "r.sarif"}, id="other-format"),
    ],
)
def test_no_notice_outside_an_interactive_json_file_write(terminal, capsys, overrides) -> None:
    notice.notice_report_schema_default(_opts(**overrides))
    assert capsys.readouterr().err == ""


def test_no_notice_in_ci_or_when_the_format_was_chosen(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.setattr(notice, "_format_chosen", lambda: False)
    monkeypatch.setattr(notice, "_interactive", lambda: False)
    notice.notice_report_schema_default(_opts())
    monkeypatch.setattr(notice, "_interactive", lambda: True)
    monkeypatch.setattr(notice, "_format_chosen", lambda: True)
    notice.notice_report_schema_default(_opts())
    assert capsys.readouterr().err == ""


def test_interactive_check_respects_ci(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(notice.sys.stderr, "isatty", lambda: True, raising=False)
    monkeypatch.setenv("CI", "true")
    assert notice._interactive() is False
