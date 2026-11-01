"""An unhandled exception inside a command never exits 0 from the console entry point."""

from __future__ import annotations

import click
import pytest

from agent_bom.cli._entry import make_entry_point


@click.group()
def _group() -> None:
    pass


@_group.command("boom")
def _boom() -> None:
    raise KeyError("3.2.3.post2")


def test_unhandled_exception_exits_non_zero_and_names_the_error(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["agent-bom", "boom"])
    monkeypatch.setattr("agent_bom.cli._entry._check_for_update_bg", lambda: None)
    with pytest.raises(SystemExit) as raised:
        make_entry_point(_group)()
    assert raised.value.code == 1
    err = capsys.readouterr().err
    assert "agent-bom error:" in err
    assert "3.2.3.post2" in err
