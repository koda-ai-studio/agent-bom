"""Scanning source must not let Python print private paths or source literals."""

import subprocess
import sys
import textwrap
import warnings

import pytest

from agent_bom.ai_components.framework_agents import _scan_python_file
from agent_bom.ast.application_entrypoints import _python_entries
from agent_bom.parsers.skill_audit_behavior import _scan_python_ast_risks
from agent_bom.python_agents import _extract_agent_defs


def _assert_source_syntax_warning_does_not_escape_scanner(scanner, tmp_path):
    source = 'token = "synthetic-secret\\q"\n'
    path = tmp_path / "private-agent.py"
    path.write_text(source)
    with warnings.catch_warnings(record=True) as observed:
        warnings.simplefilter("always")
        if scanner == "agents":
            _extract_agent_defs(source, str(path))
        elif scanner == "frameworks":
            _scan_python_file(path, tmp_path)
        elif scanner == "entrypoints":
            _python_entries(tmp_path, path, source)
        else:
            _scan_python_ast_risks({"SKILL.md": f"```python\n{source}```"})
    assert not observed


def _assert_concurrent_source_parses(monkeypatch, warning_category):
    import ast
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from types import SimpleNamespace

    from agent_bom.ast import source_reader
    from agent_bom.ast.source_reader import parse_python_source

    first_entered, second_called, second_entered, first_done = (Event() for _ in range(4))

    def parser(source, **kwargs):
        if source == "first":
            first_entered.set()
            assert second_called.wait(3)
            # A serialized parser keeps the second call outside its warning
            # context until the first call returns; concurrent parsing enters.
            second_entered.wait(0.2)
        else:
            second_entered.set()
            assert first_done.wait(3)
            warnings.warn("synthetic private source", warning_category)
        return ast.Module(body=[], type_ignores=[])

    def first():
        try:
            return parse_python_source("first")
        finally:
            first_done.set()

    def second():
        assert first_entered.wait(3)
        second_called.set()
        return parse_python_source("second")

    monkeypatch.setattr(source_reader, "ast", SimpleNamespace(parse=parser))
    with warnings.catch_warnings(record=True) as observed:
        warnings.simplefilter("always")
        with ThreadPoolExecutor(max_workers=2) as workers:
            a, b = workers.submit(first), workers.submit(second)
            a.result(timeout=5)
            b.result(timeout=5)
    assert not observed


def _run_warning_probe(*arguments: str) -> None:
    # Python <=3.13 warning capture is process-global. Background scan workers
    # must not contribute unrelated warnings to these source-redaction checks.
    script = textwrap.dedent("""\
        import sys
        from pathlib import Path
        import pytest
        from tests.test_source_warning_redaction import (
            _assert_source_syntax_warning_does_not_escape_scanner,
            _assert_concurrent_source_parses,
        )
        if sys.argv[1] == "scanner":
            _assert_source_syntax_warning_does_not_escape_scanner(sys.argv[2], Path(sys.argv[3]))
        else:
            category = {"SyntaxWarning": SyntaxWarning, "DeprecationWarning": DeprecationWarning}[sys.argv[2]]
            with pytest.MonkeyPatch.context() as patch:
                _assert_concurrent_source_parses(patch, category)
    """)
    result = subprocess.run([sys.executable, "-c", script, *arguments], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("scanner", ["agents", "frameworks", "entrypoints", "skills"])
def test_source_syntax_warning_does_not_escape_scanner(scanner, tmp_path):
    _run_warning_probe("scanner", scanner, str(tmp_path))


@pytest.mark.parametrize("warning_category", [SyntaxWarning, DeprecationWarning])
def test_concurrent_source_parses_do_not_restore_warning_output_mid_parse(warning_category):
    _run_warning_probe("concurrent", warning_category.__name__)
