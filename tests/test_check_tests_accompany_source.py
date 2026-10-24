from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_tests_accompany_source.py"
spec = importlib.util.spec_from_file_location("check_tests_accompany_source", SCRIPT)
assert spec and spec.loader
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


@pytest.mark.parametrize(
    ("files", "missing"),
    [
        (["src/agent_bom/scanner.py"], ["src/agent_bom/scanner.py"]),
        (["src/agent_bom/scanner.py", "tests/test_scanner.py"], []),
        (["docs/README.md", "ui/app/page.tsx"], []),
        (["src/agent_bom/data/registry.json"], []),
        (["src/agent_bom/a.py", "src/agent_bom/b.py", "tests/fixtures/x.json"], []),
    ],
)
def test_source_without_tests(files: list[str], missing: list[str]) -> None:
    assert check.source_without_tests(files) == missing


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "README.md").write_text("x\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _commit(repo: Path, path: str) -> None:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("x = 1\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", path)


def test_main_fails_source_only_change(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    _commit(repo, "src/agent_bom/feature.py")
    assert check.main(["--base", base]) == 1
    assert "src/agent_bom/feature.py" in capsys.readouterr().out


def test_main_passes_with_a_test_and_when_waived(repo: Path) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    _commit(repo, "src/agent_bom/feature.py")
    assert check.main(["--base", base, "--waived"]) == 0
    _commit(repo, "tests/test_feature.py")
    assert check.main(["--base", base]) == 0
