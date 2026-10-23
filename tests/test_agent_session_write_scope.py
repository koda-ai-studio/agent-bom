"""Writes outside the session cwd: same-repo, temp and agent-state targets are low signal."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from agent_bom.runtime.agent_sessions.write_scope import WriteScope

GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.test",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.test",
}


def git(*args: str, cwd: Path) -> None:
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args], cwd=cwd, env=GIT_ENV, check=True, capture_output=True
    )


def make_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    git("init", "-q", cwd=path)
    (path / "README.md").write_text("x\n")
    git("add", "README.md", cwd=path)
    git("commit", "-q", "-m", "init", cwd=path)
    return path


@pytest.fixture()
def scope(tmp_path) -> WriteScope:
    home = tmp_path / "home"
    home.mkdir()
    return WriteScope(home=home, temp_roots=(str(tmp_path / "scratch"),))


def test_same_repo_worktree_is_low_signal(tmp_path, scope):
    repo = make_repo(tmp_path / "repo")
    worktree = tmp_path / "wt" / "feature"
    git("worktree", "add", "-q", "-b", "feature", str(worktree), cwd=repo)
    assert scope.classify(str(worktree / "src" / "new_file.py"), str(repo)) == ("low_signal", "same_repository")
    assert scope.classify(str(repo / "nested" / "x.py"), str(worktree)) == ("low_signal", "same_repository")


def test_write_into_a_different_repository_stays_risky(tmp_path, scope):
    repo = make_repo(tmp_path / "repo")
    other = make_repo(tmp_path / "other")
    assert scope.classify(str(other / "README.md"), str(repo)) == ("risky", "medium")


def test_temp_and_agent_state_are_low_signal(tmp_path, scope):
    repo = make_repo(tmp_path / "repo")
    assert scope.classify(str(tmp_path / "scratch" / "notes.txt"), str(repo)) == ("low_signal", "temp_dir")
    assert scope.classify(str(scope.home / ".claude" / "plans" / "p.md"), str(repo)) == ("low_signal", "agent_state")
    assert scope.classify(str(scope.home / ".codex" / "memories" / "m.md"), str(repo)) == ("low_signal", "agent_state")


@pytest.mark.parametrize("relative", [".zshrc", ".gitconfig", ".ssh/authorized_keys", ".aws/config", ".claude.json"])
def test_home_dotfiles_and_credentials_stay_high(scope, tmp_path, relative):
    assert scope.classify(str(scope.home / relative), str(tmp_path / "repo")) == ("risky", "high")


def test_system_paths_stay_high(scope, tmp_path):
    assert scope.classify("/etc/hosts", str(tmp_path)) == ("risky", "high")
    assert scope.classify("/usr/local/bin/tool", str(tmp_path)) == ("risky", "high")


def test_git_lookups_are_cached_per_directory(tmp_path, scope, monkeypatch):
    repo = make_repo(tmp_path / "repo")
    calls = []
    real = scope._git_common_dir_uncached
    monkeypatch.setattr(scope, "_git_common_dir_uncached", lambda d: calls.append(d) or real(d))
    for _ in range(5):
        scope.classify(str(repo / "a" / "b.py"), str(repo / "sub"))
    assert len(calls) <= 2
