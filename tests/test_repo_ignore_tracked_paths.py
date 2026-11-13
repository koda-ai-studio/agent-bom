"""Tracked-path discovery for a scan root inside a larger Git checkout."""

from __future__ import annotations

import subprocess
from pathlib import Path

from agent_bom.scanners import repo_ignore
from agent_bom.scanners.repo_ignore import RepositoryIgnore, _git_tracked_paths


def _repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for relative in ("sub/a.py", "sub/pkg/b.env", "other/c.py", "top.txt"):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    return tmp_path


def test_subdirectory_root_sees_only_its_tracked_files(tmp_path: Path) -> None:
    root = _repo(tmp_path) / "sub"

    files, dirs, fail_closed = _git_tracked_paths(root.resolve())

    assert files == frozenset({"a.py", "pkg/b.env"})
    assert dirs == frozenset({"pkg"})
    assert fail_closed is False


def test_tracked_file_under_a_subdirectory_root_is_not_gitignored(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "sub" / ".gitignore").write_text("*.env\n")
    (repo / "sub" / "pkg" / "untracked.env").write_text("x\n")

    ignore = RepositoryIgnore.for_root(repo / "sub")
    ignore.enter_directory("pkg")

    assert ignore.is_ignored_file("pkg/b.env") is False
    assert ignore.is_ignored_file("pkg/untracked.env") is True


def test_tracked_listing_is_scoped_to_the_scan_root(tmp_path: Path, monkeypatch) -> None:
    root = (_repo(tmp_path) / "sub").resolve()
    calls: list[list[str]] = []
    real_run = subprocess.run

    def recording_run(command, *args, **kwargs):
        calls.append(list(command))
        return real_run(command, *args, **kwargs)

    monkeypatch.setattr(repo_ignore.subprocess, "run", recording_run)
    _git_tracked_paths(root)

    listing = [command for command in calls if "ls-files" in command]
    assert listing == [["git", "-C", str(root), "ls-files", "-z", "--cached"]]
