"""Regression contracts for untrusted repository inputs."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from agent_bom import repo_scan
from agent_bom.scanners.state import consume_coverage_warnings, reset_scan_warnings
from agent_bom.secret_scanner import scan_secrets
from agent_bom.traversal import is_nested_worktree_root, iter_discovery_files


@pytest.mark.parametrize("target_kind", ["outside", "inside", "dangling"])
def test_file_symlinks_are_excluded_with_coverage(tmp_path, target_kind):
    root = tmp_path / "root"
    root.mkdir()
    target = (root if target_kind == "inside" else tmp_path) / "target.txt"
    if target_kind != "dangling":
        target.write_text("harmless fixture")
    link = root / "linked.py"
    link.symlink_to(target)
    reset_scan_warnings()
    try:
        assert link not in list(iter_discovery_files(root))
        gaps = consume_coverage_warnings()
        assert any(w["reason"] == "file_symlink" and w["kind"] == "coverage_gap" for w in gaps)
    finally:
        reset_scan_warnings()
    result = scan_secrets(root)
    assert result.warnings
    assert result.files_scanned == (1 if target_kind == "inside" else 0)
    assert result.pruned_directories == 0


def test_directory_symlink_not_probed_for_worktree_metadata(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / ".git").write_text("gitdir: /elsewhere/.git/worktrees/private")
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    real_read = Path.read_text

    def guarded_read(path, *args, **kwargs):
        assert path.resolve() != outside / ".git", "read metadata outside scan root"
        return real_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read)
    assert list(iter_discovery_files(root)) == []


def test_worktree_pointer_symlink_is_not_read(tmp_path):
    outside = tmp_path / "pointer"
    outside.write_text("gitdir: /elsewhere/.git/worktrees/private")
    root = tmp_path / "root"
    root.mkdir()
    (root / ".git").symlink_to(outside)
    assert not is_nested_worktree_root(root)


def test_git_object_storage_counts_toward_clone_budget(tmp_path, monkeypatch):
    objects = tmp_path / ".git" / "objects"
    objects.mkdir(parents=True)
    (objects / "pack").write_bytes(b"x" * 101)
    monkeypatch.setattr(repo_scan, "REPO_SCAN_MAX_SIZE_BYTES", 100)
    with pytest.raises(repo_scan.RepoScanError, match="size cap"):
        repo_scan._directory_within_bounds(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX process group fixture")
def test_clone_budget_aborts_live_download_and_descendant(tmp_path, monkeypatch):
    launcher = tmp_path / "git"
    receipt = tmp_path / "descendant.pid"
    completed = tmp_path / "completed"
    launcher.write_text(
        f"#!{sys.executable}\n"
        "import subprocess, sys, time\nfrom pathlib import Path\n"
        f'child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])\n'
        f"Path({str(receipt)!r}).write_text(str(child.pid))\n"
        'root = Path(sys.argv[-1]); objects = root / ".git" / "objects"\n'
        'objects.mkdir(parents=True)\n(objects / "pack").write_bytes(b"x" * 4096)\n'
        "time.sleep(30)\n"
        f'Path({str(completed)!r}).write_text("clone finished")\n'
    )
    launcher.chmod(0o700)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    monkeypatch.setattr(repo_scan, "validate_repo_url", lambda url: url)
    monkeypatch.setattr(repo_scan, "REPO_SCAN_MAX_SIZE_BYTES", 1024)
    monkeypatch.setattr(repo_scan, "REPO_SCAN_CLONE_TIMEOUT_SECONDS", 10)
    try:
        with pytest.raises(repo_scan.RepoScanError, match="size cap"):
            repo_scan._clone_into_tempdir("https://example.test/repo")
        assert not completed.exists()
        import psutil

        pid = int(receipt.read_text())
        assert not psutil.pid_exists(pid) or psutil.Process(pid).status() == psutil.STATUS_ZOMBIE
    finally:
        if receipt.exists():
            import signal

            try:
                os.kill(int(receipt.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_symlinked_ignore_file_cannot_hide_source(tmp_path):
    from agent_bom.scanners.repo_ignore import RepositoryIgnore

    outside = tmp_path / "outside-ignore"
    outside.write_text("*.py\n")
    root = tmp_path / "root"
    root.mkdir()
    (root / ".gitignore").symlink_to(outside)
    source = root / "app.py"
    source.write_text('print("fixture")')
    assert source in list(iter_discovery_files(root, ignore=RepositoryIgnore.for_root(root)))


@pytest.mark.parametrize("failure", ["count", "timeout"])
def test_live_clone_failure_stops_and_cleans(tmp_path, monkeypatch, failure):
    from agent_bom.scanners.repo_clone import run_bounded_clone

    marker = tmp_path / "finished"
    cmd = [sys.executable, "-c", f"import time; from pathlib import Path; time.sleep(3); Path({str(marker)!r}).touch()"]
    checks = []

    def check():
        checks.append(True)
        if failure == "count":
            raise repo_scan.RepoScanError("file-count cap")

    error = repo_scan.RepoScanError if failure == "count" else subprocess.TimeoutExpired
    with pytest.raises(error):
        run_bounded_clone(cmd, env=dict(os.environ), timeout=0.1, check_bounds=check)
    assert checks and not marker.exists()


def test_clone_error_output_is_retained_and_bounded():
    from agent_bom.scanners.repo_clone import run_bounded_clone

    result = run_bounded_clone(
        [sys.executable, "-c", 'import sys; sys.stderr.write("x" * 100000); sys.exit(2)'],
        env=dict(os.environ),
        timeout=5,
        check_bounds=lambda: None,
    )
    assert result.returncode == 2
    assert result.stderr == "x" * 4096


@pytest.mark.parametrize("directory", [False, True])
def test_clone_refuses_symlinks_before_any_scan(tmp_path, directory):
    outside = tmp_path / "outside"
    if directory:
        outside.mkdir()
    else:
        outside.write_text("harmless fixture")
    root = tmp_path / "root"
    root.mkdir()
    (root / "linked").symlink_to(outside, target_is_directory=directory)
    with pytest.raises(repo_scan.RepoScanError, match="symlink"):
        repo_scan._directory_within_bounds(root)
    assert outside.exists()
