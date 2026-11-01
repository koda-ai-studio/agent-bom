"""Absolute-path launchers in MCP configs: allowed when the file checks out, rejected otherwise.

Claude Desktop-style configs name ``/Users/me/.venv/bin/python``. An exact
allowlist match skipped every such server from the live audit. The launcher
check is hygiene, not a sandbox, so an absolute path is accepted only when the
basename is a known launcher and the file is a real, executable, non
world-writable file in a non world-writable directory.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from agent_bom.core.security_validation import SecurityError, require_recognized_launcher


def _launcher(directory: Path, name: str = "python3", mode: int = 0o755) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(mode)
    return path


def test_bare_names_keep_working():
    require_recognized_launcher("npx")
    require_recognized_launcher("python3")
    with pytest.raises(SecurityError):
        require_recognized_launcher("bash")


def test_absolute_path_to_known_launcher_is_accepted(tmp_path):
    require_recognized_launcher(str(_launcher(tmp_path / "venv" / "bin")))


def test_absolute_path_with_unknown_basename_is_rejected(tmp_path):
    with pytest.raises(SecurityError, match="not a recognized MCP launcher"):
        require_recognized_launcher(str(_launcher(tmp_path / "bin", name="evil")))


def test_missing_file_is_rejected(tmp_path):
    with pytest.raises(SecurityError, match="does not exist"):
        require_recognized_launcher(str(tmp_path / "bin" / "python3"))


def test_directory_named_like_a_launcher_is_rejected(tmp_path):
    (tmp_path / "python3").mkdir()
    with pytest.raises(SecurityError, match="regular file"):
        require_recognized_launcher(str(tmp_path / "python3"))


def test_non_executable_file_is_rejected(tmp_path):
    with pytest.raises(SecurityError, match="executable"):
        require_recognized_launcher(str(_launcher(tmp_path / "bin", mode=0o644)))


def test_world_writable_launcher_is_rejected(tmp_path):
    with pytest.raises(SecurityError, match="world-writable"):
        require_recognized_launcher(str(_launcher(tmp_path / "bin", mode=0o777)))


def test_launcher_in_world_writable_directory_is_rejected(tmp_path):
    path = _launcher(tmp_path / "bin")
    path.parent.chmod(0o777)
    try:
        with pytest.raises(SecurityError, match="world-writable"):
            require_recognized_launcher(str(path))
    finally:
        path.parent.chmod(0o755)


def test_launcher_in_sticky_world_writable_directory_is_still_rejected(tmp_path):
    path = _launcher(tmp_path / "shared")
    path.parent.chmod(0o1777)
    try:
        with pytest.raises(SecurityError, match="world-writable"):
            require_recognized_launcher(str(path))
    finally:
        path.parent.chmod(0o755)


@pytest.mark.parametrize("command", ["../bin/python3", "bin/python3", "./python3", "~/venv/bin/python3", "/usr/bin/../bin/python3"])
def test_relative_or_unnormalised_paths_are_rejected(command):
    with pytest.raises(SecurityError):
        require_recognized_launcher(command)


def test_symlink_to_versioned_interpreter_is_accepted(tmp_path):
    target = _launcher(tmp_path / "pythons" / "bin", name="python3.13")
    link = tmp_path / "venv" / "bin" / "python"
    link.parent.mkdir(parents=True)
    link.symlink_to(target)
    require_recognized_launcher(str(link))


def test_symlink_whose_target_is_world_writable_is_rejected(tmp_path):
    target = _launcher(tmp_path / "pythons" / "bin", name="python3", mode=0o777)
    link = tmp_path / "venv" / "bin" / "python"
    link.parent.mkdir(parents=True)
    link.symlink_to(target)
    with pytest.raises(SecurityError, match="world-writable"):
        require_recognized_launcher(str(link))


def test_symlink_to_non_launcher_binary_is_rejected(tmp_path):
    target = _launcher(tmp_path / "bin", name="bash")
    link = tmp_path / "venv" / "bin" / "python3"
    link.parent.mkdir(parents=True)
    link.symlink_to(target)
    with pytest.raises(SecurityError, match="resolves to"):
        require_recognized_launcher(str(link))


def test_symlink_to_launcher_cli_script_is_accepted(tmp_path):
    """Package-manager shims (``npx`` -> ``npx-cli.js``) are how npm installs launchers."""
    target = _launcher(tmp_path / "lib" / "node_modules" / "npm" / "bin", name="npx-cli.js")
    link = tmp_path / "bin" / "npx"
    link.parent.mkdir(parents=True)
    link.symlink_to(target)
    require_recognized_launcher(str(link))


def test_blocked_server_records_a_coverage_warning(tmp_path, monkeypatch):
    from agent_bom.discovery.config_parsers import parse_mcp_config
    from agent_bom.scanners.state import consume_coverage_warnings, reset_scan_warnings

    reset_scan_warnings()
    consume_coverage_warnings()
    config = tmp_path / "mcp.json"
    config.write_text('{"mcpServers": {"venv-server": {"command": "/nonexistent/venv/bin/python", "args": ["-m", "server"]}}}')
    servers = parse_mcp_config(json.loads(config.read_text()), str(config))
    assert servers and servers[0].security_blocked
    warnings = consume_coverage_warnings()
    assert any(row.get("reason") == "launcher_rejected" and "venv-server" in str(row.get("detail")) for row in warnings), warnings


def test_rejection_reason_is_sanitised_and_names_the_check(tmp_path):
    with pytest.raises(SecurityError) as excinfo:
        require_recognized_launcher(str(_launcher(tmp_path / "bin", mode=0o777)))
    assert "not a sandbox" in str(excinfo.value)
    assert stat.S_ISREG(os.stat(tmp_path / "bin" / "python3").st_mode)
