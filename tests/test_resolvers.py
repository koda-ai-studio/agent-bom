"""Tests for runtime version resolvers."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

from agent_bom.resolvers.runtime_resolver import (
    _walk_npm_tree,
    resolve_go_versions,
    resolve_npm_versions,
    resolve_pip_versions,
)

# ── Runtime Resolver Tests ────────────────────────────────────────────────────


class TestResolvePipVersions:
    """Tests for pip version resolution."""

    def test_pip_not_found(self):
        with patch("shutil.which", return_value=None):
            assert resolve_pip_versions() == {}

    def test_pip_success(self):
        mock_output = json.dumps(
            [
                {"name": "requests", "version": "2.31.0"},
                {"name": "Flask", "version": "3.0.0"},
            ]
        )
        mock_result = MagicMock(returncode=0, stdout=mock_output, stderr="")
        with patch("shutil.which", return_value="/usr/bin/pip"), patch("subprocess.run", return_value=mock_result):
            versions = resolve_pip_versions()
            assert versions == {"requests": "2.31.0", "flask": "3.0.0"}

    def test_pip_with_python_path(self):
        mock_output = json.dumps([{"name": "numpy", "version": "1.26.0"}])
        mock_result = MagicMock(returncode=0, stdout=mock_output, stderr="")
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            versions = resolve_pip_versions(python_path="/path/to/python")
            assert versions == {"numpy": "1.26.0"}
            mock_run.assert_called_once()
            assert mock_run.call_args[0][0][0] == "/path/to/python"

    def test_pip_failure(self):
        mock_result = MagicMock(returncode=1, stdout="", stderr="error")
        with patch("shutil.which", return_value="/usr/bin/pip"), patch("subprocess.run", return_value=mock_result):
            assert resolve_pip_versions() == {}

    def test_pip_timeout(self):
        with patch("shutil.which", return_value="/usr/bin/pip"), patch("subprocess.run", side_effect=subprocess.TimeoutExpired("pip", 30)):
            assert resolve_pip_versions() == {}

    def test_pip_invalid_json(self):
        mock_result = MagicMock(returncode=0, stdout="not json", stderr="")
        with patch("shutil.which", return_value="/usr/bin/pip"), patch("subprocess.run", return_value=mock_result):
            assert resolve_pip_versions() == {}


class TestResolveNpmVersions:
    """Tests for npm version resolution."""

    def test_npm_not_found(self, tmp_path):
        with patch("shutil.which", return_value=None):
            assert resolve_npm_versions(tmp_path) == {}

    def test_no_package_json(self, tmp_path):
        with patch("shutil.which", return_value="/usr/bin/npm"):
            assert resolve_npm_versions(tmp_path) == {}

    def test_npm_success(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        mock_output = json.dumps(
            {
                "dependencies": {
                    "express": {"version": "4.18.2", "dependencies": {"accepts": {"version": "1.3.8"}}},
                    "lodash": {"version": "4.17.21"},
                }
            }
        )
        mock_result = MagicMock(returncode=0, stdout=mock_output, stderr="")
        with patch("shutil.which", return_value="/usr/bin/npm"), patch("subprocess.run", return_value=mock_result):
            versions = resolve_npm_versions(tmp_path)
            assert versions == {"express": "4.18.2", "accepts": "1.3.8", "lodash": "4.17.21"}

    def test_npm_nonzero_exit_still_parses(self, tmp_path):
        """npm ls returns non-zero for missing deps but still outputs JSON."""
        (tmp_path / "package.json").write_text("{}")
        mock_output = json.dumps({"dependencies": {"pkg": {"version": "1.0.0"}}})
        mock_result = MagicMock(returncode=1, stdout=mock_output, stderr="missing deps")
        with patch("shutil.which", return_value="/usr/bin/npm"), patch("subprocess.run", return_value=mock_result):
            versions = resolve_npm_versions(tmp_path)
            assert versions == {"pkg": "1.0.0"}

    def test_npm_empty_output(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        mock_result = MagicMock(returncode=0, stdout="", stderr="")
        with patch("shutil.which", return_value="/usr/bin/npm"), patch("subprocess.run", return_value=mock_result):
            assert resolve_npm_versions(tmp_path) == {}

    def test_npm_timeout(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        with patch("shutil.which", return_value="/usr/bin/npm"), patch("subprocess.run", side_effect=subprocess.TimeoutExpired("npm", 30)):
            assert resolve_npm_versions(tmp_path) == {}


class TestResolveGoVersions:
    """Tests for Go module version resolution."""

    def test_go_not_found(self, tmp_path):
        with patch("shutil.which", return_value=None):
            assert resolve_go_versions(tmp_path) == {}

    def test_no_go_mod(self, tmp_path):
        with patch("shutil.which", return_value="/usr/bin/go"):
            assert resolve_go_versions(tmp_path) == {}

    def test_go_success(self, tmp_path):
        (tmp_path / "go.mod").write_text("module example.com/foo")
        # go list -m -json outputs concatenated JSON objects
        mock_output = '{"Path": "github.com/foo/bar", "Version": "v1.2.3"}\n{"Path": "github.com/baz/qux", "Version": "v0.5.0"}\n'
        mock_result = MagicMock(returncode=0, stdout=mock_output, stderr="")
        with patch("shutil.which", return_value="/usr/bin/go"), patch("subprocess.run", return_value=mock_result):
            versions = resolve_go_versions(tmp_path)
            assert versions == {"github.com/foo/bar": "1.2.3", "github.com/baz/qux": "0.5.0"}

    def test_go_failure(self, tmp_path):
        (tmp_path / "go.mod").write_text("module example.com/foo")
        mock_result = MagicMock(returncode=1, stdout="", stderr="error")
        with patch("shutil.which", return_value="/usr/bin/go"), patch("subprocess.run", return_value=mock_result):
            assert resolve_go_versions(tmp_path) == {}

    def test_go_timeout(self, tmp_path):
        (tmp_path / "go.mod").write_text("module example.com/foo")
        with patch("shutil.which", return_value="/usr/bin/go"), patch("subprocess.run", side_effect=subprocess.TimeoutExpired("go", 30)):
            assert resolve_go_versions(tmp_path) == {}


class TestWalkNpmTree:
    """Tests for npm dependency tree walker."""

    def test_flat_deps(self):
        deps = {"a": {"version": "1.0"}, "b": {"version": "2.0"}}
        versions: dict[str, str] = {}
        _walk_npm_tree(deps, versions)
        assert versions == {"a": "1.0", "b": "2.0"}

    def test_nested_deps(self):
        deps = {"a": {"version": "1.0", "dependencies": {"c": {"version": "3.0"}}}}
        versions: dict[str, str] = {}
        _walk_npm_tree(deps, versions)
        assert versions == {"a": "1.0", "c": "3.0"}

    def test_empty(self):
        versions: dict[str, str] = {}
        _walk_npm_tree({}, versions)
        assert versions == {}

    def test_missing_version_key(self):
        deps = {"a": {"resolved": "https://..."}}
        versions: dict[str, str] = {}
        _walk_npm_tree(deps, versions)
        assert versions == {}


# ── Drift Detector Tests ─────────────────────────────────────────────────────
