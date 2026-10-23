"""Source-built language runtimes on hosts and VM snapshots, read without executing them."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from agent_bom.filesystem import scan_disk_path_native
from agent_bom.models import Package
from agent_bom.parsers import host_runtimes
from agent_bom.parsers.host_runtimes import detect_host_runtimes


def _write(root: Path, rel: str, content: str | bytes) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode() if isinstance(content, str) else content)
    return path


def _php_binary(version: str, padding: int = 4096) -> bytes:
    return b"\x7fELF\x02\x01\x01" + b"\x00" * padding + b"X-Powered-By: PHP/" + version.encode() + b"\x00PHP_VERSION\x00"


def _runtimes(packages: list[Package]) -> dict[str, Package]:
    return {pkg.name: pkg for pkg in packages if pkg.ecosystem == "generic" and pkg.cpe}


def test_host_php_from_binary_header(tmp_path: Path) -> None:
    _write(tmp_path, "usr/local/bin/php", _php_binary("8.3.30"))
    php = _runtimes(scan_disk_path_native(tmp_path))["php"]
    assert (php.version, php.cpe, php.purl) == ("8.3.30", "cpe:2.3:a:php:php:8.3.30:*:*:*:*:*:*:*", "pkg:generic/php/php@8.3.30")
    assert php.version_evidence == [{"type": "binary_version_string", "source_file": "usr/local/bin/php"}]
    assert php.discovery_provenance["source"] == "binary"
    assert php.discovery_provenance["source_type"] == "filesystem_scan"


def test_php_version_header_takes_precedence(tmp_path: Path) -> None:
    _write(tmp_path, "usr/local/bin/php", _php_binary("8.3.30"))
    _write(tmp_path, "usr/local/include/php/main/php_version.h", '#define PHP_MAJOR_VERSION 8\n#define PHP_VERSION "8.3.30"\n')
    php = _runtimes(scan_disk_path_native(tmp_path))["php"]
    assert php.version == "8.3.30"
    assert {item["source_file"] for item in php.version_evidence} == {"usr/local/include/php/main/php_version.h"}


@pytest.mark.parametrize(
    ("files", "name", "version", "cpe_product"),
    [
        (
            {
                "usr/local/bin/python3.12": b"\x7fELF",
                "usr/local/include/python3.12/patchlevel.h": '#define PY_VERSION "3.12.4"\n',
            },
            "cpython",
            "3.12.4",
            "python:python",
        ),
        (
            {
                "usr/local/bin/node": b"\x7fELF",
                "usr/local/include/node/node_version.h": (
                    "#define NODE_MAJOR_VERSION 22\n#define NODE_MINOR_VERSION 3\n#define NODE_PATCH_VERSION 0\n"
                ),
            },
            "node",
            "22.3.0",
            "nodejs:node.js",
        ),
        (
            {"usr/local/bin/node": b"\x7fELF" + b"\x00" * 64 + b"https://nodejs.org/download/release/v20.15.1/\x00"},
            "node",
            "20.15.1",
            "nodejs:node.js",
        ),
        ({"usr/local/go/VERSION": "go1.22.4\ntime 2024-05-30T19:26:07Z\n"}, "go", "1.22.4", "golang:go"),
        (
            {
                "usr/local/bin/ruby": b"\x7fELF",
                "usr/local/lib/ruby/3.3.0/x86_64-linux/rbconfig.rb": '  CONFIG["RUBY_PROGRAM_VERSION"] = "3.3.4"\n',
            },
            "ruby",
            "3.3.4",
            "ruby-lang:ruby",
        ),
        ({"opt/java/openjdk/release": 'IMPLEMENTOR="Eclipse Adoptium"\nJAVA_VERSION="21.0.4"\n'}, "openjdk", "21.0.4", "oracle:openjdk"),
    ],
)
def test_host_runtime_versions_from_version_files(tmp_path: Path, files: dict, name: str, version: str, cpe_product: str) -> None:
    for rel, content in files.items():
        _write(tmp_path, rel, content)
    runtime = _runtimes(scan_disk_path_native(tmp_path))[name]
    assert runtime.version == version
    assert runtime.cpe == f"cpe:2.3:a:{cpe_product}:{version}:*:*:*:*:*:*:*"


def test_header_without_binary_is_not_a_runtime(tmp_path: Path) -> None:
    _write(tmp_path, "usr/local/include/python3.12/patchlevel.h", '#define PY_VERSION "3.12.4"\n')
    _write(tmp_path, "usr/local/include/node/node_version.h", "#define NODE_MAJOR_VERSION 22\n")
    assert _runtimes(scan_disk_path_native(tmp_path)) == {}


def test_distro_duplicate_is_dropped(tmp_path: Path) -> None:
    _write(tmp_path, "usr/local/bin/php", _php_binary("8.3.30"))
    assert detect_host_runtimes(tmp_path, [Package(name="php8.3-cli", version="8.3.30-1", ecosystem="deb")]) == []
    assert [pkg.version for pkg in detect_host_runtimes(tmp_path, [Package(name="php8.2", version="8.2.1-1", ecosystem="deb")])] == [
        "8.3.30"
    ]


def test_version_string_beyond_the_read_budget_is_not_used(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(host_runtimes, "_BINARY_SCAN_BYTES", 8192)
    _write(tmp_path, "usr/local/bin/php", _php_binary("8.3.30", padding=16384))
    assert detect_host_runtimes(tmp_path, []) == []


@pytest.mark.parametrize("version", ["8.3.30:*:*:*", "x.y.z", "9" * 40])
def test_hostile_version_strings_are_rejected(tmp_path: Path, version: str) -> None:
    _write(tmp_path, "usr/local/bin/php", _php_binary(version))
    assert detect_host_runtimes(tmp_path, []) == []


def test_symlinked_binary_is_not_followed(tmp_path: Path) -> None:
    target = _write(tmp_path / "elsewhere", "php", _php_binary("8.3.30"))
    root = tmp_path / "root"
    (root / "usr/local/bin").mkdir(parents=True)
    (root / "usr/local/bin/php").symlink_to(target)
    assert detect_host_runtimes(root, []) == []


def test_runtime_detection_never_executes_binaries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("runtime detection must not run subprocesses")

    monkeypatch.setattr(subprocess, "run", _refuse)
    monkeypatch.setattr(subprocess, "Popen", _refuse)
    php = _write(tmp_path, "usr/local/bin/php", _php_binary("8.3.30"))
    php.chmod(0o755)
    assert [pkg.name for pkg in detect_host_runtimes(tmp_path, [])] == ["php"]
