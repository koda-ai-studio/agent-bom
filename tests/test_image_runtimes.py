"""Language runtimes compiled into official images (PHP_VERSION, NODE_VERSION, ...)."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from agent_bom.models import Package
from agent_bom.oci_parser import parse_oci_tarball
from agent_bom.parsers.image_runtimes import runtime_packages_from_config

FIXTURE = Path(__file__).parent / "fixtures" / "php2shell" / "image-config.json"


def _config(*env: str) -> dict:
    return {"config": {"Env": ["PATH=/usr/local/bin:/usr/bin", *env]}, "history": []}


def _layer(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as tf:
        for path, content in files.items():
            info = tarfile.TarInfo(name=path)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _docker_save(tmp_path: Path, config: dict, layers: list[dict[str, bytes]]) -> Path:
    out = tmp_path / "image.tar"
    with tarfile.open(out, mode="w:") as outer:
        layer_paths = []
        for index, files in enumerate(layers):
            data = _layer(files)
            name = f"{index:040x}/layer.tar"
            layer_paths.append(name)
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            outer.addfile(info, io.BytesIO(data))
        for name, payload in (
            ("config.json", json.dumps(config).encode()),
            ("manifest.json", json.dumps([{"Config": "config.json", "RepoTags": ["php:8.3"], "Layers": layer_paths}]).encode()),
        ):
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            outer.addfile(info, io.BytesIO(payload))
    return out


def _runtimes(packages: list[Package]) -> dict[str, Package]:
    return {pkg.name: pkg for pkg in packages if pkg.ecosystem == "generic"}


@pytest.mark.parametrize(
    ("env", "name", "version", "cpe_prefix"),
    [
        ("PHP_VERSION=8.3.30", "php", "8.3.30", "cpe:2.3:a:php:php:8.3.30:"),
        ("PYTHON_VERSION=3.13.17", "cpython", "3.13.17", "cpe:2.3:a:python:python:3.13.17:"),
        ("NODE_VERSION=22.23.4", "node", "22.23.4", "cpe:2.3:a:nodejs:node.js:22.23.4:"),
        ("GOLANG_VERSION=1.27.3", "go", "1.27.3", "cpe:2.3:a:golang:go:1.27.3:"),
        ("RUBY_VERSION=3.4.11", "ruby", "3.4.11", "cpe:2.3:a:ruby-lang:ruby:3.4.11:"),
        ("JAVA_VERSION=jdk-21.0.12.1+1", "openjdk", "21.0.12.1", "cpe:2.3:a:oracle:openjdk:21.0.12.1:"),
        ("JAVA_VERSION=jdk-17.0.13+11", "openjdk", "17.0.13", "cpe:2.3:a:oracle:openjdk:17.0.13:"),
    ],
)
def test_official_image_env_yields_runtime_with_cpe(env: str, name: str, version: str, cpe_prefix: str) -> None:
    (pkg,) = runtime_packages_from_config(_config(env))
    assert (pkg.name, pkg.version, pkg.ecosystem) == (name, version, "generic")
    assert pkg.cpe is not None and pkg.cpe.startswith(cpe_prefix)
    assert pkg.cpe.count(":") == 12
    assert pkg.purl and pkg.purl.endswith(f"@{version}")
    assert pkg.version_evidence[0]["type"] == "image_env"
    assert pkg.discovery_provenance == {
        "source_type": "image_scan",
        "source": "image-env",
        "observed_via": [env.split("=", 1)[0]],
        "confidence": "medium",
    }


@pytest.mark.parametrize(
    "env",
    [
        "PHP_VERSION=$(curl evil)",
        "PHP_VERSION=",
        "PHP_VERSION=latest",
        "NODE_VERSION=22.x",
        "JAVA_VERSION=jdk8u432-b06",
        "PHPIZE_DEPS=autoconf",
        "GOLANG_VERSION=1.27.3; rm -rf /",
    ],
)
def test_untrusted_or_unknown_env_values_are_not_inventoried(env: str) -> None:
    assert runtime_packages_from_config(_config(env)) == []


def test_missing_or_malformed_config_is_empty() -> None:
    assert runtime_packages_from_config(None) == []
    assert runtime_packages_from_config({"config": {"Env": "PHP_VERSION=8.3.30"}}) == []
    assert runtime_packages_from_config({"Config": {"Env": ["PHP_VERSION=8.3.30"]}})[0].name == "php"


def test_php2shell_fixture_image_with_binary_is_binary_corroborated(tmp_path: Path) -> None:
    config = json.loads(FIXTURE.read_text())
    tar = _docker_save(tmp_path, config, [{"etc/os-release": b"ID=debian\n"}, {"usr/local/bin/php": b"\x7fELF"}])
    php = _runtimes(parse_oci_tarball(tar).packages)["php"]
    assert php.version == "8.3.30"
    assert php.cpe == "cpe:2.3:a:php:php:8.3.30:*:*:*:*:*:*:*"
    assert php.discovery_provenance["source"] == "binary"
    assert [occ.package_path for occ in php.occurrences] == ["usr/local/bin/php"]
    assert any(item["type"] == "binary" and item["source_file"] == "usr/local/bin/php" for item in php.version_evidence)


def test_env_only_runtime_keeps_image_env_provenance(tmp_path: Path) -> None:
    tar = _docker_save(tmp_path, _config("NODE_VERSION=22.23.4"), [{"etc/os-release": b"ID=debian\n"}])
    node = _runtimes(parse_oci_tarball(tar).packages)["node"]
    assert node.discovery_provenance["source"] == "image-env"
    assert node.occurrences == []


def test_binary_removed_by_whiteout_drops_runtime(tmp_path: Path) -> None:
    tar = _docker_save(
        tmp_path,
        _config("PHP_VERSION=8.3.30"),
        [{"usr/local/bin/php": b"\x7fELF"}, {"usr/local/bin/.wh.php": b""}],
    )
    assert "php" not in _runtimes(parse_oci_tarball(tar).packages)


def test_distro_package_of_same_release_is_not_double_counted(tmp_path: Path) -> None:
    status = b"Package: php8.2-cli\nStatus: install ok installed\nVersion: 8.2.7-1~deb12u1\nSource: php8.2\n\n"
    tar = _docker_save(tmp_path, _config("PHP_VERSION=8.2.7"), [{"var/lib/dpkg/status": status}])
    packages = parse_oci_tarball(tar).packages
    assert "php" not in _runtimes(packages)
    assert [pkg.name for pkg in packages if pkg.ecosystem == "deb"] == ["php8.2-cli"]


def test_distro_package_of_different_release_keeps_source_built_runtime(tmp_path: Path) -> None:
    status = b"Package: python3.11\nStatus: install ok installed\nVersion: 3.11.2-6+deb12u2\n\n"
    tar = _docker_save(tmp_path, _config("PYTHON_VERSION=3.13.17"), [{"var/lib/dpkg/status": status}])
    assert _runtimes(parse_oci_tarball(tar).packages)["cpython"].version == "3.13.17"


def test_python_env_merges_with_header_detected_cpython(tmp_path: Path) -> None:
    header = b'#define PY_VERSION "3.13.17"\n'
    tar = _docker_save(tmp_path, _config("PYTHON_VERSION=3.13.17"), [{"usr/local/include/python3.13/patchlevel.h": header}])
    runtimes = [pkg for pkg in parse_oci_tarball(tar).packages if pkg.ecosystem == "generic"]
    assert [(pkg.name, pkg.version) for pkg in runtimes] == [("cpython", "3.13.17")]
    assert runtimes[0].cpe == "cpe:2.3:a:python:python:3.13.17:*:*:*:*:*:*:*"
    assert runtimes[0].discovery_provenance["source"] == "binary"


def test_installed_header_version_wins_over_stale_env(tmp_path: Path) -> None:
    header = b'#define PY_VERSION "3.13.18"\n'
    tar = _docker_save(tmp_path, _config("PYTHON_VERSION=3.13.17"), [{"usr/local/include/python3.13/patchlevel.h": header}])
    (cpython,) = [pkg for pkg in parse_oci_tarball(tar).packages if pkg.ecosystem == "generic"]
    assert cpython.version == "3.13.18"
    assert cpython.cpe == "cpe:2.3:a:python:python:3.13.18:*:*:*:*:*:*:*"
