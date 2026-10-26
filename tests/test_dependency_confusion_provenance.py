"""Dependency confusion needs evidence beyond an internal-looking name.

A package locked from the ecosystem's public registry with an artifact checksum
is a public package; the name alone does not make it a confusion target.
Internal-looking names without that evidence, or resolved from a private
registry, keep being flagged.
"""

from __future__ import annotations

import json

from agent_bom.malicious import check_dependency_confusion
from agent_bom.models import Package
from agent_bom.parsers.compiled_parsers import parse_cargo_packages
from agent_bom.parsers.node_parsers import parse_npm_packages
from agent_bom.parsers.uv_lock import parse_uv_lock
from agent_bom.scanners.package_coverage import _flag_suspicious_packages

_SHA256 = "a" * 64
_CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
_CRATES_IO_SPARSE = "sparse+https://index.crates.io/"


def _cargo_project(tmp_path, source: str | None, checksum: str | None = _SHA256) -> None:
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "app"\nversion = "0.1.0"\n[dependencies]\npin-project = "1"\n')
    rows = ['[[package]]\nname = "app"\nversion = "0.1.0"\ndependencies = ["pin-project"]\n']
    extra = (f'source = "{source}"\n' if source else "") + (f'checksum = "{checksum}"\n' if checksum else "")
    rows.append(f'[[package]]\nname = "pin-project"\nversion = "1.1.10"\n{extra}dependencies = ["pin-project-internal"]\n')
    rows.append(f'[[package]]\nname = "pin-project-internal"\nversion = "1.1.10"\n{extra}')
    (tmp_path / "Cargo.lock").write_text("version = 3\n\n" + "\n".join(rows))


def _by_name(packages: list[Package]) -> dict[str, Package]:
    return {p.name: p for p in packages}


def test_crates_io_locked_internal_crate_is_not_confusion(tmp_path):
    _cargo_project(tmp_path, _CRATES_IO)
    pkg = _by_name(parse_cargo_packages(tmp_path))["pin-project-internal"]
    assert pkg.checksums == {"SHA-256": _SHA256}
    assert pkg.download_url == "https://static.crates.io/crates/pin-project-internal/pin-project-internal-1.1.10.crate"
    assert check_dependency_confusion(pkg) is None
    _flag_suspicious_packages([pkg])
    assert pkg.is_malicious is False


def test_crates_io_sparse_index_locked_crate_is_not_confusion(tmp_path):
    _cargo_project(tmp_path, _CRATES_IO_SPARSE)
    assert check_dependency_confusion(_by_name(parse_cargo_packages(tmp_path))["pin-project-internal"]) is None


def test_private_cargo_registry_internal_crate_still_flagged(tmp_path):
    _cargo_project(tmp_path, "sparse+https://cargo.corp.example/index/")
    pkg = _by_name(parse_cargo_packages(tmp_path))["pin-project-internal"]
    assert pkg.download_url is None
    assert check_dependency_confusion(pkg) is not None


def test_public_download_without_checksum_is_not_evidence():
    pkg = Package(
        name="auth-internal",
        version="1.0.0",
        ecosystem="cargo",
        download_url="https://static.crates.io/crates/auth-internal/auth-internal-1.0.0.crate",
    )
    assert check_dependency_confusion(pkg) is not None


def test_checksum_without_public_download_is_not_evidence():
    pkg = Package(name="auth-internal", version="1.0.0", ecosystem="npm", checksums={"SHA-512": "b" * 128})
    assert check_dependency_confusion(pkg) is not None


def test_public_host_for_another_ecosystem_is_not_evidence():
    pkg = Package(
        name="auth-internal",
        version="1.0.0",
        ecosystem="pypi",
        checksums={"SHA-256": _SHA256},
        download_url="https://registry.npmjs.org/auth-internal/-/auth-internal-1.0.0.tgz",
    )
    assert check_dependency_confusion(pkg) is not None


def _npm_lock(tmp_path, resolved: str) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"name": "app", "dependencies": {"left-pad-internal": "^1.0.0"}}))
    lock = {
        "name": "app",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "dependencies": {"left-pad-internal": "^1.0.0"}},
            "node_modules/left-pad-internal": {
                "version": "1.0.0",
                "resolved": resolved,
                "integrity": "sha512-" + "A" * 86 + "==",
            },
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))


def test_npm_public_registry_locked_internal_name_is_not_confusion(tmp_path):
    _npm_lock(tmp_path, "https://registry.npmjs.org/left-pad-internal/-/left-pad-internal-1.0.0.tgz")
    pkg = _by_name(parse_npm_packages(tmp_path))["left-pad-internal"]
    assert pkg.download_url == "https://registry.npmjs.org/left-pad-internal/-/left-pad-internal-1.0.0.tgz"
    assert check_dependency_confusion(pkg) is None


def test_npm_private_registry_locked_internal_name_still_flagged(tmp_path):
    _npm_lock(tmp_path, "https://npm.corp.example/left-pad-internal/-/left-pad-internal-1.0.0.tgz")
    pkg = _by_name(parse_npm_packages(tmp_path))["left-pad-internal"]
    assert pkg.download_url is None
    assert check_dependency_confusion(pkg) is not None


def _uv_project(tmp_path, registry: str, file_url: str) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname="app"\nversion="0.1.0"\ndependencies=["acme-internal"]\n')
    (tmp_path / "uv.lock").write_text(
        "version = 1\n"
        '[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { virtual = "." }\n'
        'dependencies = [{ name = "acme-internal" }]\n'
        f'[[package]]\nname = "acme-internal"\nversion = "1.0.0"\nsource = {{ registry = "{registry}" }}\n'
        f'sdist = {{ url = "{file_url}", hash = "sha256:{_SHA256}", size = 10 }}\n'
    )


def test_pypi_locked_internal_name_is_not_confusion(tmp_path):
    _uv_project(
        tmp_path,
        "https://pypi.org/simple",
        "https://files.pythonhosted.org/packages/aa/bb/acme_internal-1.0.0.tar.gz",
    )
    pkg = _by_name(parse_uv_lock(tmp_path))["acme-internal"]
    assert pkg.checksums == {"SHA-256": _SHA256}
    assert check_dependency_confusion(pkg) is None


def test_private_index_locked_internal_name_still_flagged(tmp_path):
    _uv_project(tmp_path, "https://pypi.corp.example/simple", "https://pypi.corp.example/files/acme_internal-1.0.0.tar.gz")
    pkg = _by_name(parse_uv_lock(tmp_path))["acme-internal"]
    assert pkg.download_url is None
    assert check_dependency_confusion(pkg) is not None


def test_unlocked_internal_names_keep_true_positive_classes():
    for name, eco in [
        ("company-auth-internal", "pypi"),
        ("acme-private", "pypi"),
        ("corp-ml-sdk", "pypi"),
        ("auth-internal", "cargo"),
        ("billing-internal", "npm"),
        ("@evil-corp/internal-sdk", "npm"),
    ]:
        assert check_dependency_confusion(Package(name=name, version="1.0.0", ecosystem=eco)) is not None, name
