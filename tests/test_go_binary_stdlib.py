"""Go binaries in images: modules and the Go standard library reach the OSV lookup.

Modules read from Go build info were tagged ecosystem ``golang``, which the OSV
query skipped as unknown, and the toolchain version was never read, so a
bundled binary's ``stdlib`` CVEs (OSV ecosystem ``Go``, package ``stdlib``)
were missed with no note.
"""

from __future__ import annotations

import pytest

from agent_bom.oci_parser import parse_oci_tarball
from agent_bom.parsers.oci_extractors import go_toolchain_version
from agent_bom.scanners.package_matching import _osv_ecosystems_for_package
from tests.test_oci_parser import _make_docker_save_tar

MAGIC = b"\xff Go buildinf:"


def _buildinfo(version: bytes, modinfo: bytes) -> bytes:
    # Go 1.18+ layout: magic, pointer size, flags (0x2 = inline strings), padding to
    # 32 bytes, then varint-prefixed version and module info strings.
    header = MAGIC + b"\x08\x02" + b"\x00" * 16
    return header + bytes([len(version)]) + version + bytes([len(modinfo)]) + modinfo


def _binary(version: bytes = b"go1.18.2") -> bytes:
    modinfo = (
        b"0w\xaf\x0c\x92t\x08\x02A\xe1\xc1\x07\xe6\xd6\x18\xe6"
        b"path\tgithub.com/tianon/gosu\ndep\tgithub.com/opencontainers/runc\tv1.1.0\th1:abc=\n"
    )
    return b"\x7fELF" + b"\x00" * 60 + _buildinfo(version, modinfo) + b"\x00" * 64


def _packages(files):
    return parse_oci_tarball(_make_docker_save_tar([files])).packages


def test_bundled_go_binary_reports_stdlib_and_modules_under_go():
    packages = _packages({"usr/local/bin/gosu": _binary()})
    found = {(p.name, p.version, p.ecosystem) for p in packages}
    assert ("stdlib", "1.18.2", "go") in found
    assert ("github.com/opencontainers/runc", "v1.1.0", "go") in found
    stdlib = next(p for p in packages if p.name == "stdlib")
    assert stdlib.purl == "pkg:golang/stdlib@v1.18.2"


def test_go_packages_from_images_are_queried_in_the_go_osv_ecosystem():
    packages = [p for p in _packages({"usr/local/bin/gosu": _binary()}) if p.ecosystem == "go"]
    assert packages and all(_osv_ecosystems_for_package(p) == ["Go"] for p in packages)


@pytest.mark.parametrize(
    "raw,expected",
    [
        (b"go1.18.2", "1.18.2"),
        (b"go1.20", "1.20.0"),
        (b"go1.22rc1", "1.22.0-rc.1"),
        (b"go1.21beta2", "1.21.0-beta.2"),
        (b"go1.22.1 X:boringcrypto", "1.22.1"),
        (b"devel go1.23-abc123", None),
        (b"", None),
    ],
)
def test_toolchain_version_normalizes_to_osv_semver(raw, expected):
    assert go_toolchain_version(_buildinfo(raw, b"")) == expected


def test_pre_118_layout_without_inline_strings_yields_no_stdlib_guess():
    legacy = MAGIC + b"\x08\x00" + b"\x00" * 16 + b"go1.17.5"
    assert go_toolchain_version(legacy) is None
