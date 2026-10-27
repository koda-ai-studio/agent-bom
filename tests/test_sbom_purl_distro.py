"""SBOM OS packages carry their distro from the purl, like an image scan reads os-release.

Parity: the same package seen by an image scan (``/etc/os-release`` ID +
VERSION_ID) and by SBOM ingest (purl namespace + ``distro=`` qualifier) must
resolve to the same advisory ecosystem.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.filesystem import read_os_release_metadata
from agent_bom.models import Package
from agent_bom.parsers.oci_layer import _apply_detected_distro
from agent_bom.sbom import parse_sbom_document
from agent_bom.scanners.package_matching import _resolve_osv_ecosystems

# (purl, os-release ID, os-release VERSION_ID, expected local-DB ecosystem keys)
_CASES = [
    ("pkg:rpm/redhat/openssl@3.0.7-27.el9?arch=x86_64&distro=rhel-9.4", "rhel", "9.4", ["Red Hat:enterprise_linux:9"]),
    ("pkg:rpm/redhat/openssl@3.0.7-27.el9?arch=x86_64&distro=redhat-9.4", "rhel", "9.4", ["Red Hat:enterprise_linux:9"]),
    ("pkg:rpm/redhat/openssl@3.0.7-27.el9?distro=el9", "rhel", "9", ["Red Hat:enterprise_linux:9"]),
    ("pkg:rpm/rocky/openssl@3.0.7-27.el9_3?arch=x86_64&distro=rocky-9.3", "rocky", "9.3", ["Rocky Linux:9"]),
    ("pkg:rpm/almalinux/openssl@3.0.7-27.el8?distro=almalinux-8.9", "almalinux", "8.9", ["AlmaLinux:8"]),
    ("pkg:rpm/centos/bash@4.2.46-35.el7_9?distro=centos-7", "centos", "7", ["Red Hat:enterprise_linux:7"]),
    (
        "pkg:rpm/opensuse/curl@8.0.1-150400.5.32.1?distro=opensuse-leap-15.5",
        "opensuse-leap",
        "15.5",
        ["openSUSE:Leap 15.5", "openSUSE:Leap 15.5 NonFree"],
    ),
    ("pkg:rpm/amzn/openssl@3.0.8-1.amzn2023?distro=amzn-2023", "amzn", "2023", []),
    ("pkg:deb/debian/libc6@2.36-9%2Bdeb12u4?arch=amd64&distro=debian-12", "debian", "12", ["Debian:12"]),
    ("pkg:deb/debian/libc6@2.36-9%2Bdeb12u4?distro=debian-12.5", "debian", "12.5", ["Debian:12"]),
    ("pkg:deb/ubuntu/libc6@2.35-0ubuntu3.6?arch=amd64&distro=ubuntu-22.04", "ubuntu", "22.04", ["Ubuntu:22.04:LTS", "Ubuntu:22.04"]),
    ("pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&distro=3.19.1", "alpine", "3.19.1", ["Alpine:v3.19"]),
    ("pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&distro=alpine-3.19.1", "alpine", "3.19.1", ["Alpine:v3.19"]),
    ("pkg:apk/wolfi/glibc@2.39-r1?arch=x86_64", "wolfi", None, ["Wolfi"]),
]


def _cyclonedx(purl: str) -> dict:
    name = purl.split("/")[-1].split("@")[0]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"type": "library", "name": name, "version": "1", "purl": purl}],
    }


def _spdx2(purl: str) -> dict:
    name = purl.split("/")[-1].split("@")[0]
    return {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "SPDXID": "SPDXRef-p",
                "name": name,
                "versionInfo": "1",
                "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}],
            }
        ],
    }


def _image_package(tmp_path: Path, purl: str, os_id: str, version_id: str | None) -> Package:
    root = tmp_path / "rootfs"
    (root / "etc").mkdir(parents=True)
    lines = [f'ID="{os_id}"'] + ([f'VERSION_ID="{version_id}"'] if version_id else [])
    (root / "etc" / "os-release").write_text("\n".join(lines) + "\n", encoding="utf-8")
    name, version = read_os_release_metadata(root)
    package = Package(name="pkg", version="1", ecosystem=purl[4:].split("/", 1)[0])
    _apply_detected_distro([package], name, version)
    return package


@pytest.mark.parametrize(("purl", "os_id", "version_id", "expected"), _CASES)
@pytest.mark.parametrize("document", [_cyclonedx, _spdx2], ids=["cyclonedx", "spdx2"])
def test_sbom_purl_distro_matches_image_scan_ecosystem(tmp_path, document, purl, os_id, version_id, expected):
    packages, _, _ = parse_sbom_document(document(purl))
    [sbom_pkg] = packages
    image_pkg = _image_package(tmp_path, purl, os_id, version_id)

    assert (sbom_pkg.distro_name, sbom_pkg.distro_version) == (image_pkg.distro_name, image_pkg.distro_version)
    assert _resolve_osv_ecosystems(sbom_pkg, for_local_db=True) == expected
    assert _resolve_osv_ecosystems(sbom_pkg, for_local_db=True) == _resolve_osv_ecosystems(image_pkg, for_local_db=True)
    assert _resolve_osv_ecosystems(sbom_pkg, for_local_db=False) == _resolve_osv_ecosystems(image_pkg, for_local_db=False)


@pytest.mark.parametrize(
    "purl",
    [
        "pkg:rpm/openssl@3.0.7-27.el9",  # no namespace, no qualifier
        "pkg:rpm/redhat/openssl@3.0.7?distro=",  # empty qualifier
        "pkg:deb/debian/libc6@2.36?distro=bookworm",  # codename: name known, release not
        "pkg:pypi/requests@2.31.0?distro=rhel-9",  # not an OS package
    ],
)
def test_sbom_purl_distro_never_guesses(purl):
    [pkg] = parse_sbom_document(_cyclonedx(purl))[0]
    expected_name = {"redhat": "rhel", "debian": "debian"}.get(purl[4:].split("/")[1] if purl.count("/") > 1 else "", None)
    if pkg.ecosystem not in {"rpm", "deb", "apk"}:
        expected_name = None
    assert pkg.distro_name == expected_name
    assert pkg.distro_version is None
