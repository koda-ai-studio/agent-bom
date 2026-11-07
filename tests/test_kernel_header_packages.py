"""Kernel header packages in an image are not kernel exposure.

A container runs on the host kernel. ``linux-libc-dev`` 6.1.27-1 in
redis:7.0.11 matched 7,873 kernel CVEs once OSV pages were followed, which
took the scan from 31 s to 198 s and buried every other finding. Header and
UAPI packages are left out of the advisory lookup, with one note per scan
that says how many and why; real kernel packages are still matched.
"""

from __future__ import annotations

import pytest

from agent_bom.coverage import is_scan_note
from agent_bom.models import Package
from agent_bom.scanners.package_preparation import _select_scannable_packages
from agent_bom.scanners.state import peek_coverage_warnings, reset_scan_warnings


def _pkg(name: str, ecosystem: str, distro: str, version: str = "12") -> Package:
    return Package(name=name, version="6.1.27-1", ecosystem=ecosystem, distro_name=distro, distro_version=version)


HEADERS = [
    _pkg("linux-libc-dev", "deb", "debian"),
    _pkg("linux-headers-6.1.0-9-amd64", "deb", "debian"),
    _pkg("kernel-headers", "rpm", "rhel", "9"),
    _pkg("kernel-devel", "rpm", "rhel", "9"),
    _pkg("linux-headers", "apk", "alpine", "3.19.1"),
]
KERNELS = [
    _pkg("linux-image-6.1.0-9-amd64", "deb", "debian"),
    _pkg("kernel", "rpm", "rhel", "9"),
    _pkg("linux-lts", "apk", "alpine", "3.19.1"),
]


@pytest.fixture(autouse=True)
def _fresh_scan_state() -> None:
    reset_scan_warnings()


def _notes() -> list[dict]:
    return [w for w in peek_coverage_warnings() if w.get("reason") == "kernel_header_packages_not_assessed"]


def test_header_packages_skip_the_lookup_and_real_kernels_stay() -> None:
    scannable = _select_scannable_packages(HEADERS + KERNELS)
    assert scannable == KERNELS
    [note] = _notes()
    assert is_scan_note(note)
    assert note["package_count"] == len(HEADERS)
    assert "kernel advisories on header packages are not image exposure; assess the host kernel" in note["detail"]
    assert "linux-libc-dev@6.1.27-1" in note["detail"]


def test_one_note_per_scan_across_several_batches() -> None:
    _select_scannable_packages(HEADERS[:2])
    _select_scannable_packages(HEADERS[2:])
    [note] = _notes()
    assert note["package_count"] == len(HEADERS)


@pytest.mark.parametrize(
    "package",
    [
        Package(name="linux-libc-dev", version="6.1.27-1", ecosystem="deb"),  # no distro: never guessed
        Package(name="linux-libc-dev", version="1.0.0", ecosystem="npm", distro_name="debian", distro_version="12"),
    ],
)
def test_same_name_outside_a_known_distro_package_is_still_looked_up(package: Package) -> None:
    assert _select_scannable_packages([package]) == [package]
    assert _notes() == []
