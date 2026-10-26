"""The ``docker export`` fallback is bounded like the OCI layer walk.

A flattened container filesystem is one very large layer. It must honour the
same member-count, size and wall-clock limits as ``scan_oci`` and report a
coverage gap (a partial scan) instead of reading past them.
"""

from __future__ import annotations

import io
import tarfile
import tracemalloc
from pathlib import Path

import pytest

from agent_bom.image import _packages_from_tar
from agent_bom.scanners.state import consume_coverage_warnings, reset_scan_warnings

_MIB = 1024 * 1024


def _rootfs(path: Path, *, extra_files: int = 0, filler: int = 0, status_entries: int = 2) -> Path:
    status = "".join(f"Package: pkg{i}\nStatus: install ok installed\nVersion: 1.0-{i}\n\n" for i in range(status_entries)).encode()
    with tarfile.open(path, "w") as tf:
        for name, data in (("var/lib/dpkg/status", status), ("etc/os-release", b'ID=debian\nVERSION_ID="12"\n')):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        if filler:
            info = tarfile.TarInfo("opt/model/weights.bin")
            info.size = filler
            tf.addfile(info, io.BytesIO(bytes(filler)))
        for index in range(extra_files):
            info = tarfile.TarInfo(f"srv/data/file-{index}.txt")
            info.size = 1
            tf.addfile(info, io.BytesIO(b"x"))
    return path


@pytest.fixture(autouse=True)
def _clean_warnings() -> None:
    reset_scan_warnings()
    consume_coverage_warnings()


def _gaps() -> list[tuple[str, str]]:
    return [(w["reason"], w["release"]) for w in consume_coverage_warnings()]


def test_rootfs_within_limits_extracts_packages_with_distro(tmp_path: Path) -> None:
    packages = _packages_from_tar(_rootfs(tmp_path / "fs.tar"))
    deb = sorted((p.name, p.version, p.distro_name, p.distro_version) for p in packages if p.ecosystem == "deb")
    assert deb == [("pkg0", "1.0-0", "debian", "12"), ("pkg1", "1.0-1", "debian", "12")]
    assert _gaps() == []


def test_member_limit_reports_a_partial_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_OCI_MAX_LAYER_MEMBERS", "50")
    packages = _packages_from_tar(_rootfs(tmp_path / "fs.tar", extra_files=200))
    assert packages == []
    assert _gaps() == [("oci_layer_member_limit", "oci:docker-export")]


def test_size_limit_reports_a_partial_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_OCI_MAX_LAYER_UNCOMPRESSED_BYTES", str(4 * _MIB))
    packages = _packages_from_tar(_rootfs(tmp_path / "fs.tar", filler=8 * _MIB))
    assert packages == []
    assert _gaps() == [("oci_layer_size_limit", "oci:docker-export")]


def test_exhausted_time_budget_reports_a_partial_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_OCI_SCAN_TIMEOUT_SECONDS", "0.000001")
    packages = _packages_from_tar(_rootfs(tmp_path / "fs.tar", status_entries=5))
    assert packages == []
    assert _gaps() == [("oci_scan_time_budget", "oci:docker-export")]


def test_large_rootfs_is_read_in_place_with_bounded_memory(tmp_path: Path) -> None:
    rootfs = _rootfs(tmp_path / "fs.tar", filler=24 * _MIB, status_entries=2000)
    tracemalloc.start()
    try:
        packages = _packages_from_tar(rootfs)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len([p for p in packages if p.ecosystem == "deb"]) == 2000
    assert peak < 12 * _MIB


def test_unreadable_rootfs_is_a_coverage_gap_not_a_crash(tmp_path: Path) -> None:
    broken = tmp_path / "fs.tar"
    broken.write_bytes(b"not a tar archive" * 64)
    assert _packages_from_tar(broken) == []
    assert _gaps() == [("oci_layer_parse_error", "oci:docker-export")]
