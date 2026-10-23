"""GPU stack components found on disk match NVIDIA CSAF and NVD CPE advisories by version."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom import config
from agent_bom.db.schema import init_db
from agent_bom.filesystem import scan_disk_path_native
from agent_bom.models import Package
from agent_bom.parsers.gpu_stack import finalize_gpu_stack
from agent_bom.scanners import nvidia_advisory, package_coverage
from agent_bom.scanners.local_advisories import _scan_packages_db_conn

FIXTURES = Path(__file__).parent / "fixtures" / "nvidia_csaf"


def _rootfs(root: Path, toolkit_version: str) -> Path:
    status = root / "var/lib/dpkg/status"
    status.parent.mkdir(parents=True)
    status.write_text(
        "".join(
            f"Package: {name}\nStatus: install ok installed\nVersion: {toolkit_version}-1\n\n"
            for name in ("nvidia-container-toolkit", "nvidia-container-toolkit-base", "libnvidia-container1")
        )
    )
    return root


@pytest.fixture
def csaf_feed(monkeypatch: pytest.MonkeyPatch) -> None:
    docs = {name: json.loads((FIXTURES / name).read_text()) for name in ("container-toolkit-5582.json", "gpu-display-driver-5586.json")}

    async def _index(**_kwargs: object) -> list[dict]:
        return [{"id": name, "path": name, "url": name} for name in docs]

    async def _fetch(url: str, _client: object) -> dict:
        return docs[url]

    async def _no_ghsa(_packages: list[Package]) -> int:
        return 0

    monkeypatch.setattr(nvidia_advisory, "fetch_nvidia_advisory_index", _index)
    monkeypatch.setattr(nvidia_advisory, "fetch_nvidia_csaf", _fetch)
    monkeypatch.setattr(package_coverage, "_check_ghsa", _no_ghsa)


async def _enrich(packages: list[Package]) -> list[Package]:
    await package_coverage._scan_supplemental_advisories(packages, offline=False)
    return packages


@pytest.mark.asyncio
@pytest.mark.usefixtures("csaf_feed")
async def test_vulnerable_container_toolkit_on_disk_matches_nvidia_csaf(tmp_path: Path) -> None:
    packages = await _enrich(scan_disk_path_native(_rootfs(tmp_path, "1.16.1")))
    hits = {(pkg.name, v.id, v.fixed_version) for pkg in packages for v in pkg.vulnerabilities}
    assert hits == {("nvidia-container-toolkit", "CVE-2024-0132", "1.16.2")}
    (vuln,) = next(pkg for pkg in packages if pkg.name == "nvidia-container-toolkit").vulnerabilities
    assert vuln.advisory_sources == ["nvidia_csaf"]


@pytest.mark.asyncio
@pytest.mark.usefixtures("csaf_feed")
async def test_fixed_container_toolkit_has_no_csaf_finding(tmp_path: Path) -> None:
    packages = await _enrich(scan_disk_path_native(_rootfs(tmp_path, "1.16.2")))
    assert [v.id for pkg in packages for v in pkg.vulnerabilities] == []


def _driver(version: str) -> Package:
    pkg = Package(name="nvidia-gpu-display-driver", version=version, ecosystem="generic")
    pkg.version_evidence = [{"type": "loaded_kernel_module", "source_file": "proc/driver/nvidia/version"}]
    (driver,) = finalize_gpu_stack([pkg])
    return driver


@pytest.mark.asyncio
@pytest.mark.usefixtures("csaf_feed")
@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("550.54.15", [("CVE-2024-0126", "550.127.05")]),
        ("550.127.05", []),
        ("535.183.01", [("CVE-2024-0126", "535.216.01")]),
        ("470.256.02", []),
    ],
)
async def test_driver_csaf_fix_is_chosen_from_the_same_linux_branch(version: str, expected: list[tuple[str, str]]) -> None:
    (driver,) = await _enrich([_driver(version)])
    assert [(v.id, v.fixed_version) for v in driver.vulnerabilities] == expected


def test_csaf_fixed_version_reads_underscore_product_ids() -> None:
    doc = json.loads((FIXTURES / "container-toolkit-5582.json").read_text())
    assert nvidia_advisory._extract_fixed_version(doc["vulnerabilities"][0]) == "1.16.2"


def _nvd_conn():
    conn = init_db(Path(":memory:"))
    rows = [
        (
            "CVE-2024-0132",
            "cpe:2.3:a:nvidia:nvidia_container_toolkit:*:*:*:*:*:*:*:*",
            "nvidia",
            "nvidia_container_toolkit",
            None,
            None,
            None,
            "1.16.2",
            "excluding",
        ),
        (
            "CVE-2024-0090",
            "cpe:2.3:a:nvidia:gpu_display_driver:*:*:*:*:*:linux:*:*",
            "nvidia",
            "gpu_display_driver",
            None,
            "550",
            "including",
            "550.90.07",
            "excluding",
        ),
        (
            "CVE-2024-0091",
            "cpe:2.3:a:nvidia:gpu_display_driver:*:*:*:*:*:windows:*:*",
            "nvidia",
            "gpu_display_driver",
            None,
            "550",
            "including",
            "552.55",
            "excluding",
        ),
    ]
    conn.executemany(
        "INSERT INTO cpe_matches (cve_id, criteria, vendor, product, version, "
        "version_start, version_start_op, version_end, version_end_op) VALUES (?,?,?,?,?,?,?,?,?)",
        rows,
    )
    for cve, *_ in rows:
        conn.execute("INSERT INTO vulns (id, summary, severity, cvss_score, source) VALUES (?, 'gpu flaw', 'critical', 9.0, 'nvd')", (cve,))
    conn.commit()
    return conn


def test_distro_anchored_toolkit_matches_nvd_by_upstream_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "ENABLE_CPE_MATCH", False)
    packages = scan_disk_path_native(_rootfs(tmp_path, "1.16.1"))
    _scan_packages_db_conn(_nvd_conn(), packages, set())
    assert {(pkg.name, v.id) for pkg in packages for v in pkg.vulnerabilities} == {("nvidia-container-toolkit", "CVE-2024-0132")}


@pytest.mark.parametrize(("version", "expected"), [("550.54.15", ["CVE-2024-0090"]), ("550.100.01", [])])
def test_linux_driver_ignores_windows_only_nvd_ranges(monkeypatch: pytest.MonkeyPatch, version: str, expected: list[str]) -> None:
    monkeypatch.setattr(config, "ENABLE_CPE_MATCH", False)
    driver = _driver(version)
    _scan_packages_db_conn(_nvd_conn(), [driver], set())
    assert [v.id for v in driver.vulnerabilities] == expected
