"""OS packages must only match advisories published for their own distro.

OSV's bare ``Linux`` ecosystem is the upstream kernel feed. A distro package
(``kernel`` on Amazon Linux, Fedora, ...) carries backports that upstream
ranges know nothing about, so matching it there yields false positives and
wrong fix versions. A distro without a supported feed gets an explicit
coverage warning instead.
"""

from __future__ import annotations

import asyncio
import itertools

import pytest

from agent_bom.coverage import detect_release_coverage_gaps, osv_fallback_db_keys
from agent_bom.db.lookup import lookup_package
from agent_bom.db.schema import init_db
from agent_bom.intel_lookup import normalize_package_query
from agent_bom.models import Package
from agent_bom.scanners.osv import ecosystem_matches
from agent_bom.scanners.package_matching import _resolve_osv_ecosystems

_AMZN_KERNEL = "6.1.102-108.177.amzn2023"

_UNSUPPORTED_DISTROS = [None, "", "unknown-os", "amzn", "ol", "fedora", "sles", "azurelinux", "mariner", "rhel"]
_VERSIONS = [None, "", "2023", "9.5", "40"]


@pytest.mark.parametrize(
    ("ecosystem", "distro_name", "distro_version", "for_local_db"),
    list(itertools.product(["deb", "apk", "rpm"], _UNSUPPORTED_DISTROS, _VERSIONS, [True, False])),
)
def test_os_packages_never_resolve_to_upstream_linux(ecosystem, distro_name, distro_version, for_local_db):
    pkg = Package(name="kernel", version="1.0", ecosystem=ecosystem, distro_name=distro_name, distro_version=distro_version)

    resolved = _resolve_osv_ecosystems(pkg, for_local_db=for_local_db)

    assert all(eco.split(":", 1)[0].lower() != "linux" for eco in resolved), resolved


@pytest.mark.parametrize("distro_name", ["amzn", "ol", "fedora", "sles", "azurelinux", "unknown-os", None])
def test_rpm_without_supported_feed_resolves_to_no_ecosystem(distro_name):
    pkg = Package(name="kernel", version=_AMZN_KERNEL, ecosystem="rpm", distro_name=distro_name, distro_version="2023")

    assert _resolve_osv_ecosystems(pkg, for_local_db=True) == []
    assert _resolve_osv_ecosystems(pkg, for_local_db=False) == []


def test_supported_rpm_distro_still_resolves():
    pkg = Package(name="openssl", version="3.0.7-1.el9", ecosystem="rpm", distro_name="rhel", distro_version="9.4")

    assert _resolve_osv_ecosystems(pkg, for_local_db=True) == ["Red Hat:enterprise_linux:9"]


def test_live_upstream_linux_advisory_does_not_match_rpm_query():
    assert ecosystem_matches("Linux", "rpm") is False
    assert ecosystem_matches("Red Hat:enterprise_linux:9", "rpm") is True


def test_intel_package_match_does_not_route_rpm_to_upstream_linux():
    query = normalize_package_query({"purl": f"pkg:rpm/amzn/kernel@{_AMZN_KERNEL}"})

    assert query["ecosystem"] != "linux"


def _seed_upstream_kernel_advisory(conn) -> None:
    conn.execute(
        "INSERT INTO vulns(id, summary, severity, source) VALUES (?, ?, ?, ?)",
        ("CVE-2099-0001", "synthetic upstream kernel advisory", "high", "osv"),
    )
    conn.execute(
        "INSERT INTO affected(vuln_id, ecosystem, package_name, introduced, fixed, last_affected) VALUES (?, ?, ?, ?, ?, ?)",
        ("CVE-2099-0001", "linux", "kernel", "6.1.0", "6.1.110", None),
    )
    conn.commit()


def test_offline_scan_of_amazon_linux_kernel_ignores_upstream_advisory(tmp_path, monkeypatch):
    from agent_bom.scanners import ScanOptions, consume_coverage_warnings, consume_scan_warnings, scan_packages

    db_path = tmp_path / "vulns.db"
    conn = init_db(db_path)
    _seed_upstream_kernel_advisory(conn)
    assert lookup_package(conn, "Linux", "kernel", _AMZN_KERNEL), "fixture must reproduce the upstream range hit"
    conn.close()
    monkeypatch.setattr("agent_bom.db.schema.DB_PATH", db_path)
    monkeypatch.setattr("agent_bom.db.schema.db_freshness_days", lambda path=None: 0)

    pkg = Package(name="kernel", version=_AMZN_KERNEL, ecosystem="rpm", distro_name="amzn", distro_version="2023")
    try:
        asyncio.run(scan_packages([pkg], options=ScanOptions(offline=True)))
    except Exception:  # noqa: BLE001 - an honest incomplete-scan outcome is acceptable here
        pass

    coverage = consume_coverage_warnings()
    consume_scan_warnings()
    assert pkg.vulnerabilities == []
    assert any(w.get("reason") == "advisory_source_unavailable" and w.get("release") == "amazon-linux:2023" for w in coverage)


@pytest.mark.parametrize(
    ("distro_name", "distro_version", "expected_release"),
    [
        ("fedora", "40", "fedora:40"),
        ("azurelinux", "3.0", "azurelinux:3"),
        ("mariner", "2.0", "mariner:2"),
        ("photon", "5.0", "photon:5"),
        ("rhel", None, "rhel:unknown"),
        (None, None, "rpm-unknown-distro:unknown"),
    ],
)
def test_every_unresolved_rpm_distro_warns_source_unavailable(tmp_path, distro_name, distro_version, expected_release):
    conn = init_db(tmp_path / "vulns.db")
    pkg = Package(name="kernel", version="1.0-1", ecosystem="rpm", distro_name=distro_name, distro_version=distro_version)

    warnings = detect_release_coverage_gaps([pkg], conn=conn)
    conn.close()

    assert [w["release"] for w in warnings] == [expected_release]
    assert warnings[0]["reason"] == "advisory_source_unavailable"
    assert "not a clean bill of health" in warnings[0]["detail"].lower()


def test_single_unsupported_rpm_package_still_warns(tmp_path):
    conn = init_db(tmp_path / "vulns.db")
    pkg = Package(name="kernel", version=_AMZN_KERNEL, ecosystem="rpm", distro_name="amzn", distro_version="2023")

    warnings = detect_release_coverage_gaps([pkg], conn=conn)
    conn.close()

    assert [(w["release"], w["package_count"]) for w in warnings] == [("amazon-linux:2023", 1)]


def test_source_unavailable_gap_does_not_force_pointless_osv_fallback(tmp_path):
    conn = init_db(tmp_path / "vulns.db")
    pkgs = [Package(name=f"p{i}", version="1.0-1", ecosystem="rpm", distro_name="amzn", distro_version="2023") for i in range(6)]
    gaps = detect_release_coverage_gaps(pkgs, conn=conn)
    conn.close()

    assert gaps
    assert osv_fallback_db_keys(pkgs, gaps=gaps) == set()
