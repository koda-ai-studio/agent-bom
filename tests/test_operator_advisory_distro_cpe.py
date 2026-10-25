"""Distro packages of a CPE product are never silently clean against a CPE advisory.

PHP2Shell (CVE-2026-109618 / CVE-2026-109619) names ``php:php``. The official
image builds php from source (a CPE-carrying runtime, compared upstream);
Debian ships it as ``php8.2-*`` built from source package ``php8.2`` with
backported fixes, so an upstream range cannot decide it. Without a distro feed
record it is indeterminate; with one, the distro verdict wins.

The Debian package rows are trimmed from a real ``debian:12`` + ``php8.2-cli``
image scan (no host paths or names kept).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom import history
from agent_bom.cli import main
from agent_bom.db import schema
from agent_bom.db.schema import init_db
from agent_bom.scanners.cpe_distro_packages import distro_ships_cpe_product
from agent_bom.scanners.distro_cpe_verdict import local_distro_verdict
from agent_bom.scanners.operator_advisory import OperatorAdvisory, match_advisories_against_reports

FIXTURE = Path(__file__).parent / "fixtures" / "php2shell" / "operator-advisory.json"
_DISTRO_REASON = "distro package php8.2-cli 8.2.29-1~deb12u1 ships php; verify against the distribution's advisory"


def _advisory() -> OperatorAdvisory:
    return OperatorAdvisory.model_validate(json.loads(FIXTURE.read_text()))


def _deb(name: str, version: str, source: str) -> dict:
    return {
        "name": name,
        "version": version,
        "ecosystem": "deb",
        "purl": f"pkg:deb/debian/{name}@{version}",
        "source_package": source,
        "distro_name": "debian",
        "distro_version": "12",
    }


def _runtime(version: str) -> dict:
    return {"name": "php", "version": version, "ecosystem": "generic", "cpe": f"cpe:2.3:a:php:php:{version}:*:*:*:*:*:*:*"}


def _report(*packages: dict, image: str = "abtest/php-debian:12") -> dict:
    return {
        "ai_bom_version": "1",
        "scan_id": f"scan-{image}",
        "agents": [{"name": f"image:{image}", "mcp_servers": [{"name": image, "packages": list(packages)}]}],
    }


def _debian_image(version: str) -> dict:
    return _report(
        _deb("php-common", "2:93", "php-defaults"),
        _deb("php8.2-cli", version, "php8.2"),
        _deb("php8.2-common", version, "php8.2"),
    )


@pytest.fixture()
def debian_feed_db(tmp_path: Path):
    """A local DB whose Debian tracker record fixes CVE-2026-109618 in 8.2.35-1~deb12u1 for bookworm."""
    conn = init_db(tmp_path / "vulns.db")
    conn.execute(
        "INSERT INTO vulns (id, summary, severity, source, aliases) VALUES (?, ?, 'unknown', 'debian-tracker', ?)",
        ("DEBIAN-CVE-2026-109618", "php8.2 OOM longjmp RCE", "CVE-2026-109618"),
    )
    conn.execute(
        "INSERT INTO affected (vuln_id, ecosystem, package_name, introduced, fixed, last_affected) VALUES (?, ?, ?, '0', ?, '')",
        ("DEBIAN-CVE-2026-109618", "debian:12", "php8.2", "8.2.35-1~deb12u1"),
    )
    conn.commit()
    yield conn
    conn.close()


# --- the explicit CPE product -> distro package mapping -------------------------------------


@pytest.mark.parametrize(
    "package",
    [
        _deb("php8.2-cli", "8.2.29-1~deb12u1", "php8.2"),
        _deb("libapache2-mod-php8.2", "8.2.29-1~deb12u1", "php8.2"),
        {"name": "php8.2-fpm", "version": "8.2.29-1", "ecosystem": "deb"},
        {"name": "php82-cli", "version": "8.2.29-r0", "ecosystem": "apk", "source_package": "php82"},
        {"name": "php83", "version": "8.3.30-r0", "ecosystem": "apk"},
        {"name": "php-cli", "version": "8.2.13-1.el9", "ecosystem": "rpm", "source_package": "php"},
        {"name": "php", "version": "8.2.13-1.el9", "ecosystem": "rpm"},
    ],
)
def test_distro_packages_that_ship_php_are_mapped(package: dict) -> None:
    assert distro_ships_cpe_product("php:php", package) is True


@pytest.mark.parametrize(
    "package",
    [
        _deb("php-common", "2:93", "php-defaults"),
        _deb("php8.2-redis", "6.0.2-1", "php-redis"),
        {"name": "php82-pecl-redis", "version": "6.0.2-r0", "ecosystem": "apk", "source_package": "php82-pecl-redis"},
        {"name": "php-pecl-redis5", "version": "5.3.7-1.el9", "ecosystem": "rpm", "source_package": "php-pecl-redis5"},
        {"name": "phpmyadmin", "version": "5.2.1", "ecosystem": "deb"},
        {"name": "php", "version": "8.3.30", "ecosystem": "generic"},
        {"name": "php8.2-cli", "version": "8.2.29", "ecosystem": "npm"},
    ],
)
def test_other_packages_are_not_mapped(package: dict) -> None:
    assert distro_ships_cpe_product("php:php", package) is False


def test_unmapped_cpe_product_maps_nothing() -> None:
    assert distro_ships_cpe_product("openssl:openssl", _deb("php8.2-cli", "8.2.29-1~deb12u1", "php8.2")) is False


# --- the PHP2Shell scenario end to end -------------------------------------------------------


def test_official_runtime_before_fix_is_affected_with_upstream_fix() -> None:
    result = match_advisories_against_reports([_advisory()], [_report(_runtime("8.3.30"), image="php:8.3.30-cli")])
    assert [(f["package"]["name"], f["fixed_version"]) for f in result.findings] == [("php", "8.3.36")]
    assert result.complete is True


def test_official_runtime_at_fix_is_clean() -> None:
    result = match_advisories_against_reports([_advisory()], [_report(_runtime("8.3.36"), image="php:8.3.36-cli")])
    assert result.findings == [] and result.indeterminate == [] and result.complete is True


def test_debian_package_without_distro_record_is_indeterminate_not_clean() -> None:
    result = match_advisories_against_reports([_advisory()], [_debian_image("8.2.29-1~deb12u1")])
    assert result.findings == []
    assert result.indeterminate[0] == {
        "advisory_id": "CVE-2026-109618",
        "package": "php8.2-cli@8.2.29-1~deb12u1",
        "reason": "distro_backport_unverified",
        "detail": _DISTRO_REASON,
    }
    assert [row["package"] for row in result.indeterminate] == ["php8.2-cli@8.2.29-1~deb12u1", "php8.2-common@8.2.29-1~deb12u1"]
    assert result.complete is False


def test_debian_feed_record_marks_pre_fix_package_affected(debian_feed_db) -> None:
    verdict = local_distro_verdict(debian_feed_db)
    result = match_advisories_against_reports([_advisory()], [_debian_image("8.2.29-1~deb12u1")], distro_verdict=verdict)
    assert result.indeterminate == []
    assert [(f["package"]["name"], f["fixed_version"]) for f in result.findings] == [
        ("php8.2-cli", "8.2.35-1~deb12u1"),
        ("php8.2-common", "8.2.35-1~deb12u1"),
    ]
    assert result.findings[0]["distro_verdict"] == {"ecosystem": "debian:12", "record": "DEBIAN-CVE-2026-109618"}
    assert result.complete is True


def test_debian_feed_record_marks_backported_package_clean(debian_feed_db) -> None:
    verdict = local_distro_verdict(debian_feed_db)
    result = match_advisories_against_reports([_advisory()], [_debian_image("8.2.35-1~deb12u1")], distro_verdict=verdict)
    assert result.findings == [] and result.indeterminate == [] and result.complete is True


def test_distro_record_for_another_release_does_not_decide(debian_feed_db) -> None:
    report = _debian_image("8.2.29-1~deb12u1")
    for package in report["agents"][0]["mcp_servers"][0]["packages"]:
        package["distro_version"] = "13"
    result = match_advisories_against_reports([_advisory()], [report], distro_verdict=local_distro_verdict(debian_feed_db))
    assert result.findings == []
    assert {row["reason"] for row in result.indeterminate} == {"distro_backport_unverified"}


# --- CLI table + JSON output -----------------------------------------------------------------


@pytest.fixture()
def state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(history, "HISTORY_DIR", tmp_path / "history")
    monkeypatch.setattr(schema, "DB_PATH", tmp_path / "absent" / "vulns.db")
    return tmp_path


def _cli(*args: str):
    return CliRunner().invoke(main, ["db", "advisory", *args], catch_exceptions=False)


def test_cli_table_shows_distro_indeterminate_reason(state: Path) -> None:
    _cli("add", "--file", str(FIXTURE))
    report = state / "debian.json"
    report.write_text(json.dumps(_debian_image("8.2.29-1~deb12u1")))
    result = _cli("match", "--report", str(report))
    assert result.exit_code == 2
    assert f"CVE-2026-109618\tphp8.2-cli@8.2.29-1~deb12u1\tindeterminate: {_DISTRO_REASON}" in result.output


def test_cli_uses_local_debian_feed_verdict(state: Path, monkeypatch: pytest.MonkeyPatch, debian_feed_db) -> None:
    db_file = Path(debian_feed_db.execute("PRAGMA database_list").fetchone()[2])
    monkeypatch.setattr(schema, "DB_PATH", db_file)
    _cli("add", "--file", str(FIXTURE))
    vulnerable, patched = state / "old.json", state / "new.json"
    vulnerable.write_text(json.dumps(_debian_image("8.2.29-1~deb12u1")))
    patched.write_text(json.dumps(_debian_image("8.2.35-1~deb12u1")))

    body = json.loads(_cli("match", "--report", str(vulnerable), "--format", "json").output)
    assert [(f["package"]["name"], f["fixed_version"]) for f in body["findings"]] == [
        ("php8.2-cli", "8.2.35-1~deb12u1"),
        ("php8.2-common", "8.2.35-1~deb12u1"),
    ]
    clean = _cli("match", "--report", str(patched), "--format", "json")
    assert clean.exit_code == 0
    assert json.loads(clean.output)["findings"] == []
