""" "Am I affected?" examines every package occurrence a stored report carries.

A container-image package occurrence lives in the report's ``blast_radius`` and
``findings`` sections (asset ``pkg:<eco>:<name>@<version>:image:<digest>``), not
under an agent's MCP server. The answer must cover it exactly as the findings
list does, name its asset type and node id, and count the image as examined.
The feed severity follows the findings policy: the primary record's CVSS first,
never the maximum label across alias records.
"""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest

from agent_bom.db.schema import init_db
from agent_bom.scanners.advisory_affected import affected_answer, feed_advisory_from_db, stored_findings_answer
from agent_bom.scanners.operator_advisory import OperatorAdvisory, iter_report_packages

_IMAGE_NODE = "pkg:pypi:pillow@9.0.0:image:136d3d0d913e"
_SAFE_IMAGE_NODE = "pkg:pypi:pillow@10.2.0:image:9fd82bd12cf6"


def _blast_row(node_id: str, version: str, *, vulnerability: str | None, fixed: str | None = None) -> dict[str, Any]:
    row: dict[str, Any] = {
        "asset": {"name": f"pillow@{version}", "asset_type": "package", "identifier": node_id, "location": f"pkg:pypi/pillow@{version}"},
        "package_name": "pillow",
        "package_version": version,
        "package_stable_id": f"stable-{version}",
        "package": f"pillow@{version}",
        "ecosystem": "pypi",
        "affected_agents": [],
        "affected_servers": [],
        "severity": "high",
        "cvss_score": 8.8,
        "fixed_version": fixed,
        "vulnerability_id": vulnerability,
    }
    return row


def _report() -> dict[str, Any]:
    webp = {"id": "CVE-2023-4863", "severity": "high", "fixed_version": "10.0.1", "summary": "libwebp heap overflow"}
    return {
        "scan_id": "showcase",
        "scan_completed_at": "2026-10-28T08:00:00+00:00",
        "agents": [
            {
                "name": "etl-agent",
                "mcp_servers": [
                    {
                        "name": "etl-server",
                        "packages": [
                            {
                                "name": "pillow",
                                "version": "9.0.0",
                                "ecosystem": "pypi",
                                "purl": "pkg:pypi/pillow@9.0.0",
                                "vulnerabilities": [webp],
                            }
                        ],
                    }
                ],
            }
        ],
        "blast_radius": [
            # The server-carried occurrence, listed in the agent tree already: never a second row.
            {
                **_blast_row("pkg:pypi:pillow@9.0.0", "9.0.0", vulnerability="CVE-2023-4863", fixed="10.0.1"),
                "affected_servers": ["etl-server"],
            },
            _blast_row(_IMAGE_NODE, "9.0.0", vulnerability="CVE-2023-4863", fixed="10.0.1"),
            # A second advisory on the same image package: one occurrence, two vulnerabilities.
            _blast_row(_IMAGE_NODE, "9.0.0", vulnerability="CVE-2023-50447", fixed="10.2.0"),
            _blast_row(_SAFE_IMAGE_NODE, "10.2.0", vulnerability="CVE-2024-28219", fixed="10.3.0"),
        ],
    }


def _advisory() -> OperatorAdvisory:
    return OperatorAdvisory.model_validate(
        {
            "id": "CVE-2023-4863",
            "aliases": ["GHSA-j7hp-h8jx-5ppr"],
            "summary": "libwebp heap overflow",
            "severity": "high",
            "affected": [{"ecosystem": "pypi", "name": "pillow", "ranges": [{"introduced": "0", "fixed": "10.0.1"}]}],
        }
    )


def test_report_walk_yields_image_occurrences_once_per_asset() -> None:
    occurrences = list(iter_report_packages(_report()))
    labels = sorted((asset.get("server", ""), asset.get("node_id", ""), package["version"]) for asset, package, _ in occurrences)
    assert labels == [("", _SAFE_IMAGE_NODE, "10.2.0"), ("", _IMAGE_NODE, "9.0.0"), ("etl-server", "", "9.0.0")]
    image = next(package for asset, package, _ in occurrences if asset.get("node_id") == _IMAGE_NODE)
    assert sorted(v["id"] for v in image["vulnerabilities"]) == ["CVE-2023-4863", "CVE-2023-50447"]
    assert image["stable_id"] == "stable-9.0.0" and image["purl"] == "pkg:pypi/pillow@9.0.0"


def test_affected_answer_covers_image_occurrences_with_asset_type_and_node_id() -> None:
    answer = affected_answer(_advisory(), [_report()], source="operator_advisory")

    server_row = next(row for row in answer["rows"] if row["asset_type"] == "mcp_server")
    assert server_row["asset_label"] == "etl-server" and server_row["verdict"] == "affected"
    assert server_row["asset_node_id"] == server_row["graph"]["server_node_id"]
    rows = {(row["asset_type"], row["asset_node_id"]): row for row in answer["rows"] if row["asset_type"] != "mcp_server"}
    assert set(rows) == {("package", _IMAGE_NODE), ("package", _SAFE_IMAGE_NODE)}
    assert rows[("package", _IMAGE_NODE)]["verdict"] == "affected"
    assert rows[("package", _IMAGE_NODE)]["fixed_version"] == "10.0.1"
    assert rows[("package", _IMAGE_NODE)]["asset_label"] == _IMAGE_NODE
    assert rows[("package", _IMAGE_NODE)]["graph"] == {"package_node_id": _IMAGE_NODE, "server_node_id": None, "agent_node_id": None}
    assert rows[("package", _SAFE_IMAGE_NODE)]["verdict"] == "not_affected"
    assert answer["summary"] == {
        "affected": 2,
        "possibly_affected": 0,
        "not_affected": 1,
        "clean_scanned": 1,
        "assets_examined": 3,
        "reports_examined": 1,
    }
    assert answer["coverage"] == {"agent_packages": 1, "standalone_packages": 2, "unexamined_sections": []}
    assert answer["complete"] is True
    assert len({row["id"] for row in answer["rows"]}) == 3


def test_unreadable_section_is_reported_never_silently_complete() -> None:
    report = _report()
    report["blast_radius"] = "corrupt"
    answer = affected_answer(_advisory(), [report], source="operator_advisory")
    assert answer["coverage"]["unexamined_sections"] == ["blast_radius"]
    assert answer["complete"] is False
    assert answer["incomplete_reason"]


def test_stored_findings_fallback_sees_image_occurrences() -> None:
    answer = stored_findings_answer("CVE-2023-50447", [_report()])
    assert answer is not None
    image = next(row for row in answer["rows"] if row["asset_type"] == "package")
    assert (image["asset_node_id"], image["verdict"], image["fixed_version"]) == (_IMAGE_NODE, "affected", "10.2.0")
    assert answer["advisory"]["fixed_versions"] == ["10.2.0"]
    # The same version behind the MCP server is named by the recorded finding's version, so it is affected too.
    assert [row["asset_type"] for row in answer["rows"]] == ["mcp_server", "package"]


def _feed_db(tmp_path) -> sqlite3.Connection:
    conn = init_db(tmp_path / "vulns.db")
    conn.execute(
        "INSERT INTO vulns (id, summary, severity, cvss_score, cvss_vector, aliases, published, source) VALUES (?,?,?,?,?,?,?,?)",
        (
            "CVE-2023-4863",
            "libwebp heap overflow",
            "high",
            8.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "GHSA-j7hp-h8jx-5ppr",
            "2023-09-12",
            "nvd",
        ),
    )
    conn.execute(
        "INSERT INTO vulns (id, summary, severity, cvss_score, cvss_vector, aliases, published, source) VALUES (?,?,?,?,?,?,?,?)",
        ("GHSA-j7hp-h8jx-5ppr", "Pillow libwebp", "critical", None, None, "CVE-2023-4863", "2023-09-13", "ghsa"),
    )
    conn.execute(
        "INSERT INTO affected (vuln_id, ecosystem, package_name, introduced, fixed, last_affected) VALUES (?,?,?,?,?,?)",
        ("GHSA-j7hp-h8jx-5ppr", "PyPI", "pillow", "0", "10.0.1", ""),
    )
    conn.commit()
    return conn


def test_feed_severity_follows_primary_record_cvss_not_alias_maximum(tmp_path) -> None:
    conn = _feed_db(tmp_path)
    try:
        advisory = feed_advisory_from_db(conn, "CVE-2023-4863")
    finally:
        conn.close()
    assert advisory is not None
    assert advisory.severity == "high"
    assert advisory.severity_source == "cvss"
    assert advisory.cvss_score == 8.8
    answer = affected_answer(advisory, [_report()], source="feed")
    assert answer["advisory"]["severity"] == "high"
    assert answer["advisory"]["severity_source"] == "cvss"
    assert answer["advisory"]["cvss_score"] == 8.8


def test_feed_severity_prefers_any_cvss_score_and_labels_only_without_one(tmp_path) -> None:
    conn = _feed_db(tmp_path)
    try:
        # A score on an alias record still outranks every label.
        conn.execute("UPDATE vulns SET cvss_score = NULL, cvss_vector = NULL WHERE id = 'CVE-2023-4863'")
        conn.execute("UPDATE vulns SET cvss_score = 6.5 WHERE id = 'GHSA-j7hp-h8jx-5ppr'")
        conn.commit()
        advisory = feed_advisory_from_db(conn, "CVE-2023-4863")
        assert advisory is not None
        assert (advisory.severity, advisory.severity_source, advisory.cvss_score) == ("medium", "cvss", 6.5)
        # Without any score the worst recorded label speaks, as the scan reports the record it matched.
        conn.execute("UPDATE vulns SET cvss_score = NULL WHERE id = 'GHSA-j7hp-h8jx-5ppr'")
        conn.commit()
        advisory = feed_advisory_from_db(conn, "CVE-2023-4863")
        assert advisory is not None
        assert (advisory.severity, advisory.severity_source, advisory.cvss_score) == ("critical", "ghsa_advisory", None)
    finally:
        conn.close()


@pytest.mark.parametrize("section", ["blast_radius", "vulnerabilities"])
def test_legacy_and_current_blast_radius_section_names_are_both_read(section: str) -> None:
    report = _report()
    rows = report.pop("blast_radius")
    report[section] = rows
    nodes = {asset.get("node_id") for asset, _, _ in iter_report_packages(report)}
    assert {_IMAGE_NODE, _SAFE_IMAGE_NODE} <= nodes
