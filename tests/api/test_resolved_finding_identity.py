"""A resolved finding keeps the package it was on and names the scans that saw and cleared it."""

# ruff: noqa: F811
from __future__ import annotations

from typing import Any

from agent_bom.api import stores
from agent_bom.api.finding_lifecycle_fold import replay_lifecycle
from agent_bom.api.finding_scan_lifecycle import apply_scan_lifecycle
from tests.api.test_finding_lifecycle_replay_store import _job
from tests.api.test_finding_lifecycle_sequences import (  # noqa: F401
    VULN,
    T,
    client,
    push_estate,
    store_kind,
)


def _stream_row(asset: str, cve: str, name: str, version: str, severity: str) -> dict[str, Any]:
    """The unified stream row the CLI pushes: package identity only under ``evidence``, no scan id."""
    return {
        "id": f"{asset}:{cve}:{name}:{version}",
        "canonical_id": f"{asset}:{cve}:{name}:{version}",
        "finding_type": "CVE",
        "source": "MCP_SCAN",
        "cve_id": cve,
        "vulnerability_id": cve,
        "severity": severity,
        "title": f"{cve}: {name}@{version}",
        "scan_id": None,
        "evidence": {"package_name": name, "package_version": version, "ecosystem": "pypi"},
        "asset": {"name": asset, "asset_type": "mcp_server", "identifier": asset},
    }


def _expire_all_jobs() -> None:
    assert stores._get_store().cleanup_expired(-86400) >= 0


def test_resolved_row_keeps_package_identity_and_both_scans(push_estate):
    seen = push_estate.scan("asset-a", [], T[1], rows=[_stream_row("asset-a", *VULN)])
    cleared = push_estate.scan("asset-a", [], T[2], rows=[])
    row = push_estate.one(VULN[0], "resolved")
    assert row["resolution_reason"] == "no_longer_detected"
    assert row["package_version"] == VULN[2]
    assert row["ecosystem"] == "pypi"
    assert row["package"] in {VULN[1], f"{VULN[1]}@{VULN[2]}"}
    assert row["scan_id"] == seen["job_id"]
    assert row["resolved_by_scan_id"] == cleared["job_id"]


def test_resolved_identity_survives_scan_retention(push_estate):
    push_estate.scan("asset-a", [], T[1], rows=[_stream_row("asset-a", *VULN)])
    cleared = push_estate.scan("asset-a", [], T[2], rows=[])
    _expire_all_jobs()
    row = push_estate.one(VULN[0], "resolved")
    assert row["package_version"] == VULN[2]
    assert row["ecosystem"] == "pypi"
    assert row["resolved_by_scan_id"] == cleared["job_id"]


def test_open_and_reopened_rows_carry_no_resolving_scan(push_estate):
    push_estate.scan("asset-a", [], T[1], rows=[_stream_row("asset-a", *VULN)])
    push_estate.scan("asset-a", [], T[2], rows=[])
    push_estate.scan("asset-a", [], T[3], rows=[_stream_row("asset-a", *VULN)])
    row = push_estate.one(VULN[0], "open")
    assert row["status"] == "reopened"
    assert row.get("resolved_by_scan_id") is None


def test_replay_without_a_durable_table_names_the_resolving_scan() -> None:
    row = _stream_row("host", *VULN)
    states = replay_lifecycle([_job("a", T[1], [row]), _job("b", T[2], [])], lambda job: [])
    assert [(state.status, state.resolved_job_id) for state in states] == [("resolved", "b")]
    served = apply_scan_lifecycle(
        [], states, since=None, live_since=None, load_payloads=lambda _states: None, finish_rows=lambda rows: rows
    )
    assert len(served) == 1
    resolved = served[0]
    assert (resolved["package_version"], resolved["ecosystem"], resolved["scan_id"]) == (VULN[2], "pypi", "a")
    assert resolved["resolved_by_scan_id"] == "b"


def test_a_late_older_scan_does_not_change_the_resolving_scan() -> None:
    row = _stream_row("host", *VULN)
    states = replay_lifecycle([_job("b", T[2], []), _job("c", T[3], []), _job("a", T[1], [row])], lambda job: [])
    assert [(state.status, state.resolved_job_id) for state in states] == [("resolved", "b")]
