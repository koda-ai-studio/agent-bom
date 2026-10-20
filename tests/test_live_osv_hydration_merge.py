"""Live OSV advisories must survive hydration and merge with an outdated local DB.

Realistic wire shape: ``/v1/querybatch`` returns only ``{id, modified}`` stubs,
details come from ``/v1/vulns/{id}``, and the local DB is built by the real
OSV ingestion code from advisory records, holding only three of the five
advisories the live feed reports for lodash@4.17.20.
"""

from __future__ import annotations

import asyncio
import json
import socket
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.db.schema import init_db
from agent_bom.db.sync import _ingest_osv_file

LOCAL = {"GHSA-29mw-wpgm-hmr9": "CVE-2020-28500", "GHSA-35jh-r3h4-6jhm": "CVE-2021-23337", "GHSA-xxjr-mmjv-4gpg": "CVE-2025-13465"}
LIVE_ONLY = {"GHSA-f23m-r3pf-42rh": "CVE-2026-2950", "GHSA-r5fr-rjxr-66jc": "CVE-2026-4800"}
ALL = {**LOCAL, **LIVE_ONLY}
FIXED = {"GHSA-29mw-wpgm-hmr9": "4.17.21", "GHSA-35jh-r3h4-6jhm": "4.17.21", "GHSA-xxjr-mmjv-4gpg": "4.17.23"}


def _record(ghsa_id: str) -> dict:
    return {
        "id": ghsa_id,
        "aliases": [ALL[ghsa_id]],
        "summary": f"lodash advisory {ghsa_id}",
        "modified": "2026-10-17T02:56:13Z",
        "published": "2026-04-01T23:50:27Z",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": FIXED.get(ghsa_id, "4.18.0")}]}],
            }
        ],
        "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-1321"]},
    }


def _build_db(path: Path, *, synced_days_ago: int) -> Path:
    conn = init_db(path)
    try:
        for ghsa_id in LOCAL:
            _ingest_osv_file(conn, json.dumps(_record(ghsa_id)).encode(), f"{ghsa_id}.json")
        synced = (datetime.now(timezone.utc) - timedelta(days=synced_days_ago)).isoformat()
        conn.execute("INSERT OR REPLACE INTO sync_meta(source,last_synced,record_count) VALUES ('osv',?,?)", (synced, len(LOCAL)))
        conn.commit()
    finally:
        conn.close()
    return path


class _OSVServer:
    """Answers the two OSV endpoints the scanner uses; records every request."""

    def __init__(self, *, failing_details: frozenset[str] = frozenset()) -> None:
        self.failing_details = failing_details
        self.calls: list[str] = []

    async def request(self, _client, method: str, url: str, **kwargs):
        self.calls.append(f"{method} {url}")
        request = httpx.Request(method, url)
        if url.endswith("/querybatch"):
            queries = kwargs["json"]["queries"]
            stubs = [{"id": ghsa_id, "modified": "2026-10-17T02:56:13Z"} for ghsa_id in ALL]
            results = [{"vulns": stubs} if q["package"]["name"] == "lodash" and q["version"] == "4.17.20" else {} for q in queries]
            return httpx.Response(200, json={"results": results}, request=request)
        ghsa_id = url.rsplit("/", 1)[-1]
        if "/vulns/" in url and ghsa_id in ALL and ghsa_id not in self.failing_details:
            return httpx.Response(200, json=_record(ghsa_id), request=request)
        return httpx.Response(503, json={}, request=request)


@pytest.fixture(autouse=True)
def _no_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    def _refuse(*_args, **_kwargs):
        raise AssertionError("test attempted a real network connection")

    monkeypatch.setattr(socket.socket, "connect", _refuse)
    monkeypatch.setattr(socket, "create_connection", _refuse)


def _install(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, server: _OSVServer, *, synced_days_ago: int = 61) -> None:
    @asynccontextmanager
    async def _client(*_args, **_kwargs):
        yield object()

    db = _build_db(tmp_path / "vulns.db", synced_days_ago=synced_days_ago)
    monkeypatch.setattr("agent_bom.db.schema.DB_PATH", db)
    monkeypatch.setattr("agent_bom.scanners.create_client", _client)
    monkeypatch.setattr("agent_bom.scanners.request_with_retry", server.request)
    monkeypatch.setattr("agent_bom.scanners._get_scan_cache", lambda: None)
    monkeypatch.setenv("AGENT_BOM_SCAN_CACHE", str(tmp_path / "scan_cache.db"))
    monkeypatch.delenv("AGENT_BOM_VULN_DB_MAX_AGE_HOURS", raising=False)
    monkeypatch.delenv("AGENT_BOM_VULN_DB_OFFLINE", raising=False)

    async def _no_ghsa(_packages):
        return 0

    monkeypatch.setattr("agent_bom.scanners.package_scan._check_ghsa", _no_ghsa)


def _cli_json() -> dict:
    result = CliRunner().invoke(main, ["check", "lodash@4.17.20", "--ecosystem", "npm", "--format", "json"])
    return json.loads(result.output)


def _mcp() -> dict:
    from agent_bom.mcp_tools.scanning import check_impl

    return json.loads(
        asyncio.run(
            check_impl(
                package="lodash@4.17.20",
                ecosystem="npm",
                _validate_ecosystem=lambda ecosystem: ecosystem,
                _truncate_response=lambda response: response,
            )
        )
    )


def _ids(payload: dict) -> set[str]:
    return {detail["id"] for detail in payload["vulnerability_details"]}


def test_ids_only_querybatch_is_hydrated_and_merged_with_partial_local_db(monkeypatch, tmp_path):
    server = _OSVServer()
    _install(monkeypatch, tmp_path, server)

    payload = _cli_json()

    assert any(call.endswith("/querybatch") for call in server.calls)
    hydrated = {call.rsplit("/", 1)[-1] for call in server.calls if "/vulns/" in call}
    assert hydrated == set(ALL)
    assert _ids(payload) == set(ALL.values())
    assert payload["vulnerability_count"] == 5
    assert payload["completeness"]["status"] == "complete"
    assert _ids(_mcp()) == set(ALL.values())


def test_live_ids_whose_details_fail_are_kept_not_dropped(monkeypatch, tmp_path):
    server = _OSVServer(failing_details=frozenset(LIVE_ONLY))
    _install(monkeypatch, tmp_path, server)

    payload = _cli_json()

    reported = {detail["id"]: detail for detail in payload["vulnerability_details"]}
    for ghsa_id in LIVE_ONLY:
        assert ghsa_id in reported, f"{ghsa_id} was dropped after its detail fetch failed"
        # Without details nothing beyond the ID is invented: no fix, no summary, no score.
        assert reported[ghsa_id]["fixed_version"] is None
        assert reported[ghsa_id]["cvss_score"] is None
        assert reported[ghsa_id]["summary"] == "No description available"
    assert set(LOCAL.values()) <= set(reported)
    assert any("advisory details" in warning.lower() for warning in payload["scan_warnings"])


def test_outdated_db_without_a_live_osv_answer_is_incomplete(monkeypatch, tmp_path):
    """No OSV request completed (and no cache answer): never claim live data backed the result."""
    _install(monkeypatch, tmp_path, _OSVServer())

    async def _silent(_packages):
        return {}

    monkeypatch.setattr("agent_bom.scanners.query_osv_batch", _silent)

    payload = _cli_json()

    assert _ids(payload) == set(LOCAL.values())
    assert payload["completeness"]["status"] == "incomplete"
    assert "did not answer" in payload["completeness"]["reason"]
    assert _mcp()["completeness"] == payload["completeness"]


def test_fresh_db_needs_no_live_answer(monkeypatch, tmp_path):
    server = _OSVServer()
    _install(monkeypatch, tmp_path, server, synced_days_ago=0)

    payload = _cli_json()

    assert server.calls == []
    assert payload["completeness"] == {"status": "complete", "reason": ""}
