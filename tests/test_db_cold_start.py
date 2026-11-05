"""A first run with no vulnerability DB builds fast, publishes atomically and stays honest about scope."""

from __future__ import annotations

import os
import re
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from rich.console import Console

from agent_bom.cli.agents.scan_pipeline import preflight
from agent_bom.db import sync as sync_module
from agent_bom.db.schema import init_db
from agent_bom.db.sync_build import STALE_BUILD_SECONDS, build_files, open_sync_session
from agent_bom.db.sync_common import OSV_APPLICATION_ECOSYSTEMS, _update_sync_meta
from agent_bom.models import Package
from agent_bom.scanners import package_coverage
from agent_bom.vuln_freshness import compute_freshness, local_osv_is_scoped

REPO_ROOT = Path(__file__).resolve().parents[1]


def _pragma(conn: sqlite3.Connection, name: str) -> object:
    return conn.execute(f"PRAGMA {name}").fetchone()[0]


def _stub_kev(seen: list[dict], db_path: Path):
    """A source that records what the database looks like while the sync runs."""

    def sync(conn: sqlite3.Connection, url: str | None = None) -> int:
        seen.append(
            {
                "target_exists": db_path.exists(),
                "synchronous": _pragma(conn, "synchronous"),
                "journal_mode": _pragma(conn, "journal_mode"),
                "cache_size": _pragma(conn, "cache_size"),
                "wal_autocheckpoint": _pragma(conn, "wal_autocheckpoint"),
            }
        )
        conn.execute("INSERT INTO kev_entries(cve_id) VALUES ('CVE-2021-0001')")
        _update_sync_meta(conn, "kev", 1, {})
        return 1

    return sync


@pytest.mark.real_vuln_db_sync
def test_cold_sync_builds_aside_without_fsyncs_and_publishes_a_wal_database(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "db" / "vulns.db"
    seen: list[dict] = []
    monkeypatch.setattr(sync_module, "sync_kev", _stub_kev(seen, db_path))

    assert sync_module.sync_db(path=db_path, sources=["kev"]) == {"kev": 1}

    assert seen[0]["target_exists"] is False
    assert (seen[0]["synchronous"], seen[0]["journal_mode"], seen[0]["cache_size"]) == (0, "memory", -262144)
    assert build_files(db_path) == []
    conn = sqlite3.connect(db_path)
    try:
        assert _pragma(conn, "journal_mode") == "wal"
        assert conn.execute("SELECT cve_id FROM kev_entries").fetchall() == [("CVE-2021-0001",)]
        assert conn.execute("SELECT source FROM sync_meta").fetchall() == [("kev",)]
    finally:
        conn.close()
    assert sorted(path.name for path in db_path.parent.iterdir()) == ["vulns.db"]
    if os.name == "posix":
        assert db_path.stat().st_mode & 0o777 == 0o600


@pytest.mark.real_vuln_db_sync
def test_existing_database_is_updated_in_place_with_crash_safe_settings(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "vulns.db"
    init_db(db_path).close()
    inode = db_path.stat().st_ino
    seen: list[dict] = []
    monkeypatch.setattr(sync_module, "sync_kev", _stub_kev(seen, db_path))

    sync_module.sync_db(path=db_path, sources=["kev"])

    assert seen[0]["target_exists"] is True
    assert seen[0]["journal_mode"] == "wal"
    assert seen[0]["synchronous"] == 1
    assert seen[0]["wal_autocheckpoint"] == 16384
    assert db_path.stat().st_ino == inode


@pytest.mark.real_vuln_db_sync
def test_failed_source_still_publishes_the_sources_that_completed(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "vulns.db"
    monkeypatch.setattr(sync_module, "sync_kev", _stub_kev([], db_path))

    def broken_nvd(*_args, **_kwargs) -> int:
        raise ConnectionError("feed unreachable")

    monkeypatch.setattr(sync_module, "_sync_nvd_source", broken_nvd)

    with pytest.raises(ConnectionError):
        sync_module.sync_db(path=db_path, sources=["kev", "nvd"])

    conn = sqlite3.connect(db_path)
    try:
        assert conn.execute("SELECT source FROM sync_meta").fetchall() == [("kev",)]
    finally:
        conn.close()
    assert build_files(db_path) == []


@pytest.mark.real_vuln_db_sync
@pytest.mark.parametrize("failure", [sqlite3.OperationalError("disk I/O error"), KeyboardInterrupt()])
def test_database_error_or_interrupt_never_publishes_a_build(tmp_path, monkeypatch, failure: BaseException) -> None:
    db_path = tmp_path / "vulns.db"

    def failing(*_args, **_kwargs) -> int:
        raise failure

    monkeypatch.setattr(sync_module, "sync_kev", failing)

    with pytest.raises(type(failure)):
        sync_module.sync_db(path=db_path, sources=["kev"])

    assert not db_path.exists()
    assert build_files(db_path) == []


def test_a_build_abandoned_by_a_crash_is_swept_but_a_live_one_is_kept(tmp_path) -> None:
    db_path = tmp_path / "vulns.db"
    abandoned = tmp_path / "vulns.db.build-old"
    live = tmp_path / "vulns.db.build-live"
    abandoned.write_bytes(b"x")
    live.write_bytes(b"x")
    long_ago = time.time() - STALE_BUILD_SECONDS - 60
    os.utime(abandoned, (long_ago, long_ago))

    session = open_sync_session(db_path)
    session.close(None)

    assert not abandoned.exists()
    assert live.exists()


def test_publish_clears_stale_sidecars_of_a_deleted_database(tmp_path) -> None:
    db_path = tmp_path / "vulns.db"
    stale_wal = tmp_path / "vulns.db-wal"
    stale_wal.write_bytes(b"not this database's log")

    session = open_sync_session(db_path)
    session.close(None)

    assert not stale_wal.exists()
    conn = sqlite3.connect(db_path)
    try:
        assert conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    finally:
        conn.close()


def _refresh(tmp_path, monkeypatch, *, db_path: Path, scope: str = "application", sources: str | None = None) -> dict:
    captured: dict = {}

    def fake_sync(**kwargs) -> dict:
        captured.update(kwargs)
        progress = kwargs.get("progress")
        if progress:
            progress("kev", "start")
            progress("kev", "complete", 1650)
        return {}

    monkeypatch.setattr(sync_module, "sync_db", fake_sync)
    monkeypatch.setattr("agent_bom.db.schema.DB_PATH", db_path)
    monkeypatch.delenv("AGENT_BOM_NVD_TIME_BUDGET_SECONDS", raising=False)
    opts = SimpleNamespace(
        inventory=None,
        extra_inventories=(),
        demo=False,
        offline=False,
        no_scan=False,
        dry_run=False,
        quiet=False,
        auto_update_db=True,
        db_sources=sources,
        db_osv_scope=scope,
    )
    console = Console(file=open(tmp_path / "console.txt", "w", encoding="utf-8"), width=200, force_terminal=False)
    st = SimpleNamespace(con=console, vuln_freshness=None, pre_scan_step_timings={})
    preflight._refresh_vuln_data(opts, st)
    console.file.close()
    captured["console"] = (tmp_path / "console.txt").read_text(encoding="utf-8")
    captured["timings"] = st.pre_scan_step_timings
    return captured


def _synced_db(path: Path, coverage: dict, *, age_hours: int = 48) -> None:
    conn = init_db(path)
    _update_sync_meta(conn, "osv", 10, coverage)
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(time.time() - age_hours * 3600))
    conn.execute("UPDATE sync_meta SET last_synced = ?", (stamp,))
    conn.commit()
    conn.close()


def test_cold_refresh_scopes_osv_caps_nvd_and_reports_per_source_timing(tmp_path, monkeypatch) -> None:
    captured = _refresh(tmp_path, monkeypatch, db_path=tmp_path / "absent.db")

    assert captured["osv_ecosystems"] == list(OSV_APPLICATION_ECOSYSTEMS)
    assert captured["nvd_time_budget"] == preflight.COLD_START_NVD_BUDGET_SECONDS
    assert re.search(r"kev: \d+\.\ds \(1,650 records\)", captured["console"])
    assert "db refresh" in captured["timings"]
    assert "db refresh kev" in captured["timings"]


def test_operator_nvd_budget_wins_over_the_cold_start_cap(tmp_path, monkeypatch) -> None:
    def refresh() -> dict:
        captured: dict = {}
        monkeypatch.setattr(sync_module, "sync_db", lambda **kw: captured.update(kw) or {})
        monkeypatch.setattr("agent_bom.db.schema.DB_PATH", tmp_path / "absent.db")
        monkeypatch.setenv("AGENT_BOM_NVD_TIME_BUDGET_SECONDS", "900")
        opts = SimpleNamespace(
            inventory=None,
            extra_inventories=(),
            demo=False,
            offline=False,
            no_scan=False,
            dry_run=False,
            quiet=True,
            auto_update_db=True,
            db_sources=None,
            db_osv_scope="all",
        )
        preflight._refresh_vuln_data(opts, SimpleNamespace(con=Console(quiet=True), vuln_freshness=None, pre_scan_step_timings={}))
        return captured

    assert refresh()["nvd_time_budget"] is None


def test_warm_refresh_keeps_the_default_nvd_budget(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "vulns.db"
    _synced_db(db_path, {"coverage": "selected_ecosystems", "ecosystems": ["PyPI"]})

    captured = _refresh(tmp_path, monkeypatch, db_path=db_path)

    assert captured["osv_ecosystems"] == list(OSV_APPLICATION_ECOSYSTEMS)
    assert captured["nvd_time_budget"] is None


def test_a_full_database_is_never_silently_narrowed_by_a_scoped_refresh(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "vulns.db"
    _synced_db(db_path, {"coverage": "all_ecosystems"})

    captured = _refresh(tmp_path, monkeypatch, db_path=db_path)

    assert captured["osv_ecosystems"] is None


def test_default_scope_keeps_the_full_archive(tmp_path, monkeypatch) -> None:
    captured = _refresh(tmp_path, monkeypatch, db_path=tmp_path / "absent.db", scope="all")

    assert captured["osv_ecosystems"] is None


def test_scoped_local_hit_outside_the_scope_is_still_asked_of_live_osv(tmp_path, monkeypatch) -> None:
    """A scoped archive can hold cross-ecosystem rows; one hit must not pass for the whole ecosystem."""
    db_path = tmp_path / "vulns.db"
    _synced_db(db_path, {"coverage": "selected_ecosystems", "ecosystems": ["PyPI"]}, age_hours=0)
    monkeypatch.setattr("agent_bom.db.schema.DB_PATH", db_path)
    monkeypatch.setattr(package_coverage, "local_db_untrusted", lambda **_kw: False)
    hex_pkg = Package(name="plug", version="1.0.0", ecosystem="hex")
    pypi_pkg = Package(name="django", version="3.2.25", ecosystem="pypi")
    held = {package_coverage._package_db_key(hex_pkg), package_coverage._package_db_key(pypi_pkg)}

    targets, covered = package_coverage._select_osv_targets([hex_pkg, pypi_pkg], False, [], held, [])

    assert targets == [hex_pkg]
    assert covered == {"pypi"}


def test_full_database_local_hit_still_stands_alone(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "vulns.db"
    _synced_db(db_path, {"coverage": "all_ecosystems"}, age_hours=0)
    monkeypatch.setattr("agent_bom.db.schema.DB_PATH", db_path)
    monkeypatch.setattr(package_coverage, "local_db_untrusted", lambda **_kw: False)
    hex_pkg = Package(name="plug", version="1.0.0", ecosystem="hex")

    targets, _covered = package_coverage._select_osv_targets([hex_pkg], False, [], {package_coverage._package_db_key(hex_pkg)}, [])

    assert targets == []
    assert local_osv_is_scoped() is False


def test_freshness_discloses_the_osv_scope(tmp_path) -> None:
    db_path = tmp_path / "vulns.db"
    _synced_db(db_path, {"coverage": "selected_ecosystems", "ecosystems": ["PyPI", "npm"]}, age_hours=0)

    freshness = compute_freshness(db_path=db_path)

    assert freshness.osv_scope == ["PyPI", "npm"]
    assert freshness.to_dict()["osv_scope"] == ["PyPI", "npm"]
    assert "OSV archive scoped to PyPI, npm; other ecosystems are checked live" in freshness.summary_line()


def test_freshness_of_a_full_database_claims_no_scope(tmp_path) -> None:
    db_path = tmp_path / "vulns.db"
    _synced_db(db_path, {"coverage": "all_ecosystems"}, age_hours=0)

    freshness = compute_freshness(db_path=db_path)

    assert freshness.osv_scope == []
    assert "osv_scope" not in freshness.to_dict()
    assert "scoped" not in freshness.summary_line()


def test_application_scope_holds_every_flat_ecosystem_the_scanner_resolves() -> None:
    from agent_bom.scanners.package_matching import ECOSYSTEM_MAP

    os_ecosystems = {"Debian", "Alpine"}
    assert set(ECOSYSTEM_MAP.values()) - os_ecosystems <= set(OSV_APPLICATION_ECOSYSTEMS)


def _action() -> dict:
    return yaml.safe_load((REPO_ROOT / "action.yml").read_text(encoding="utf-8"))


def _step(name: str) -> dict:
    return next(step for step in _action()["runs"]["steps"] if step.get("name") == name)


def test_action_defaults_to_the_application_scope_and_keys_the_cache_by_it() -> None:
    action = _action()

    assert action["inputs"]["vuln-db-scope"]["default"] == "application"
    cache = _step("Cache agent-bom vulnerability database")["with"]
    assert "inputs.vuln-db-scope" in cache["key"]
    assert "inputs.vuln-db-scope" in cache["restore-keys"]
    # A key shared with older full databases would restore one and keep paying for it.
    assert cache["key"].startswith("agent-bom-vulndb-v2-")
    assert cache["restore-keys"].startswith("agent-bom-vulndb-v2-")


def test_action_forwards_the_scope_only_with_the_refresh_and_validates_it() -> None:
    run = _step("Run agent-bom")["run"]

    assert 'ARGS+=(--auto-update-db --db-osv-scope "$DB_OSV_SCOPE")' in run
    assert "vuln-db-scope must be one of: application, full" in run


def test_action_mcp_gate_stays_online_for_ecosystems_a_scoped_database_lacks() -> None:
    step = _step("MCP gate")

    assert step["env"]["INPUT_VULN_DB_SCOPE"] == "${{ inputs.vuln-db-scope }}"
    assert 'if [ "$INPUT_AUTO_UPDATE_DB" = "true" ] && [ "$INPUT_VULN_DB_SCOPE" = "full" ]; then' in step["run"]


def test_action_install_from_source_says_it_needs_this_repository_as_the_workspace() -> None:
    description = _action()["inputs"]["install-from-source"]["description"]

    assert "workspace" in description
    assert "this repository" in description


_NOTED = {"partial_sources": [{"source": "NVD", "reason": "time_budget"}], "osv_scope": ["PyPI", "npm"]}


def _run_properties(report) -> dict:
    from agent_bom.output.sarif_common import _sarif_run_properties

    return _sarif_run_properties(report, SimpleNamespace(outcome=SimpleNamespace(value="complete")))


def test_sarif_run_carries_the_data_coverage_notes() -> None:
    from agent_bom.models import AIBOMReport

    properties = _run_properties(AIBOMReport(agents=[], blast_radii=[], vuln_data_freshness=_NOTED))

    assert properties["vuln_data_partial_sources"] == _NOTED["partial_sources"]
    assert properties["vuln_data_osv_scope"] == ["PyPI", "npm"]


def test_sarif_run_without_notes_adds_no_properties() -> None:
    from agent_bom.models import AIBOMReport

    properties = _run_properties(AIBOMReport(agents=[], blast_radii=[]))

    assert "vuln_data_partial_sources" not in properties
    assert "vuln_data_osv_scope" not in properties


@pytest.mark.parametrize(
    "data",
    [
        {"vuln_data_freshness": _NOTED},
        {"runs": [{"properties": {"vuln_data_partial_sources": _NOTED["partial_sources"], "vuln_data_osv_scope": _NOTED["osv_scope"]}}]},
    ],
)
def test_job_summary_and_comment_state_the_data_coverage(data: dict) -> None:
    from scripts.action_report import data_coverage_lines, render_comment, render_summary

    notes = data_coverage_lines(data)
    summary = render_summary([], exit_code="0", scan_type="scan", result_file="r.sarif", data_notes=notes)
    comment = render_comment([], exit_code="0", data_notes=notes)

    for rendered in (summary, comment):
        assert "NVD sync is partial (time_budget); it resumes at the next refresh" in rendered
        assert "Local OSV data covers PyPI, npm; other ecosystems were checked live" in rendered


def test_a_report_with_whole_data_gets_no_coverage_notes() -> None:
    from scripts.action_report import data_coverage_lines

    assert data_coverage_lines({"vuln_data_freshness": {"mode": "local"}}) == []
    assert data_coverage_lines({"runs": [{"properties": {}}]}) == []


def test_permissions_doc_lists_the_bulk_archive_host_the_refresh_reads() -> None:
    doc = (REPO_ROOT / "docs" / "PERMISSIONS.md").read_text(encoding="utf-8")

    assert "https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip" in doc
