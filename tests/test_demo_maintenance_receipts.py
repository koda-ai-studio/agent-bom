"""Demo maintenance preserves evidence and avoids rebuilding a current estate."""

from unittest.mock import Mock

from agent_bom.demo_estate import bootstrap


def test_current_estate_skips_composition(monkeypatch):
    from agent_bom.api import stores
    from agent_bom.demo_estate import enterprise_composition

    monkeypatch.setattr(bootstrap, "demo_estate_enabled", lambda: True)
    monkeypatch.setattr(bootstrap, "demo_estate_force_reseed", lambda: False)
    monkeypatch.setattr(bootstrap, "_demo_seed_block_reason", lambda *a: None)
    monkeypatch.setattr(bootstrap, "_tenant_has_demo_jobs", lambda *a: True)
    monkeypatch.setattr(stores, "_get_graph_store", Mock)
    monkeypatch.setattr(stores, "_get_store", Mock)
    monkeypatch.setattr(bootstrap, "_existing_snapshots", lambda *a: [])
    monkeypatch.setattr(bootstrap, "_showcase_seed_is_current", lambda *a: True)
    monkeypatch.setattr(
        bootstrap,
        "get_demo_estate_bootstrap_status",
        lambda **kw: {"enterprise_contract": {"content_hash": "recorded"}, "estate_seed_marker": list(bootstrap.DEMO_ESTATE_SEED_MARKER)},
    )
    monkeypatch.setattr(bootstrap, "refresh_demo_daily_evidence", lambda **kw: {})
    build = Mock(side_effect=RuntimeError("must not rebuild"))
    monkeypatch.setattr(enterprise_composition, "build_demo_estate", build)
    summary = bootstrap.maybe_bootstrap_demo_estate()
    assert build.call_count == 0
    assert summary["enterprise_contract"]["content_hash"] == "recorded"


def test_demo_intel_path_never_defaults_to_operator_database(tmp_path, monkeypatch):
    from agent_bom.intel_lookup import resolve_intel_db_path

    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_DEMO_STATE_DIR", str(tmp_path))
    monkeypatch.delenv("AGENT_BOM_DB_PATH", raising=False)
    assert resolve_intel_db_path() == tmp_path / "db" / "vulns.db"


def test_demo_feed_receipts_are_partial_synthetic_and_idempotent(tmp_path, monkeypatch):
    from agent_bom.demo_estate.feed_receipts import seed_demo_feed_receipts
    from agent_bom.intel_lookup import list_intel_sources

    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_DEMO_STATE_DIR", str(tmp_path))
    monkeypatch.delenv("AGENT_BOM_DB_PATH", raising=False)
    assert seed_demo_feed_receipts() == 3
    assert seed_demo_feed_receipts() == 0
    sources = list_intel_sources()["sources"]
    runs = [s["feed_run"] for s in sources if s["feed_run"]["last_synced"]]
    assert len(runs) == 3
    assert all(r["status"] == "partial" and r["record_count"] > 0 for r in runs)
    assert all(r["validation_status"] == "synthetic_demo_fixture" for r in runs)
    assert all(r["partial_reason"] == "synthetic_demo_fixture_not_live_sync" for r in runs)


def test_demo_feed_receipts_refuse_explicit_operator_path(tmp_path, monkeypatch):
    from agent_bom.demo_estate.feed_receipts import seed_demo_feed_receipts

    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "demo"))
    monkeypatch.setenv("AGENT_BOM_DEMO_STATE_DIR", str(tmp_path / "demo"))
    operator = tmp_path / "operator.db"
    monkeypatch.setenv("AGENT_BOM_DB_PATH", str(operator))
    assert seed_demo_feed_receipts() == 0
    assert not operator.exists()


def test_demo_feed_receipts_preserve_existing_non_demo_evidence(tmp_path, monkeypatch):
    from agent_bom.db.schema import init_db
    from agent_bom.demo_estate.feed_receipts import seed_demo_feed_receipts

    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_DEMO_STATE_DIR", str(tmp_path))
    monkeypatch.delenv("AGENT_BOM_DB_PATH", raising=False)
    conn = init_db(tmp_path / "db" / "vulns.db")
    try:
        conn.execute("INSERT INTO vulns(id, summary, severity, source) VALUES ('CVE-2099-0001', 'preserved', 'high', 'nvd')")
        conn.commit()
        assert seed_demo_feed_receipts() == 0
        assert conn.execute("SELECT count(*) FROM sync_meta").fetchone()[0] == 0
        assert conn.execute("SELECT id, source FROM vulns").fetchone()["id"] == "CVE-2099-0001"
    finally:
        conn.close()
