"""KEV history is an observed issue count; legacy snapshots stay unknown."""

import sqlite3
from dataclasses import replace

import pytest

from agent_bom.api.trend_comparison import public_trend_point
from agent_bom.api.trend_recording import trend_point_from_scan_result
from agent_bom.baseline import InMemoryTrendStore, SQLiteTrendStore, TrendPoint


def _point(**kwargs):
    return TrendPoint(
        timestamp="2026-10-19T00:00:00Z",
        total_vulns=3,
        critical=1,
        high=2,
        medium=0,
        low=0,
        posture_score=70,
        posture_grade="C",
        scan_id="scan-1",
        **kwargs,
    )


def _result(**kwargs):
    return {"scan_id": "scan-1", "generated_at": "2026-10-19T00:00:00Z", "posture_scorecard": {"grade": "C", "score": 70}, **kwargs}


def test_legacy_point_is_unknown_not_zero():
    point = _point()
    assert point.to_dict()["kev_count"] is None
    assert public_trend_point(point, None)["kev_count"] is None


@pytest.mark.parametrize("invalid", [-1, True, 1.5, "2"])
def test_kev_count_rejects_invalid_values(invalid):
    with pytest.raises(ValueError, match="kev_count"):
        _point(kev_count=invalid)


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_kev_snapshot_replay_and_tenant_isolation(tmp_path, backend):
    store = InMemoryTrendStore() if backend == "memory" else SQLiteTrendStore(str(tmp_path / "trends.db"))
    a = _point(tenant_id="a", kev_count=2)
    store.record(a)
    store.record(replace(a, kev_count=1))
    store.record(_point(tenant_id="b", kev_count=0))
    assert [p.kev_count for p in store.get_history(tenant_id="a")] == [1]
    assert [p.kev_count for p in store.get_history(tenant_id="b")] == [0]
    if backend == "sqlite":
        store = SQLiteTrendStore(str(tmp_path / "trends.db"))
        assert [p.kev_count for p in store.get_history(tenant_id="a")] == [1]
        with pytest.raises(sqlite3.IntegrityError):
            store._conn.execute("UPDATE trend_history SET kev_count=-1")


def test_sqlite_migrates_legacy_rows_without_inventing_measurement(tmp_path):
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE trend_history (id INTEGER PRIMARY KEY, timestamp TEXT, total_vulns INTEGER, "
            "critical INTEGER, high INTEGER, medium INTEGER, low INTEGER, posture_score REAL, posture_grade TEXT)"
        )
        conn.execute("INSERT INTO trend_history VALUES (1,'2026-10-18T00:00:00Z',1,0,1,0,0,90,'A')")
    store = SQLiteTrendStore(str(path))
    assert store.get_history()[0].kev_count is None
    assert store._conn.execute("SELECT version FROM control_plane_schema_versions WHERE component='trend_history'").fetchone()[0] == 3


def test_records_active_kev_issue_occurrences_from_canonical_findings():
    result = _result(
        findings=[
            {"id": "a", "is_kev": True},
            {"id": "a", "is_kev": True},
            {"id": "b", "is_kev": True},
            {"id": "c", "is_kev": True, "suppressed": True},
            {"id": "d", "is_kev": False},
        ],
        packages=[{"vulnerabilities": [{"is_kev": True}] * 9}],
    )
    point = trend_point_from_scan_result(result, tenant_id="a")
    assert point.kev_count == 2


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({}, None),
        ({"packages": []}, 0),
        ({"packages": [{"vulnerabilities": None}]}, None),
        ({"packages": [{"vulnerabilities": "bad"}]}, None),
        ({"packages": [{"vulnerabilities": []}]}, 0),
        ({"packages": [None]}, None),
        ({"packages": [{"name": "legacy"}]}, None),
        ({"findings": []}, 0),
        ({"findings": [{"id": "old"}]}, None),
        ({"findings": [{"id": "bad", "is_kev": "false"}]}, None),
        ({"findings": [{"is_kev": False}]}, 0),
        ({"packages": [{"vulnerabilities": [{"is_kev": True}, {"is_kev": False}]}]}, 1),
        ({"blast_radius": [{"is_kev": True}, {"is_kev": True, "suppressed": True}]}, 1),
        ({"blast_radii": [{"cisa_kev": True}, {"cisa_kev": False}]}, 1),
        ({"findings": [{"is_kev": True}, {"id": "unknown"}]}, None),
    ],
)
def test_kev_count_fallbacks_and_unknown_flags(payload, expected):
    point = trend_point_from_scan_result(_result(**payload), tenant_id="a")
    assert point.kev_count == expected
