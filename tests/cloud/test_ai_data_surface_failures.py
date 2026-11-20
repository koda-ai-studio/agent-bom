"""Databricks, vector DB and Snowflake AI surfaces: failed reads are classified, never empty."""

from types import SimpleNamespace

import pytest

from agent_bom.cloud import databricks, snowflake_ai_surfaces, vector_db
from agent_bom.cloud.databricks_connection import databricks_read_warning

PRIVATE = "private-marker acct-123 object MY_DB.SECRET_SCHEMA"


# ── Databricks ───────────────────────────────────────────────────────────


def _endpoint(name):
    return SimpleNamespace(name=name, state=SimpleNamespace(ready=SimpleNamespace(value="READY")))


def test_serving_endpoint_conversion_failure_keeps_later_endpoints(monkeypatch):
    real = databricks._serving_endpoint_agent

    def convert(ep, host):
        if ep.name == "bad":
            raise KeyError(PRIVATE)
        return real(ep, host)

    monkeypatch.setattr(databricks, "_serving_endpoint_agent", convert)
    ws = SimpleNamespace(serving_endpoints=SimpleNamespace(list=lambda: iter([_endpoint("a"), _endpoint("bad"), _endpoint("c")])))
    warnings: list[str] = []
    agents = databricks._discover_serving_agents(ws, "https://fixture.cloud.databricks.com", warnings, PermissionError)
    assert len(agents) == 2
    assert len(warnings) == 1 and warnings[0].startswith("databricks:serving-endpoints:unavailable:")
    assert PRIVATE not in warnings[0]


def test_cluster_conversion_failure_keeps_later_clusters(monkeypatch):
    clusters = [SimpleNamespace(cluster_id=c, cluster_name=c, state="RUNNING") for c in ("a", "bad", "c")]

    def convert(ws, cluster, host, warnings, gpus):
        if cluster.cluster_id == "bad":
            raise TypeError(PRIVATE)
        return SimpleNamespace(name=cluster.cluster_id)

    monkeypatch.setattr(databricks, "_cluster_agent", convert)
    monkeypatch.setattr(databricks, "databricks_node_gpu_counts", lambda _ws: {})
    ws = SimpleNamespace(clusters=SimpleNamespace(list=lambda: iter(clusters)))
    warnings: list[str] = []
    agents = databricks._discover_cluster_agents(ws, "https://fixture.cloud.databricks.com", warnings, PermissionError)
    assert [a.name for a in agents] == ["a", "c"]
    assert len(warnings) == 1 and warnings[0].startswith("databricks:clusters:unavailable:")


def test_databricks_sdk_errors_are_classified():
    errors = pytest.importorskip("databricks.sdk.errors")
    assert databricks_read_warning("clusters", errors.PermissionDenied(PRIVATE)).startswith("databricks:clusters:denied:")
    assert databricks_read_warning("clusters", errors.Unauthenticated(PRIVATE)).startswith("databricks:clusters:denied:")
    assert databricks_read_warning("clusters", errors.TooManyRequests(PRIVATE)).startswith("databricks:clusters:throttled:")
    warning = databricks_read_warning("clusters", RuntimeError(PRIVATE))
    assert warning.startswith("databricks:clusters:unavailable:") and PRIVATE not in warning


def test_listing_failure_is_classified_and_fixed_text():
    errors = pytest.importorskip("databricks.sdk.errors")

    def fail():
        raise errors.TooManyRequests(PRIVATE)

    ws = SimpleNamespace(serving_endpoints=SimpleNamespace(list=fail))
    warnings: list[str] = []
    assert databricks._discover_serving_agents(ws, "https://h", warnings, errors.PermissionDenied) == []
    assert warnings[0].startswith("databricks:serving-endpoints:throttled:") and PRIVATE not in warnings[0]


# ── Vector DB ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("db_type", ["qdrant", "weaviate", "chroma", "milvus"])
@pytest.mark.parametrize("body", [b"not json", b'"a string"', b"[1, 2]", b'{"result": 5, "data": 5, "classes": 5}'])
def test_unreadable_collection_listing_is_unknown_not_zero(db_type, body):
    if db_type == "chroma" and body == b"[1, 2]":
        pytest.skip("a JSON list is chroma's valid shape")
    assert vector_db._count_collections(db_type, body) is None
    assert vector_db._parse_version(db_type, body) == ""


def test_valid_empty_listing_is_zero():
    assert vector_db._count_collections("qdrant", b'{"result": {"collections": []}}') == 0
    assert vector_db._count_collections("chroma", b"[]") == 0


def test_check_marks_unreadable_exposed_collections(monkeypatch):
    monkeypatch.setattr(vector_db, "_port_open", lambda *a, **k: True)
    monkeypatch.setattr(vector_db, "_http_get", lambda *a, **k: (200, b"<html>not json</html>"))
    monkeypatch.setattr(vector_db, "_is_loopback", lambda host: False)
    monkeypatch.setattr(vector_db, "_validate_probe_target", lambda host, port: None)
    result = vector_db.check_vector_db("qdrant", "203.0.113.9", 6333)
    assert result.requires_auth is False
    assert "collections_unverified" in result.risk_flags
    assert result.metadata.get("collection_count") == "unknown"


# ── Snowflake AI surfaces ────────────────────────────────────────────────


class FakeProgrammingError(Exception):
    def __init__(self, errno, sqlstate):
        super().__init__(PRIVATE)
        self.errno = errno
        self.sqlstate = sqlstate


class Cursor:
    def __init__(self, rows=None, error=None, columns=("name", "database_name", "schema_name")):
        self.rows, self.error = rows or [], error
        self.description = [(c,) for c in columns]

    def execute(self, *_a, **_k):
        if self.error:
            raise self.error

    def fetchall(self):
        return self.rows

    def close(self):
        pass


def conn(cursor):
    return SimpleNamespace(cursor=lambda: cursor)


@pytest.mark.parametrize(
    "error,status",
    [
        (FakeProgrammingError(3001, "42501"), "denied"),
        (FakeProgrammingError(2003, "02000"), "denied"),
        (FakeProgrammingError(390100, "28000"), "denied"),
        (FakeProgrammingError(1, "XX000"), "unavailable"),
        (RuntimeError(PRIVATE), "unavailable"),
    ],
)
def test_surface_read_failure_is_classified_fixed_text(error, status):
    agents, warnings = snowflake_ai_surfaces._discover_cortex_services(conn(Cursor(error=error)), "acct", None, None)
    assert agents == []
    assert len(warnings) == 1
    assert warnings[0].startswith(f"snowflake:cortex-search:{status}:")
    assert "acct-123" not in warnings[0] and "SECRET_SCHEMA" not in warnings[0]


def test_malformed_row_keeps_neighbors():
    rows = [("svc1", "DB", "S"), ({"x": PRIVATE}, "DB", "S"), ("svc3", "DB", "S")]
    agents, warnings = snowflake_ai_surfaces._discover_cortex_services(conn(Cursor(rows=rows)), "acct", None, None)
    assert [a.name for a in agents] == ["cortex:svc1", "cortex:svc3"]
    assert len(warnings) == 1 and warnings[0].startswith("snowflake:cortex-search:unavailable:")


def test_streamlit_malformed_row_keeps_neighbors():
    rows = [("app1", "DB", "S"), (None, ["x"], "S"), ("app3", "DB", "S")]
    agents, warnings = snowflake_ai_surfaces._discover_streamlit_apps(conn(Cursor(rows=rows)), "acct")
    assert [a.name for a in agents] == ["streamlit:app1", "streamlit:app3"]
    assert len(warnings) == 1 and warnings[0].startswith("snowflake:streamlit:unavailable:")
