"""Plan review for the Postgres hot reads (no database: plans are fixtures)."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from scripts.perf.postgres_hot_reads import HotReadIds, hot_reads
from scripts.perf.postgres_plans import plan_nodes, review_plan

ROOT = Path(__file__).resolve().parents[1]

TENANT_TABLES = frozenset({"graph_edges", "report_jobs", "scan_jobs"})
INDEXES = {
    "idx_graph_edges_tenant_scan_source": {"table": "graph_edges", "leading": "tenant_id", "primary": False},
    "idx_report_claim": {"table": "report_jobs", "leading": "status", "primary": False},
    "report_jobs_pkey": {"table": "report_jobs", "leading": "job_id", "primary": True},
    "alembic_version_pkc": {"table": "alembic_version", "leading": "version_num", "primary": True},
    "idx_jobs_team_created": {"table": "scan_jobs", "leading": "team_id", "primary": False},
}


def _doc(plan: dict, execution_ms: float = 1.5) -> list[dict]:
    return [{"Plan": plan, "Planning Time": 0.2, "Execution Time": execution_ms}]


def test_plan_nodes_walks_every_child() -> None:
    plan = {"Node Type": "Limit", "Plans": [{"Node Type": "Sort", "Plans": [{"Node Type": "Seq Scan", "Relation Name": "t"}]}]}
    assert [node["Node Type"] for node in plan_nodes(plan)] == ["Limit", "Sort", "Seq Scan"]


def test_tenant_leading_index_scan_is_clean() -> None:
    plan = {
        "Node Type": "Index Scan",
        "Relation Name": "graph_edges",
        "Index Name": "idx_graph_edges_tenant_scan_source",
        "Actual Rows": 12,
        "Actual Loops": 1,
        "Shared Hit Blocks": 7,
        "Shared Read Blocks": 1,
    }
    review = review_plan(_doc(plan), tenant_tables=TENANT_TABLES, indexes=INDEXES)

    assert review["flags"] == []
    assert review["execution_ms"] == 1.5
    assert review["shared_hit_blocks"] == 7 and review["shared_read_blocks"] == 1
    assert review["scans"] == [{"node": "Index Scan", "relation": "graph_edges", "index": "idx_graph_edges_tenant_scan_source", "rows": 12}]


def test_large_sequential_scan_on_a_tenant_table_is_flagged() -> None:
    plan = {
        "Node Type": "Seq Scan",
        "Relation Name": "graph_edges",
        "Actual Rows": 40,
        "Rows Removed by Filter": 9_960,
        "Actual Loops": 1,
    }
    review = review_plan(_doc(plan), tenant_tables=TENANT_TABLES, indexes=INDEXES)
    assert review["flags"] == ["seq_scan graph_edges examined 10000 rows"]


def test_small_sequential_scan_is_not_flagged() -> None:
    plan = {"Node Type": "Seq Scan", "Relation Name": "graph_edges", "Actual Rows": 3, "Rows Removed by Filter": 4, "Actual Loops": 1}
    assert review_plan(_doc(plan), tenant_tables=TENANT_TABLES, indexes=INDEXES)["flags"] == []


def test_loops_multiply_examined_rows() -> None:
    plan = {"Node Type": "Seq Scan", "Relation Name": "scan_jobs", "Actual Rows": 1, "Rows Removed by Filter": 99, "Actual Loops": 20}
    review = review_plan(_doc(plan), tenant_tables=TENANT_TABLES, indexes=INDEXES)
    assert review["flags"] == ["seq_scan scan_jobs examined 2000 rows"]


def test_index_not_led_by_tenant_is_flagged_for_tenant_tables_only() -> None:
    plan = {
        "Node Type": "Nested Loop",
        "Plans": [
            {
                "Node Type": "Index Scan",
                "Relation Name": "report_jobs",
                "Index Name": "idx_report_claim",
                "Actual Rows": 1,
                "Actual Loops": 1,
            },
            {"Node Type": "Bitmap Index Scan", "Index Name": "report_jobs_pkey", "Actual Rows": 1, "Actual Loops": 1},
            {"Node Type": "Index Scan", "Relation Name": "alembic_version", "Index Name": "alembic_version_pkc", "Actual Rows": 1},
        ],
    }
    review = review_plan(_doc(plan), tenant_tables=TENANT_TABLES, indexes=INDEXES)
    # The primary key on a globally unique job id is a point lookup, not a tenant leak:
    # it is reported for review but distinguished from a range index.
    assert review["flags"] == ["index idx_report_claim on report_jobs leads with status, not the tenant column"]
    assert review["notes"] == ["primary-key lookup report_jobs_pkey leads with job_id"]


def test_team_id_counts_as_the_tenant_column() -> None:
    plan = {
        "Node Type": "Index Scan",
        "Relation Name": "scan_jobs",
        "Index Name": "idx_jobs_team_created",
        "Actual Rows": 3,
        "Actual Loops": 1,
    }
    assert review_plan(_doc(plan), tenant_tables=TENANT_TABLES, indexes=INDEXES)["flags"] == []


IDS = HotReadIds(
    tenant_id="default",
    scan_id="scan-1",
    job_id="job-1",
    report_id="report-1",
    node_id="agent:a",
    scope_hash="scope",
    finding_keys=("k1", "k2"),
)


def test_hot_reads_cover_findings_assets_graph_adjacency_and_report_lookup() -> None:
    reads = {read.name: read for read in hot_reads(IDS)}
    assert set(reads) == {
        "findings_lifecycle_live",
        "findings_lifecycle_payload",
        "findings_job_result",
        "findings_hub_page",
        "inventory_assets_page",
        "graph_snapshot_nodes",
        "graph_snapshot_edges",
        "graph_adjacency_out",
        "graph_adjacency_in",
        "graph_node_search",
        "attack_paths_load",
        "jobs_page",
        "retained_report_lookup",
    }
    for read in reads.values():
        assert read.sql.count("%s") == len(read.params), read.name
        assert "default" in read.params, read.name
        assert re.search(r"\b(tenant_id|team_id)\s*=\s*%s", read.sql), read.name
    assert "gns.search_text LIKE %s" in reads["graph_node_search"].sql
    assert 'source_id COLLATE "C" = %s' in reads["graph_adjacency_out"].sql
    assert 'target_id COLLATE "C" = %s' in reads["graph_adjacency_in"].sql
    assert "FROM assets WHERE" in reads["inventory_assets_page"].sql
    assert "FROM report_jobs WHERE job_id = %s AND tenant_id = %s" in reads["retained_report_lookup"].sql


def test_graph_explain_node_search_uses_the_application_predicate() -> None:
    from scripts.run_graph_postgres_explain import explain_queries

    sql = explain_queries(tenant_id="t", scan_id="s", old_scan_id="o", source_node="a", detail_node="d")["node_search"]
    assert "gns.search_text LIKE" in sql and "LOWER(gns.search_text)" not in sql


def test_explain_cli_writes_hot_read_sql_in_dry_run(tmp_path: Path) -> None:
    summary = tmp_path / "explain.json"
    command = [
        sys.executable,
        "scripts/run_graph_postgres_explain.py",
        "--dry-run",
        "--hot-reads",
        "--output-dir",
        str(tmp_path / "explain"),
        "--summary-output",
        str(summary),
    ]
    result = subprocess.run(command, cwd=ROOT, check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    payload = json.loads(summary.read_text())
    assert payload["hot_reads"]["status"] == "sql_only_not_measured"
    assert (tmp_path / "explain" / "hot-reads" / "retained_report_lookup.sql").exists()


def test_hot_read_summary_keeps_flags_per_read() -> None:
    from scripts.run_graph_postgres_explain import summarize_hot_reads

    review = {
        "ids": {"tenant_id": "default"},
        "reviews": {
            "a": {"endpoint": "GET /x", "execution_ms": 1.0, "flags": ["seq_scan t examined 5000 rows"], "notes": [], "scans": []},
            "b": {"endpoint": "GET /y", "execution_ms": 2.0, "flags": [], "notes": ["primary-key lookup"], "scans": []},
        },
        "plans": {"a": [], "b": []},
    }
    summary = summarize_hot_reads(review)
    assert summary["status"] == "explain_analyze_measured"
    assert summary["flagged"] == {"a": ["seq_scan t examined 5000 rows"]}
    assert summary["reads"]["b"]["execution_ms"] == 2.0
    assert "plans" not in summary
