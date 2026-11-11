"""The Postgres statements behind the workflow's hot reads, with live parameters.

The statement set was taken from ``pg_stat_statements`` while the workflow
harness served ``/v1/findings``, ``/v1/inventory/assets``, ``/v1/graph``,
``/v1/graph/attack-paths``, ``/v1/jobs`` and ``/v1/reports/{id}`` against a
200-agent Postgres store. Where the application builds the SQL from shared
constants, those constants are imported so a change there changes the plan
being reviewed.

Each statement is explained under the application role with ``app.tenant_id``
set, so row-level-security predicates are part of the plan.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

EXPLAIN_PREFIX = "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "


@dataclass(frozen=True)
class HotRead:
    name: str
    endpoint: str
    sql: str
    params: tuple[Any, ...]


@dataclass(frozen=True)
class HotReadIds:
    tenant_id: str
    scan_id: str
    job_id: str
    report_id: str
    node_id: str
    scope_hash: str
    finding_keys: tuple[str, ...]


def resolve_ids(conn: Any, tenant_id: str) -> HotReadIds:
    """Newest graph snapshot, scan job, report, an agent node and one lifecycle scope for ``tenant_id``."""

    def one(sql: str, params: tuple[Any, ...]) -> Any:
        row = conn.execute(sql, params).fetchone()
        return row[0] if row else ""

    scan_id = one("SELECT scan_id FROM graph_snapshots WHERE tenant_id = %s ORDER BY created_at DESC, scan_id DESC LIMIT 1", (tenant_id,))
    scope_hash = one(
        "SELECT scope_hash FROM finding_lifecycle WHERE tenant_id = %s GROUP BY scope_hash ORDER BY COUNT(*) DESC LIMIT 1", (tenant_id,)
    )
    keys = conn.execute(
        "SELECT finding_key FROM finding_lifecycle WHERE tenant_id = %s AND scope_hash = %s ORDER BY finding_key LIMIT 23",
        (tenant_id, scope_hash),
    ).fetchall()
    return HotReadIds(
        tenant_id=tenant_id,
        scan_id=str(scan_id),
        job_id=str(
            one("SELECT job_id FROM scan_jobs WHERE team_id = %s AND status = 'done' ORDER BY created_at DESC LIMIT 1", (tenant_id,))
        ),
        report_id=str(one("SELECT job_id FROM report_jobs WHERE tenant_id = %s ORDER BY created_at DESC LIMIT 1", (tenant_id,))),
        node_id=str(
            one(
                "SELECT id FROM graph_nodes WHERE tenant_id = %s AND scan_id = %s AND entity_type = 'agent' ORDER BY id LIMIT 1",
                (tenant_id, scan_id),
            )
        ),
        scope_hash=str(scope_hash),
        finding_keys=tuple(str(row[0]) for row in keys) or ("",),
    )


def _inventory_page(ids: HotReadIds) -> HotRead:
    from agent_bom.api.graph_store import _FINDING_ENTITY_TYPE_VALUES
    from agent_bom.api.inventory_service import _ASSET_TYPE_VALUES
    from agent_bom.api.postgres_graph_inventory import _inventory_cte

    finding_types = sorted(_FINDING_ENTITY_TYPE_VALUES)
    asset_types = sorted(_ASSET_TYPE_VALUES)
    cte = _inventory_cte(finding_marks=",".join("%s" for _ in finding_types), asset_marks=",".join("%s" for _ in asset_types))
    scope = (ids.tenant_id, ids.scan_id)
    sql = (
        cte + " SELECT id, entity_type, label, category_uid, class_uid, type_uid, status, risk_score, severity, severity_id,"
        " first_seen, last_seen, attributes, compliance_tags, data_sources, dimensions"
        " FROM assets WHERE 1 = 1 ORDER BY severity_id DESC, risk_score DESC, label ASC, id ASC LIMIT %s OFFSET %s"
    )
    return HotRead(
        "inventory_assets_page",
        "GET /v1/inventory/assets",
        sql,
        (*scope, *finding_types, *scope, *finding_types, *scope, *asset_types, 101, 0),
    )


def _adjacency(ids: HotReadIds, column: str) -> HotRead:
    """``incident_edge_page``'s per-direction seek, as the Postgres store binds it."""
    from agent_bom.graph.adjacency_page import EDGE_COLUMNS

    varying = "target_id" if column == "source_id" else "source_id"
    sql = (
        f"SELECT {EDGE_COLUMNS} FROM graph_edges WHERE tenant_id = %s AND scan_id = %s "
        f'AND {column} COLLATE "C" = %s ORDER BY {varying} COLLATE "C", relationship COLLATE "C" LIMIT %s'
    )
    name = "graph_adjacency_out" if column == "source_id" else "graph_adjacency_in"
    return HotRead(name, "GET /v1/graph/incident-edges", sql, (ids.tenant_id, ids.scan_id, ids.node_id, 25))


def hot_reads(ids: HotReadIds) -> list[HotRead]:
    """Every hot-read statement, bound to ``ids``."""
    from agent_bom.api.storage.finding_lifecycle import _STATE_COLUMNS
    from agent_bom.api.storage.job_payload_cache import _VERSION
    from agent_bom.db.graph_store_schema import ATTACK_PATH_ORDER

    tenant, scan = ids.tenant_id, ids.scan_id
    key_marks = ",".join("%s" for _ in ids.finding_keys)
    return [
        HotRead(
            "findings_lifecycle_live",
            "GET /v1/findings",
            f"SELECT {_STATE_COLUMNS} FROM finding_lifecycle WHERE tenant_id=%s AND status<>'resolved'",
            (tenant,),
        ),
        HotRead(
            "findings_lifecycle_payload",
            "GET /v1/findings",
            f"SELECT finding_key,payload FROM finding_lifecycle WHERE tenant_id=%s AND scope_hash=%s AND finding_key IN ({key_marks})",
            (tenant, ids.scope_hash, *ids.finding_keys),
        ),
        HotRead(
            "findings_job_result",
            "GET /v1/findings",
            f"SELECT team_id, {_VERSION}, data::text FROM scan_jobs WHERE job_id = %s AND team_id = %s LIMIT 1",
            (ids.job_id, tenant),
        ),
        HotRead(
            "findings_hub_page",
            "GET /v1/findings",
            "SELECT canonical_id, first_seen, last_seen, status, severity, severity_rank, cvss_score, effective_reach_score,"
            " scan_count, resolved_at, reopened_at, updated_at, payload, ledger_finding_id, ledger_ordinal"
            " FROM hub_findings_current WHERE tenant_id = %s AND last_seen >= %s AND origin = %s AND status IN (%s, %s)"
            ' ORDER BY effective_reach_score DESC, last_seen COLLATE "C" DESC, canonical_id COLLATE "C" LIMIT %s',
            (tenant, "1970-01-01T00:00:00Z", "scan", "open", "reopened", 101),
        ),
        _inventory_page(ids),
        HotRead(
            "graph_snapshot_nodes",
            "GET /v1/graph (current-graph load)",
            "SELECT id, entity_type, label, category_uid, class_uid, type_uid, status, risk_score, severity, severity_id,"
            " first_seen, last_seen, attributes, compliance_tags, data_sources, dimensions"
            " FROM graph_nodes WHERE tenant_id = %s AND scan_id = %s ORDER BY id",
            (tenant, scan),
        ),
        HotRead(
            "graph_snapshot_edges",
            "GET /v1/graph (current-graph load)",
            "SELECT source_id, target_id, relationship, direction, weight, traversable, first_seen, last_seen, valid_from,"
            " valid_to, confidence, provenance, source_scan_id, source_run_id, evidence, activity_id, scan_id"
            " FROM graph_edges WHERE tenant_id = %s AND scan_id = %s",
            (tenant, scan),
        ),
        *(_adjacency(ids, column) for column in ("source_id", "target_id")),
        HotRead(
            "graph_node_search",
            "GET /v1/graph/search",
            "SELECT COUNT(*) FROM graph_node_search gns JOIN graph_nodes gn"
            " ON gn.id = gns.node_id AND gn.scan_id = gns.scan_id AND gn.tenant_id = gns.tenant_id"
            " WHERE gns.tenant_id = %s AND gns.scan_id = %s AND gns.search_text LIKE %s ESCAPE '\\'",
            (tenant, scan, "%agent%"),
        ),
        HotRead(
            "attack_paths_load",
            "GET /v1/graph/attack-paths",
            "SELECT source_node, target_node, path_nodes, path_edges, composite_risk, summary FROM attack_paths"
            f" WHERE tenant_id = %s AND scan_id = %s ORDER BY {ATTACK_PATH_ORDER}",
            (tenant, scan),
        ),
        HotRead(
            "jobs_page",
            "GET /v1/jobs",
            "SELECT job_id, team_id, status, created_at, completed_at FROM scan_jobs WHERE team_id = %s"
            " ORDER BY created_at DESC LIMIT %s OFFSET %s",
            (tenant, 25, 0),
        ),
        HotRead(
            "retained_report_lookup",
            "GET /v1/reports/{job_id}",
            "SELECT data, status, started_at, completed_at, error, job_id, tenant_id FROM report_jobs WHERE job_id = %s AND tenant_id = %s",
            (ids.report_id, tenant),
        ),
    ]


def explain(conn: Any, read: HotRead, tenant_id: str) -> list[dict[str, Any]]:
    """Run one ``EXPLAIN (ANALYZE, BUFFERS)`` as the tenant, inside a transaction that is rolled back."""
    with conn.transaction(force_rollback=True):
        conn.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant_id,))
        row = conn.execute(EXPLAIN_PREFIX + read.sql, read.params).fetchone()
    document = row[0]
    return document if isinstance(document, list) else list(document)


def review_hot_reads(conn: Any, tenant_id: str) -> dict[str, Any]:
    """Explain and review every hot read; returns the bound ids, one review per read and the raw plans."""
    from scripts.perf.postgres_plans import INDEX_METADATA_SQL, TENANT_TABLES_SQL, review_plan

    ids = resolve_ids(conn, tenant_id)
    indexes = {str(r[0]): {"table": str(r[1]), "leading": r[2], "primary": bool(r[3])} for r in conn.execute(INDEX_METADATA_SQL)}
    tenant_tables = frozenset(str(r[0]) for r in conn.execute(TENANT_TABLES_SQL))
    reviews: dict[str, Any] = {}
    plans: dict[str, Any] = {}
    for read in hot_reads(ids):
        document = explain(conn, read, tenant_id)
        plans[read.name] = document
        reviews[read.name] = {"endpoint": read.endpoint, **review_plan(document, tenant_tables=tenant_tables, indexes=indexes)}
    bound = {**ids.__dict__, "finding_keys": len(ids.finding_keys)}
    return {"ids": bound, "reviews": reviews, "plans": plans}
