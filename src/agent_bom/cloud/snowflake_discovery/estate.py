"""Snowflake estate enrichment that folds every discovery lane into a scan report."""

from __future__ import annotations

import contextlib
import importlib
from typing import Any

from ._base import _borrowed_connection
from .identity import merge_live_identity_into_object_graph

_FACADE = "agent_bom.cloud.snowflake"


def _seams() -> Any:
    """Resolve patchable collaborators through the public facade at call time."""
    return importlib.import_module(_FACADE)


def _has_any(payload: dict[str, Any], *keys: str) -> bool:
    """``status == "ok"`` and at least one of *keys* is non-empty."""
    return payload.get("status") == "ok" and any(payload.get(key) for key in keys)


def _estate_object_graph(report: Any, account: str | None) -> None:
    # Object + dependency graph: tables/views → DATA_STORE nodes,
    # OBJECT_DEPENDENCIES → DEPENDS_ON lineage edges.
    #
    # The object graph's grants/memberships come from ACCOUNT_USAGE, which lags
    # 45min–2h, so a freshly-created role hierarchy is invisible. Overlay
    # zero-latency SHOW-based identity (current state) and prefer it over the
    # lagged rows so new users/roles/grants graph immediately. Best-effort.
    _sf_object_graph = _seams().discover_object_dependencies(account=account)
    try:
        _sf_live_identity = _seams().discover_identity_live(account=account)
        _sf_object_graph = merge_live_identity_into_object_graph(_sf_object_graph, _sf_live_identity)
    except Exception:  # noqa: BLE001 — live overlay is supplementary; never fail the object graph
        pass
    if _has_any(_sf_object_graph, "objects", "dependencies", "grants", "role_memberships", "users"):
        report.snowflake_object_graph_data = _sf_object_graph


def _estate_login_anomalies(report: Any, account: str | None) -> None:
    # Login anomalies: impossible travel, high distinct-IP, failed-login bursts.
    _sf_login_anomalies = _seams().discover_login_anomalies(account=account)
    if _has_any(_sf_login_anomalies, "findings"):
        report.snowflake_login_anomalies_data = _sf_login_anomalies


def _estate_exfil(report: Any, account: str | None) -> None:
    # Exfil graph: outbound shares, external stages, sensitivity-tagged objects.
    _sf_exfil = _seams().discover_data_exfil(account=account)
    if _has_any(_sf_exfil, "outbound_shares", "external_stages", "sensitive_objects"):
        report.snowflake_exfil_graph_data = _sf_exfil


def _estate_auth_posture(report: Any, account: str | None) -> None:
    # Auth posture: per-user MFA/key-pair/password matrix + network policies.
    _sf_auth = _seams().discover_auth_posture(account=account)
    if _has_any(_sf_auth, "users", "network_policies"):
        report.snowflake_auth_posture_data = _sf_auth


def _estate_services(report: Any, account: str | None) -> None:
    # Services: warehouses (compute) + database/schema containment hierarchy.
    _sf_services = _seams().discover_snowflake_services(account=account)
    # Organization → Accounts roll-up (opt-in, ORGADMIN-gated). Carried on the
    # services payload under ``organization`` so the graph builder can parent
    # the account node(s) under the org without a new top-level report field.
    # A single account / missing ORGADMIN no-ops cleanly (non-ok status).
    try:
        _sf_org = _seams().discover_organization(account=account)
        if isinstance(_sf_org, dict) and _has_any(_sf_org, "accounts"):
            _sf_services["organization"] = _sf_org
    except Exception:  # noqa: BLE001 — org roll-up is supplementary; never fail the scan
        pass
    if _has_any(_sf_services, "warehouses", "databases", "schemas"):
        report.snowflake_services_data = _sf_services


def _estate_pipeline(report: Any, account: str | None) -> None:
    # Pipeline objects: tasks (automation), streams (CDC), pipes (ingestion).
    _sf_pipeline = _seams().discover_snowflake_pipeline(account=account)
    if _has_any(_sf_pipeline, "tasks", "streams", "pipes"):
        report.snowflake_pipeline_data = _sf_pipeline


def _estate_integrations(report: Any, account: str | None) -> None:
    # Integrations: storage/API/external-access/security/notification/catalog.
    _sf_integrations = _seams().discover_snowflake_integrations(account=account)
    if _has_any(_sf_integrations, "integrations"):
        report.snowflake_integrations_data = _sf_integrations


def _estate_external_data(report: Any, account: str | None) -> None:
    # External data: iceberg + external tables (open-table-format / query-in-place).
    _sf_external = _seams().discover_snowflake_external_data(account=account)
    if _has_any(_sf_external, "iceberg_tables", "external_tables"):
        report.snowflake_external_data_data = _sf_external


def _estate_governance(report: Any, account: str | None) -> None:
    # Governance: ACCESS_HISTORY reads + Cortex agent telemetry + derived risk
    # findings. De-duplicated against object-dependency and exfil discoveries.
    _sf_governance = _seams().discover_governance(account=account).to_dict()
    if any(_sf_governance.get(key) for key in ("access_records", "agent_usage", "findings", "cortex_agents", "cortex_events")):
        report.snowflake_governance_data = {
            "status": "ok",
            "account": _sf_governance.get("account", ""),
            "discovered_at": _sf_governance.get("discovered_at", ""),
            "summary": _sf_governance.get("summary", {}),
            "access_records": _sf_governance.get("access_records", []),
            "agent_usage": _sf_governance.get("agent_usage", []),
            "cortex_agents": _sf_governance.get("cortex_agents", []),
            "cortex_events": _sf_governance.get("cortex_events", []),
            "findings": _sf_governance.get("findings", []),
            "warnings": _sf_governance.get("warnings", []),
        }


def _estate_activity(report: Any, account: str | None) -> None:
    # Activity timeline: QUERY_HISTORY (365-day lookback) + AI observability
    # events. Summarized onto the account node.
    _sf_activity = _seams().discover_activity(account=account).to_dict()
    if (
        (_sf_activity.get("summary") or {}).get("total_queries")
        or _sf_activity.get("query_history")
        or _sf_activity.get("observability_events")
    ):
        _sf_activity["status"] = "ok"
        report.snowflake_activity_data = _sf_activity


def enrich_report_with_snowflake_estate(report: Any, *, conn: Any = None, account: str | None = None) -> None:
    """Run the Snowflake estate discoveries and attach their ``snowflake_*_data`` blocks.

    Mutates ``report`` in place, populating the ``snowflake_*_data`` fields the
    graph builder consumes (object graph, login anomalies, exfil graph, auth
    posture, services, pipeline, integrations, external data, governance,
    activity). Each discovery is best-effort: a connector raising never breaks
    the scan; that block is simply skipped.

    Unlike :func:`collect_cloud_inventory`, the Snowflake estate does not fit the
    single inventory-dict shape AWS / Azure / GCP contribute — it produces
    distinct ``snowflake_*_data`` blocks — so this parallel helper is the shared
    entry point for the ``--snowflake`` CLI path, the gated
    ``AGENT_BOM_SNOWFLAKE_INVENTORY`` enrichment path, and the brokered
    cloud-connection scan. Callers decide *whether* to run it; this function owns
    *what* it runs so every surface stays identical.

    Args:
        conn: Optional already-open Snowflake connection (e.g. brokered from a
            stored read-only connection). When supplied it is lent to every
            estate discovery for the duration of this call — they reuse it
            instead of building their own from env, and it is **not** closed here
            (the caller owns its lifecycle). This gives brokered cloud-connection
            scans the same estate sweep the AWS/Azure/GCP paths get, running
            against the per-tenant read-only credentials.
        account: Optional Snowflake account label. Estate discoveries gate on a
            resolvable account (``SNOWFLAKE_ACCOUNT`` env by default); pass it
            explicitly for the brokered path where the account rides on the
            stored connection rather than process env.
    """
    with contextlib.ExitStack() as _estate_stack:
        if conn is not None:
            _estate_stack.enter_context(_borrowed_connection(conn))
        for stage in (
            _estate_object_graph,
            _estate_login_anomalies,
            _estate_exfil,
            _estate_auth_posture,
            _estate_services,
            _estate_pipeline,
            _estate_integrations,
            _estate_external_data,
            _estate_governance,
            _estate_activity,
        ):
            try:
                stage(report, account)
            except Exception:  # noqa: BLE001 — each estate block is supplementary; never fail the scan
                pass
