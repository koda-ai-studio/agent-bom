"""Brokered Azure, GCP, Snowflake and Databricks scan execution."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from agent_bom.api.connection_scan_reports import (
    _cis_summary,
    _logger,
    _mark_connection_report_sources,
    _persist_connection_report,
    _scan_audit_metadata,
)
from agent_bom.api.connection_store import CloudConnectionRecord, connection_org_fanout_enabled

if TYPE_CHECKING:
    from agent_bom.api.models import ScanJob


def _run_azure_connection_scan(
    record: CloudConnectionRecord,
    tenant_id: str,
    *,
    queued_job: ScanJob | None = None,
) -> dict[str, Any]:
    """Broker an Azure read-only credential and run inventory + CIS.

    Uses the brokered ``ClientSecretCredential`` (Reader role) and the
    ``subscription_id`` from the connection's ``auth_params`` so the same
    ``azure_inventory.discover_inventory`` and Azure CIS ``run_benchmark`` the
    sibling cloud routes use run against the customer subscription. Read-only.
    """
    from agent_bom.cloud import azure_inventory
    from agent_bom.cloud.azure_cis_benchmark import run_benchmark as run_azure_cis
    from agent_bom.cloud.connection_broker import broker_session
    from agent_bom.cloud.inventory_summary import _summarize_inventory_payload
    from agent_bom.models import AIBOMReport

    credential = broker_session(record, session_name=f"agent-bom-scan-{record.id[:8]}")
    subscription_id = str(record.auth_params.get("subscription_id") or "").strip() or None

    if connection_org_fanout_enabled(record):
        inventory_payload: Any = azure_inventory.discover_all_subscription_inventories(credential=credential, force=True)
    else:
        inventory_payload = azure_inventory.discover_inventory(subscription_id=subscription_id, credential=credential, force=True)
    cis_report = run_azure_cis(subscription_id=subscription_id, credential=credential)
    cis_dict = cis_report.to_dict()

    # Content-confirmed sensitive Azure Blob containers (when blob sampling is
    # enabled) become canonical DSPM findings on the report's findings spine.
    from agent_bom.cloud.dspm_findings import build_inventory_dspm_findings

    account_ref = f"azure:{subscription_id}" if subscription_id else None
    primary_for_dspm = inventory_payload[0] if isinstance(inventory_payload, list) and inventory_payload else inventory_payload
    dspm_findings = build_inventory_dspm_findings(
        primary_for_dspm if isinstance(primary_for_dspm, dict) else {},
        provider="azure",
        account_ref=account_ref,
    )

    report = AIBOMReport(
        agents=[],
        blast_radii=[],
        findings=dspm_findings,
        scan_id=queued_job.job_id if queued_job is not None else str(uuid.uuid4()),
    )
    _mark_connection_report_sources(report, "azure")
    report.cloud_inventory_data = inventory_payload
    report.azure_cis_benchmark_data = cis_dict
    scan_id = _persist_connection_report(record, tenant_id, report, queued_job=queued_job)

    if isinstance(inventory_payload, list):
        inventory_summary: dict[str, Any] = {
            "provider": "azure",
            "status": "ok",
            "account_count": len(inventory_payload),
            "accounts": [_summarize_inventory_payload("azure", item) for item in inventory_payload if isinstance(item, dict)],
        }
    else:
        inventory_summary = _summarize_inventory_payload("azure", inventory_payload)

    return {
        "schema_version": "cloud.connections.scan.v1",
        "connection_id": record.id,
        "tenant_id": tenant_id,
        "provider": "azure",
        "scan_id": scan_id,
        "inventory": inventory_summary,
        "cis_benchmark": _cis_summary(cis_dict),
        "audit_metadata": _scan_audit_metadata(
            "Scan ran against a read-only Azure Reader credential brokered from the stored connection. "
            "Inventory + CIS are read-only; no resource is mutated and no secret value is returned."
        ),
    }


def _run_gcp_connection_scan(
    record: CloudConnectionRecord,
    tenant_id: str,
    *,
    queued_job: ScanJob | None = None,
) -> dict[str, Any]:
    """Broker GCP read-only service-account credentials and run inventory + CIS.

    Uses the brokered ``service_account.Credentials`` (cloud-platform.read-only
    scope) and the ``project_id`` from the connection's ``auth_params`` so the
    same ``gcp_inventory.discover_inventory`` and GCP CIS ``run_benchmark`` the
    sibling cloud routes use run against the customer project. Read-only.
    """
    from agent_bom.cloud import gcp_inventory
    from agent_bom.cloud.connection_broker import broker_session
    from agent_bom.cloud.gcp_cis_benchmark import run_benchmark as run_gcp_cis
    from agent_bom.cloud.inventory_summary import _summarize_inventory_payload
    from agent_bom.models import AIBOMReport

    credentials = broker_session(record, session_name=f"agent-bom-scan-{record.id[:8]}")
    project_id = str(record.auth_params.get("project_id") or "").strip() or None

    if connection_org_fanout_enabled(record):
        inventory_payload: Any = gcp_inventory.discover_all_project_inventories(credentials=credentials, force=True)
    else:
        inventory_payload = gcp_inventory.discover_inventory(project_id=project_id, credentials=credentials, force=True)
    cis_report = run_gcp_cis(project_id=project_id, credentials=credentials)
    cis_dict = cis_report.to_dict()

    report = AIBOMReport(
        agents=[],
        blast_radii=[],
        findings=[],
        scan_id=queued_job.job_id if queued_job is not None else str(uuid.uuid4()),
    )
    _mark_connection_report_sources(report, "gcp")
    report.cloud_inventory_data = inventory_payload
    report.gcp_cis_benchmark_data = cis_dict
    scan_id = _persist_connection_report(record, tenant_id, report, queued_job=queued_job)

    if isinstance(inventory_payload, list):
        inventory_summary: dict[str, Any] = {
            "provider": "gcp",
            "status": "ok",
            "account_count": len(inventory_payload),
            "accounts": [_summarize_inventory_payload("gcp", item) for item in inventory_payload if isinstance(item, dict)],
        }
    else:
        inventory_summary = _summarize_inventory_payload("gcp", inventory_payload)

    return {
        "schema_version": "cloud.connections.scan.v1",
        "connection_id": record.id,
        "tenant_id": tenant_id,
        "provider": "gcp",
        "scan_id": scan_id,
        "inventory": inventory_summary,
        "cis_benchmark": _cis_summary(cis_dict),
        "audit_metadata": _scan_audit_metadata(
            "Scan ran against read-only GCP service-account credentials (cloud-platform.read-only) brokered from the "
            "stored connection. Inventory + CIS are read-only; no resource is mutated and no secret value is returned."
        ),
    }


def _snowflake_estate_summary(report: Any, agent_count: int) -> dict[str, Any]:
    """Non-secret count roll-up of the swept Snowflake estate for the scan envelope.

    Mirrors the AWS/Azure/GCP ``_summarize_inventory_payload`` shape: object
    metadata counts only (warehouses, databases, schemas, roles, users,
    accounts) — never object contents or secrets.
    """
    services = getattr(report, "snowflake_services_data", None) or {}
    object_graph = getattr(report, "snowflake_object_graph_data", None) or {}
    organization = services.get("organization") or {}

    # Roles / users land as graph nodes from the roles/users lists AND from the
    # grants + role_memberships that reference them, so count the distinct union
    # the same way the graph builder materializes the nodes.
    def _name(item: Any) -> str:
        return str(item.get("name") if isinstance(item, dict) else item or "").strip()

    roles: set[str] = {_name(r) for r in (object_graph.get("roles") or [])}
    users: set[str] = {_name(u) for u in (object_graph.get("users") or [])}
    for grant in object_graph.get("grants") or []:
        if isinstance(grant, dict) and grant.get("role"):
            roles.add(str(grant["role"]).strip())
    for membership in object_graph.get("role_memberships") or []:
        if not isinstance(membership, dict):
            continue
        if membership.get("role"):
            roles.add(str(membership["role"]).strip())
        if membership.get("user"):
            users.add(str(membership["user"]).strip())
    roles.discard("")
    users.discard("")

    return {
        "provider": "snowflake",
        "status": "ok",
        "agent_count": agent_count,
        "warehouse_count": len(services.get("warehouses") or []),
        "database_count": len(services.get("databases") or []),
        "schema_count": len(services.get("schemas") or []),
        "role_count": len(roles),
        "user_count": len(users),
        "account_count": len(organization.get("accounts") or []),
    }


def _run_snowflake_connection_scan(
    record: CloudConnectionRecord,
    tenant_id: str,
    *,
    queued_job: ScanJob | None = None,
) -> dict[str, Any]:
    """Broker a Snowflake read-only connection and run discovery + estate sweep + CIS.

    Opens one brokered connection and threads it into ``snowflake.discover``
    (agents), ``enrich_report_with_snowflake_estate`` (accounts / warehouses /
    databases / roles / users → typed graph nodes, parity with the AWS/Azure/GCP
    connection scans), and Snowflake CIS ``run_benchmark`` so a single read-only
    session backs the whole scan; the broker's connection is closed here once all
    have run. The estate sweep is best-effort: a failure still returns agent
    discovery + CIS. Read-only.
    """
    from agent_bom.cloud import snowflake as snowflake_discovery
    from agent_bom.cloud.connection_broker import broker_session
    from agent_bom.cloud.snowflake_cis_benchmark import run_benchmark as run_snowflake_cis
    from agent_bom.models import AIBOMReport

    # The account rides on the stored connection (role_ref = "account" or
    # "account/user"), not process env — pass it so the estate discoveries, which
    # gate on a resolvable account, run against this connection's account.
    account = (record.role_ref or "").partition("/")[0].strip() or None

    conn = broker_session(record, session_name=f"agent-bom-scan-{record.id[:8]}")
    try:
        agents, _warnings = snowflake_discovery.discover(conn=conn)
        cis_report = run_snowflake_cis(conn=conn)
        report = AIBOMReport(
            agents=agents,
            blast_radii=[],
            findings=[],
            scan_id=queued_job.job_id if queued_job is not None else str(uuid.uuid4()),
        )
        _mark_connection_report_sources(report, "snowflake")
        # Sweep the estate into the report's snowflake_*_data blocks so the graph
        # builder materializes accounts/warehouses/databases/roles/users the same
        # way AWS/Azure/GCP inventory is materialized. Best-effort — never fails
        # the scan; a raise here leaves agent discovery + CIS intact.
        try:
            snowflake_discovery.enrich_report_with_snowflake_estate(report, conn=conn, account=account)
        except Exception:  # noqa: BLE001 - estate sweep is best-effort; never mask the scan result
            _logger.warning(
                "Snowflake estate sweep failed for connection %s; returning agent discovery + CIS only",
                record.id,
                exc_info=False,
            )
    finally:
        # The broker connection is this function's to close (discover / CIS /
        # estate discoveries do not close an injected connection).
        try:
            conn.close()
        except Exception:  # noqa: BLE001 - close best-effort; never mask the scan result
            _logger.debug("Snowflake broker connection close failed for connection %s", record.id)
    cis_dict = cis_report.to_dict()

    inventory_summary = _snowflake_estate_summary(report, len(agents))
    report.cloud_inventory_data = inventory_summary
    report.snowflake_cis_benchmark_data = cis_dict
    scan_id = _persist_connection_report(record, tenant_id, report, queued_job=queued_job)

    return {
        "schema_version": "cloud.connections.scan.v1",
        "connection_id": record.id,
        "tenant_id": tenant_id,
        "provider": "snowflake",
        "scan_id": scan_id,
        "inventory": inventory_summary,
        "cis_benchmark": _cis_summary(cis_dict),
        "audit_metadata": _scan_audit_metadata(
            "Scan ran against a Snowflake connection brokered from the stored connection. "
            "Discovery, estate sweep, and CIS are read-only; no object is mutated and no secret value is returned."
        ),
    }


def _run_databricks_connection_scan(record: CloudConnectionRecord, tenant_id: str, *, queued_job: ScanJob | None = None) -> dict[str, Any]:
    from agent_bom.api.databricks_connection_scan import run_databricks_connection_scan

    return run_databricks_connection_scan(record, tenant_id, persist=_persist_connection_report, queued_job=queued_job)
