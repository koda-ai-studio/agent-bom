"""Persist existing Databricks discovery and security checks through saved connections."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from uuid import uuid4

from agent_bom.api.connection_store import CloudConnectionRecord
from agent_bom.api.models import ScanJob
from agent_bom.cloud.connection_broker import broker_session
from agent_bom.evidence.scan_run import ScanIssue
from agent_bom.models import AIBOMReport


def run_databricks_connection_scan(
    record: CloudConnectionRecord, tenant_id: str, *, persist: Callable[..., str], queued_job: ScanJob | None = None
) -> dict[str, Any]:
    """Use one scoped client; partial/denied reads never establish clean coverage."""
    from agent_bom.cloud.databricks import discover
    from agent_bom.cloud.databricks_security import run_security_checks

    if record.tenant_id != tenant_id:
        raise ValueError("Connection tenant does not match scan tenant.")
    client = broker_session(record)
    agents, warnings = discover(host=record.role_ref, workspace_client=client)
    security = run_security_checks(host=record.role_ref, workspace_client=client).to_dict()
    report = AIBOMReport(agents=agents, blast_radii=[], findings=[], scan_id=queued_job.job_id if queued_job else str(uuid4()))
    report.scan_sources = ["cloud_connection", "cloud:databricks"]
    report.databricks_security_data = security
    if warnings or any(row.get("status") in {"error", "skip", "skipped"} for row in security.get("checks", [])):
        report.scan_run.add_issue(
            ScanIssue(
                code="databricks_partial",
                stage="discovery",
                source="databricks",
                message="Some workspace reads were unavailable or denied. Inspect security check coverage and provider permissions.",
            )
        )
    scan_id = persist(record, tenant_id, report, queued_job=queued_job)
    return {
        "schema_version": "cloud.connections.scan.v1",
        "connection_id": record.id,
        "tenant_id": tenant_id,
        "provider": "databricks",
        "scan_id": scan_id,
        "inventory": {"provider": "databricks", "agent_count": len(agents)},
        "security_checks": {key: security.get(key) for key in ("passed", "failed", "total", "pass_rate")},
        "audit_metadata": {
            "read_only": True,
            "writes_performed": False,
            "note": (
                "Workspace discovery and vendor security best-practices checks use the stored workspace credential; "
                "these are not CIS checks."
            ),
        },
    }
