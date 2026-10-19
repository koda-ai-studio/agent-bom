"""Brokered AWS inventory and CIS collection."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from agent_bom.api.connection_scan_reports import (
    _cis_summary,
    _mark_connection_report_sources,
    _persist_connection_report,
    _scan_audit_metadata,
)
from agent_bom.api.connection_store import CloudConnectionRecord, connection_org_fanout_enabled

if TYPE_CHECKING:
    from agent_bom.api.models import ScanJob


def _run_aws_connection_scan(
    record: CloudConnectionRecord,
    tenant_id: str,
    *,
    queued_job: ScanJob | None = None,
) -> dict[str, Any]:
    """Broker the connection into a read-only session and run inventory + CIS.

    Uses the shared AWS runners with the brokered session and persists through
    the existing scan/graph pipeline. Returns a non-secret scan summary.

    When ``connection_org_fanout_enabled(record)``, fans inventory (and CIS)
    across member accounts via the brokered management session — gated by the
    connection's ``inventory_scope``, not ``AGENT_BOM_AWS_ORG_INVENTORY``.
    """
    from agent_bom.cloud import aws_inventory, aws_organizations
    from agent_bom.cloud.connection_broker import broker_session
    from agent_bom.cloud.inventory_summary import _summarize_inventory_payload
    from agent_bom.models import AIBOMReport

    all_regions = aws_inventory.is_all_regions(record.regions)
    # For an all-regions scan the session has no single home region; discovery
    # enumerates the enabled set from the brokered credentials.
    region = None if all_regions else (record.regions[0] if record.regions else None)
    session = broker_session(record, session_name=f"agent-bom-scan-{record.id[:8]}")

    org_fanout = connection_org_fanout_enabled(record)
    inventory_payload, cis_report = _collect_aws_inventory_cis(record, session, all_regions, region, org_fanout)

    cis_dict = cis_report.to_dict()

    report = AIBOMReport(
        agents=[],
        blast_radii=[],
        findings=[],
        scan_id=queued_job.job_id if queued_job is not None else str(uuid.uuid4()),
    )
    _mark_connection_report_sources(report, "aws")
    report.cloud_inventory_data = inventory_payload
    report.cis_benchmark_data = cis_dict
    if org_fanout:
        org = aws_organizations.discover_organization(session=session, force=True)
        if isinstance(org, dict) and org.get("status") == "ok":
            payloads = inventory_payload if isinstance(inventory_payload, list) else []
            aws_payloads = [item for item in payloads if isinstance(item, dict)]
            if aws_payloads:
                org["account_scan"] = aws_organizations.summarize_account_scan(aws_payloads)
            report.aws_organization_data = org
    scan_id = _persist_connection_report(record, tenant_id, report, queued_job=queued_job)

    if isinstance(inventory_payload, list):
        inventory_summary: dict[str, Any] = {
            "provider": "aws",
            "status": "ok",
            "account_count": len(inventory_payload),
            "accounts": [_summarize_inventory_payload("aws", item) for item in inventory_payload if isinstance(item, dict)],
        }
    else:
        inventory_summary = _summarize_inventory_payload("aws", inventory_payload)

    audit_note = (
        "Org-scope connection scan: inventory + CIS fan out across member accounts via short-lived "
        "AssumeRole from the brokered management session. Read-only; no secret value is returned."
        if org_fanout
        else (
            "Scan ran against a short-lived read-only role assumed from the stored connection. "
            "Inventory + CIS are read-only; no resource is mutated and no secret value is returned."
        )
    )
    return {
        "schema_version": "cloud.connections.scan.v1",
        "connection_id": record.id,
        "tenant_id": tenant_id,
        "provider": "aws",
        "scan_id": scan_id,
        "inventory": inventory_summary,
        "cis_benchmark": _cis_summary(cis_dict),
        "audit_metadata": _scan_audit_metadata(audit_note),
    }


def _collect_aws_inventory_cis(
    record: CloudConnectionRecord, session: Any, all_regions: bool, region: str | None, org_fanout: bool
) -> tuple[Any, Any]:
    """Collect through the brokered session while bounding secret lifetime."""
    from agent_bom.api.connection_crypto import decrypt_secret
    from agent_bom.cloud import aws_inventory
    from agent_bom.cloud.aws_cis_benchmark import run_all_account_benchmarks
    from agent_bom.cloud.aws_cis_benchmark import run_benchmark as run_aws_cis
    from agent_bom.cloud.aws_cis_benchmark import run_benchmark_all_regions as run_aws_cis_all_regions

    external_id = ""
    member_role = ""
    try:
        if org_fanout:
            external_id = decrypt_secret(record.external_id_encrypted)
            member_role = str(record.auth_params.get("member_role_name") or "").strip() or "agent-bom-readonly"
            inventory_payloads = aws_inventory.discover_all_account_inventories(
                region=region,
                force=True,
                session=session,
                external_id=external_id,
                role_name=member_role,
            )
            inventory_payload: Any = inventory_payloads
            cis_report = run_all_account_benchmarks(
                session=session,
                external_id=external_id,
                role_name=member_role,
            )
        elif all_regions:
            inventory_payload = aws_inventory.discover_inventory_all_regions(force=True, session=session)
            cis_report = run_aws_cis_all_regions(region=region, session=session)
        else:
            inventory_payload = aws_inventory.discover_inventory(region=region, force=True, session=session)
            cis_report = run_aws_cis(region=region, session=session)
    finally:
        external_id = ""

    return inventory_payload, cis_report
