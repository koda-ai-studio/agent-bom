"""Brokered database inventory and posture collection."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from agent_bom.api.connection_scan_reports import _logger, _mark_connection_report_sources, _persist_connection_report, _scan_audit_metadata
from agent_bom.api.connection_store import CloudConnectionRecord

if TYPE_CHECKING:
    from agent_bom.api.models import ScanJob


def _parse_scope_list(value: Any) -> list[str]:
    """Parse an operator-declared schema/table scope (list or comma string)."""
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return []


def _run_database_connection_scan(
    record: CloudConnectionRecord,
    tenant_id: str,
    *,
    queued_job: ScanJob | None = None,
) -> dict[str, Any]:
    """Broker a read-only database connection and run bounded DSPM content sampling.

    Opens one brokered read-only ``psycopg`` connection (connect-once — the stored
    connection secret is the only credential; nothing is prompted per-action) and,
    when database content sampling is explicitly enabled
    (``AGENT_BOM_DSPM_DB_SAMPLING``), runs :func:`scan_database_content` over the
    caller-scoped schemas. Only redacted type/count/location evidence
    (``agent-bom.dspm.database_scan.v1``) is persisted — never raw rows or values.
    Coverage states (executed/partial/skipped/unevaluable/failed) stay explicit so
    a denied/unreadable table is never reported clean. Read-only throughout.
    """
    from agent_bom.cloud.inventory_summary import _summarize_inventory_payload
    from agent_bom.models import AIBOMReport

    account, sampling_enabled, classification, coverage_note, inventory = _database_inventory(record)

    # Content-confirmed sensitive tables become canonical DSPM findings so they
    # flow through the findings spine, exports, and graph correlation the same way
    # every other finding does. Redacted evidence only; unevaluable/clean tables
    # emit nothing (never a false "clean").
    from agent_bom.cloud.dspm_findings import build_inventory_dspm_findings

    account_ref = f"database:{account}" if account else None
    dspm_findings = build_inventory_dspm_findings(inventory, provider="database", account_ref=account_ref)

    report = AIBOMReport(
        agents=[],
        blast_radii=[],
        findings=dspm_findings,
        scan_id=queued_job.job_id if queued_job is not None else str(uuid.uuid4()),
    )
    _mark_connection_report_sources(report, "database")
    report.cloud_inventory_data = inventory
    scan_id = _persist_connection_report(record, tenant_id, report, queued_job=queued_job)

    dspm_summary: dict[str, Any] = {
        "sampling_enabled": sampling_enabled,
        "data_sensitivity": (classification or {}).get("data_sensitivity", "unevaluable"),
        "tables_total": (classification or {}).get("tables_total", 0),
        "tables_sampled": (classification or {}).get("tables_sampled", 0),
        "tables_by_state": (classification or {}).get("tables_by_state", {}),
        "findings_by_type": (classification or {}).get("findings_by_type", {}),
        "findings_emitted": len(dspm_findings),
        "scan_status": (classification or {}).get("status", "skipped"),
    }
    if coverage_note:
        dspm_summary["note"] = coverage_note

    return {
        "schema_version": "cloud.connections.scan.v1",
        "connection_id": record.id,
        "tenant_id": tenant_id,
        "provider": "database",
        "scan_id": scan_id,
        "inventory": _summarize_inventory_payload("database", inventory),
        "dspm": dspm_summary,
        "audit_metadata": _scan_audit_metadata(
            "Scan ran against a read-only database connection brokered from the stored connection "
            "(default_transaction_read_only=on). Only bounded SELECT sampling ran; no row is mutated, "
            "and only redacted data-type/count/location evidence is stored — never raw values."
        ),
    }


def _database_inventory(record: CloudConnectionRecord) -> tuple[str, bool, dict[str, Any] | None, str, dict[str, Any]]:
    """Read explicitly enabled database samples and retain honest coverage states."""
    from agent_bom.cloud.connection_broker import broker_session
    from agent_bom.cloud.db_content_scan import scan_database_content
    from agent_bom.cloud.db_data_classifier import db_sampling_enabled

    account = str(record.auth_params.get("account") or record.auth_params.get("database") or "").strip()
    schemas = _parse_scope_list(record.auth_params.get("schemas"))
    include_tables = _parse_scope_list(record.auth_params.get("include_tables"))
    publicly_accessible = str(record.auth_params.get("publicly_accessible") or "").strip().lower() in {"1", "true", "yes", "on"}
    engine = str(record.auth_params.get("engine") or "postgres").strip() or "postgres"
    # Source is operator-chosen display metadata only — never a secret / DSN.
    display = record.display_name.strip() or record.id[:8]
    source = f"database://{display}"

    sampling_enabled = db_sampling_enabled()
    classification: dict[str, Any] | None = None
    coverage_note = ""
    if sampling_enabled:
        conn = broker_session(record, session_name=f"agent-bom-scan-{record.id[:8]}")
        try:
            result = scan_database_content(
                conn,
                source=source,
                schemas=schemas or None,
                include_tables=include_tables or None,
            )
            classification = result.to_dict()
        finally:
            try:
                conn.close()
            except Exception:  # noqa: BLE001 - close best-effort; never mask the scan result
                _logger.debug("Database broker connection close failed for connection %s", record.id)
    else:
        # Sampling is opt-in (parity with S3/GCS). Without it we do NOT claim the
        # database is clean — coverage is explicitly "skipped/unevaluable".
        coverage_note = (
            "Database content sampling is opt-in and was not enabled "
            "(set AGENT_BOM_DSPM_DB_SAMPLING=1). No content was read; sensitivity is unevaluable, not clean."
        )

    db_record: dict[str, Any] = {
        "name": display,
        "engine": engine,
        "publicly_accessible": publicly_accessible,
        "account_id": account or None,
    }
    if classification is not None:
        db_record["content_classification"] = classification
    inventory = {
        "provider": "database",
        "status": "ok",
        "account_id": account or None,
        "dspm_databases": [db_record],
    }

    return account, sampling_enabled, classification, coverage_note, inventory
