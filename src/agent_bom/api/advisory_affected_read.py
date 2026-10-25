"""Control-plane "affected assets" read and finding persistence for one advisory.

The advisory is the tenant's operator-declared record (by id or alias), else
the local feed record (OSV/GHSA/distro rows or NVD CPE ranges). It is matched
against the tenant's newest stored scan per target scope; nothing is rescanned.

Persistence puts operator-advisory and feed re-match results into the finding
store so they appear in ``/v1/findings``:

- One current-state row per (tenant, advisory, package occurrence); the hub
  store is keyed by ``(tenant_id, canonical_id)`` and the canonical id hashes
  the advisory id, the package stable id (or purl) and the asset.
- Rows are written with ``ingest_source = advisory:<id>`` and every write
  reconciles that source, so a package the newest scan no longer matches is
  resolved, and one a feed record now covers at scan time (the scan half of
  ``/v1/findings`` already lists it) is resolved too: superseded, never a
  duplicate.
- A possibly-affected (distro) row keeps ``severity = unknown`` and carries the
  advisory's severity as ``advisory_severity``: it is listed, never counted as
  a confirmed critical/high vulnerability in severity totals.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from agent_bom.api import compliance_hub_store
from agent_bom.api.findings_current import current_scan_jobs
from agent_bom.api.hub_ingest import hub_ingest_store_writes
from agent_bom.api.scan_finding_read import _completed_jobs_for_tenant
from agent_bom.api.stores import _get_operator_advisory_store
from agent_bom.db import schema
from agent_bom.db.operator_advisories import distro_verdicts
from agent_bom.db.schema import open_existing_db_readonly
from agent_bom.evidence.finding_response_fields import POSSIBLY_AFFECTED_STATUS
from agent_bom.scanners.advisory_affected import affected_answer, feed_advisory_from_db
from agent_bom.scanners.operator_advisory import OperatorAdvisory

_PERSISTED_VERDICTS = ("affected", "possibly_affected")


def tenant_reports(tenant_id: str) -> list[dict[str, Any]]:
    """The tenant's newest stored scan per target scope, with when each was observed."""
    reports = []
    for job in current_scan_jobs(_completed_jobs_for_tenant(tenant_id), since=None, scan_id=None):
        result = dict(job.result or {})
        result.setdefault("scan_id", job.job_id)
        result["scan_completed_at"] = job.completed_at or job.created_at
        reports.append(result)
    return reports


def _declared(tenant_id: str, advisory_id: str) -> OperatorAdvisory | None:
    wanted = advisory_id.strip().upper()
    for row in _get_operator_advisory_store().list(tenant_id):
        advisory = OperatorAdvisory.model_validate({k: v for k, v in row.items() if k != "updated_at"})
        if wanted in {identifier.upper() for identifier in advisory.identifiers}:
            return advisory
    return None


def _feed(advisory_id: str) -> OperatorAdvisory | None:
    if not schema.DB_PATH.exists():
        return None
    conn = open_existing_db_readonly(schema.DB_PATH)
    try:
        return feed_advisory_from_db(conn, advisory_id)
    finally:
        conn.close()


def resolve_advisory(tenant_id: str, advisory_id: str) -> tuple[OperatorAdvisory, str] | None:
    """``(advisory, source)``: the tenant's declaration wins over the local feed record."""
    declared = _declared(tenant_id, advisory_id)
    if declared is not None:
        return declared, "operator_advisory"
    feed = _feed(advisory_id)
    return (feed, "feed") if feed is not None else None


def tenant_affected_answer(tenant_id: str, advisory_id: str) -> dict[str, Any] | None:
    """The whole answer for one advisory over the tenant's stored scans; ``None`` when the id is unknown."""
    resolved = resolve_advisory(tenant_id, advisory_id)
    if resolved is None:
        return None
    advisory, source = resolved
    with distro_verdicts() as verdict:
        return affected_answer(advisory, tenant_reports(tenant_id), source=source, distro_verdict=verdict)


def _finding_payload(row: dict[str, Any], advisory: dict[str, Any]) -> dict[str, Any]:
    package = row["package"]
    possibly = row["verdict"] == "possibly_affected"
    payload: dict[str, Any] = {
        "id": row["id"],
        "canonical_id": row["id"],
        "origin": "bulk_ingest",
        "source": row["provenance"],
        "ingest_source": f"advisory:{advisory['id']}",
        "provenance": {"source": row["provenance"], "observed_via": "advisory_match", "scan_id": row["scan_id"]},
        "advisory_source": row["provenance"],
        "finding_type": "vulnerability",
        "cve_id": advisory["id"],
        "vulnerability_id": advisory["id"],
        "aliases": advisory["aliases"],
        "title": f"{advisory['id']}: {package.get('name', '')}",
        "summary": advisory["summary"],
        "severity": "unknown" if possibly else advisory["severity"],
        "advisory_severity": advisory["severity"],
        "verdict": row["verdict"],
        "verdict_reason": row["verdict_reason"],
        "verdict_detail": row["verdict_detail"],
        "package": package.get("name", ""),
        "package_version": row["installed_version"],
        "ecosystem": package.get("ecosystem", ""),
        "purl": package.get("purl"),
        "fixed_version": row["fixed_version"],
        "asset": {"asset_type": "mcp_server", "name": row["asset_label"], "identifier": row["graph"]["server_node_id"]},
        "affected_agents": [row["asset"].get("agent", "")],
        "affected_servers": [row["asset"].get("server", "")],
        "graph": row["graph"],
        "scan_id": row["scan_id"],
        "last_observed_scan_at": row["last_observed_at"],
    }
    if possibly:
        payload["status_detail"] = POSSIBLY_AFFECTED_STATUS
    return payload


def _write(tenant_id: str, payloads: list[dict[str, Any]], *, observed_at: str, batch_id: str, source: str) -> dict[str, Any]:
    store = compliance_hub_store.get_compliance_hub_store()
    return hub_ingest_store_writes(
        store, tenant_id, payloads, observed_at=observed_at, batch_id=batch_id, source=source, reconcile_absent=True
    )


def persist_affected_answer(tenant_id: str, answer: dict[str, Any], *, observed_at: str | None = None) -> dict[str, int]:
    """Write the answer's operator-advisory/feed rows into the finding store and retire the rest."""
    advisory = answer["advisory"]
    observed = observed_at or datetime.now(timezone.utc).isoformat()
    rows = [row for row in answer["rows"] if row["verdict"] in _PERSISTED_VERDICTS and row["provenance"] != "scan"]
    payloads = [_finding_payload(row, advisory) for row in rows]
    source = f"advisory:{advisory['id']}"
    batch_id = "advisory-" + hashlib.sha256(f"{source}|{answer['generation']}".encode()).hexdigest()[:24]
    result = _write(tenant_id, payloads, observed_at=observed, batch_id=batch_id, source=source)
    return {"persisted": len(payloads), "retired": int(result.get("reconciled") or 0)}


def retire_advisory_findings(tenant_id: str, advisory_id: str) -> int:
    """Resolve every open finding a retired advisory produced."""
    source = f"advisory:{advisory_id}"
    observed = datetime.now(timezone.utc).isoformat()
    result = _write(tenant_id, [], observed_at=observed, batch_id=f"retire-{source}", source=source)
    return int(result.get("reconciled") or 0)


MAX_PERSISTED_FEED_IDS = 500


def _has_rows(answer: dict[str, Any]) -> bool:
    return any(row["verdict"] in _PERSISTED_VERDICTS and row["provenance"] != "scan" for row in answer["rows"])


def persist_tenant_advisories(
    tenant_id: str,
    operator: list[OperatorAdvisory],
    feed: list[OperatorAdvisory],
    reports: list[dict[str, Any]],
    *,
    distro_verdict: Any = None,
    prior_feed_ids: list[str] | None = None,
    observed_at: str | None = None,
) -> list[str]:
    """Persist every declared advisory and each feed record with matches; returns the feed ids now persisted.

    Feed ids persisted earlier are re-evaluated so a rescan retires them; one the
    local DB can no longer resolve is kept (never silently resolved).
    """
    for advisory in operator:
        answer = affected_answer(advisory, reports, source="operator_advisory", distro_verdict=distro_verdict)
        persist_affected_answer(tenant_id, answer, observed_at=observed_at)
    by_id = {advisory.id: advisory for advisory in feed}
    unresolved: set[str] = set()
    for feed_id in prior_feed_ids or []:
        if feed_id not in by_id:
            record = _feed(feed_id)
            if record is None:
                unresolved.add(feed_id)
            else:
                by_id[feed_id] = record
    persisted = set(unresolved)
    for feed_id, advisory in by_id.items():
        answer = affected_answer(advisory, reports, source="feed", distro_verdict=distro_verdict)
        if _has_rows(answer) or feed_id in (prior_feed_ids or []):
            persist_affected_answer(tenant_id, answer, observed_at=observed_at)
        if _has_rows(answer):
            persisted.add(feed_id)
    return sorted(persisted)[:MAX_PERSISTED_FEED_IDS]
