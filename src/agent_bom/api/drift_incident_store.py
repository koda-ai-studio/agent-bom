"""Persistence for runtime blueprint-drift incidents.

`evaluate_runtime_blueprint_drift` compares observed runtime traffic against an
approved role/profile blueprint but is otherwise read-only. This store closes
the loop: when an evaluation reports ``drift_detected`` it is recorded as a
durable, tenant-scoped incident that an operator can list and resolve — turning
blueprints from advisory metadata into enforced contracts with an audit trail.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections import defaultdict
from dataclasses import asdict, dataclass
from typing import Any, Protocol

from agent_bom.api.storage.registry_sqlite import SQLiteRegistryStore
from agent_bom.storage.base import BackendKind
from agent_bom.storage.factory import resolve_backend


@dataclass
class DriftIncident:
    """A recorded blueprint-drift incident (one per tenant+blueprint+signature)."""

    incident_id: str
    tenant_id: str
    blueprint_id: str
    status: str  # drift_detected | review
    drift_score: float
    violation_count: int
    warning_count: int
    top_violations: list[dict[str, Any]]
    first_detected_at: str
    last_detected_at: str
    occurrences: int = 1
    resolved: bool = False
    resolved_at: str = ""
    resolved_by: str = ""
    resolution_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def incident_signature(tenant_id: str, blueprint_id: str, violations: list[dict[str, Any]]) -> str:
    """Stable id for a drift incident: same tenant+blueprint+violated-tools collapse
    into one incident (occurrences increment) instead of spamming a new row each poll."""
    tools = sorted({str(v.get("tool_name") or v.get("type") or "") for v in violations})
    raw = json.dumps({"t": tenant_id, "b": blueprint_id, "v": tools}, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


class DriftIncidentStore(Protocol):
    def upsert(self, incident: DriftIncident) -> DriftIncident: ...

    def list(self, tenant_id: str, *, include_resolved: bool = False, limit: int = 200) -> list[DriftIncident]: ...

    def get(self, tenant_id: str, incident_id: str) -> DriftIncident | None: ...

    def resolve(self, tenant_id: str, incident_id: str, *, by: str, note: str, at: str) -> DriftIncident | None: ...


class InMemoryDriftIncidentStore:
    def __init__(self) -> None:
        self._by_tenant: dict[str, dict[str, DriftIncident]] = defaultdict(dict)
        self._lock = threading.Lock()

    def upsert(self, incident: DriftIncident) -> DriftIncident:
        with self._lock:
            existing = self._by_tenant[incident.tenant_id].get(incident.incident_id)
            if existing and not existing.resolved:
                existing.last_detected_at = incident.last_detected_at
                existing.occurrences += 1
                existing.drift_score = incident.drift_score
                existing.violation_count = incident.violation_count
                existing.warning_count = incident.warning_count
                existing.top_violations = incident.top_violations
                return existing
            # New incident, or a re-detection after resolution (reopen as fresh row).
            self._by_tenant[incident.tenant_id][incident.incident_id] = incident
            return incident

    def list(self, tenant_id: str, *, include_resolved: bool = False, limit: int = 200) -> list[DriftIncident]:
        with self._lock:
            rows = [i for i in self._by_tenant.get(tenant_id, {}).values() if include_resolved or not i.resolved]
            return sorted(rows, key=lambda i: i.last_detected_at, reverse=True)[:limit]

    def get(self, tenant_id: str, incident_id: str) -> DriftIncident | None:
        with self._lock:
            return self._by_tenant.get(tenant_id, {}).get(incident_id)

    def resolve(self, tenant_id: str, incident_id: str, *, by: str, note: str, at: str) -> DriftIncident | None:
        with self._lock:
            incident = self._by_tenant.get(tenant_id, {}).get(incident_id)
            if incident is None:
                return None
            incident.resolved = True
            incident.resolved_at = at
            incident.resolved_by = by
            incident.resolution_note = note
            return incident


class SQLiteDriftIncidentStore(SQLiteRegistryStore[DriftIncident]):
    table = "drift_incidents"
    columns = ("tenant_id", "incident_id", "resolved", "last_detected_at")

    ddl = (
        """
            CREATE TABLE IF NOT EXISTS drift_incidents (
                tenant_id TEXT NOT NULL,
                incident_id TEXT NOT NULL,
                data TEXT NOT NULL,
                resolved INTEGER NOT NULL DEFAULT 0,
                last_detected_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, incident_id)
            )
            """,
        "CREATE INDEX IF NOT EXISTS idx_drift_incidents_tenant_open ON drift_incidents(tenant_id, resolved, last_detected_at DESC)",
    )

    def _decode(self, raw: str) -> DriftIncident:
        return DriftIncident(**json.loads(raw))

    def _save(self, incident: DriftIncident) -> None:
        self._put_payload((incident.tenant_id, incident.incident_id, int(incident.resolved), incident.last_detected_at), incident.to_dict())

    def list(self, tenant_id: str, *, include_resolved: bool = False, limit: int = 200) -> list[DriftIncident]:
        return self._list(
            "tenant_id = ?" + ("" if include_resolved else " AND resolved = 0"),
            (tenant_id,),
            order="last_detected_at DESC",
            limit=limit,
        )

    def get(self, tenant_id: str, incident_id: str) -> DriftIncident | None:
        return self._get("tenant_id = ? AND incident_id = ?", (tenant_id, incident_id))

    def upsert(self, incident: DriftIncident) -> DriftIncident:
        existing = self.get(incident.tenant_id, incident.incident_id)
        if existing and not existing.resolved:
            existing.last_detected_at = incident.last_detected_at
            existing.occurrences += 1
            existing.drift_score = incident.drift_score
            existing.violation_count = incident.violation_count
            existing.warning_count = incident.warning_count
            existing.top_violations = incident.top_violations
            self._save(existing)
            return existing
        self._save(incident)
        return incident

    def resolve(self, tenant_id: str, incident_id: str, *, by: str, note: str, at: str) -> DriftIncident | None:
        incident = self.get(tenant_id, incident_id)
        if incident is None:
            return None
        incident.resolved = True
        incident.resolved_at = at
        incident.resolved_by = by
        incident.resolution_note = note
        self._save(incident)
        return incident


def record_drift_if_detected(store: DriftIncidentStore, drift_result: dict[str, Any]) -> DriftIncident | None:
    """Persist a drift incident when an evaluation reports drift. Returns the
    incident, or None when the evaluation is aligned/review-only/no-activity."""
    if drift_result.get("status") != "drift_detected":
        return None
    tenant_id = str(drift_result.get("tenant_id") or "default")
    blueprint_id = str(drift_result.get("blueprint_id") or "")
    violations = list(drift_result.get("violations") or [])
    warnings = list(drift_result.get("warnings") or [])
    at = str(drift_result.get("evaluated_at") or "")
    incident = DriftIncident(
        incident_id=incident_signature(tenant_id, blueprint_id, violations),
        tenant_id=tenant_id,
        blueprint_id=blueprint_id,
        status="drift_detected",
        drift_score=float(drift_result.get("drift_score") or 0.0),
        violation_count=len(violations),
        warning_count=len(warnings),
        top_violations=violations[:5],
        first_detected_at=at,
        last_detected_at=at,
    )
    return store.upsert(incident)


_DRIFT_INCIDENT_STORE: DriftIncidentStore | None = None


def get_drift_incident_store() -> DriftIncidentStore:
    global _DRIFT_INCIDENT_STORE
    if _DRIFT_INCIDENT_STORE is not None:
        return _DRIFT_INCIDENT_STORE
    selection = resolve_backend()
    if selection.backend is BackendKind.POSTGRES:
        from agent_bom.api.storage.registry_stores import PostgresDriftIncidentStore

        _DRIFT_INCIDENT_STORE = PostgresDriftIncidentStore()
    elif selection.backend is BackendKind.SQLITE:
        _DRIFT_INCIDENT_STORE = SQLiteDriftIncidentStore(selection.sqlite_path or "")
    else:
        _DRIFT_INCIDENT_STORE = InMemoryDriftIncidentStore()
    return _DRIFT_INCIDENT_STORE


def set_drift_incident_store(store: DriftIncidentStore | None) -> None:
    global _DRIFT_INCIDENT_STORE
    _DRIFT_INCIDENT_STORE = store
