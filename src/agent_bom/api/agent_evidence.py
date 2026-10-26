"""One projection of stored scan history for the agent routes, keyed by job revision.

``/v1/agents`` and agent detail need four small facts from history: per
(agent, server) scan sightings, gateway registrations, the current snapshot's
blast-radius rows that reach each agent, and the scanned-estate agent rows.
Each stored job carries a full scan report, so the projection is built in one
pass over the tenant's jobs and reused until the durable job revision moves.
The entry is stamped with the revision observed *before* the read and only
kept when the revision is unchanged afterwards, so a write that lands during a
build can never be hidden behind a stale entry. Concurrent cold reads of one
tenant share a single build.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from agent_bom.api.agent_findings import row_reaches_agent
from agent_bom.api.findings_current import current_scan_jobs
from agent_bom.api.models import JobStatus
from agent_bom.core.tenancy import require_explicit_tenant_id

_MAX_TENANTS = 16
_REVISION_ATTEMPTS = 3

_cache: OrderedDict[tuple[int, str], tuple[Any, str, AgentEvidence]] = OrderedDict()
_cache_lock = threading.Lock()
_build_locks: dict[tuple[int, str], threading.Lock] = {}


@dataclass(frozen=True)
class AgentEvidence:
    """Read-only history facts; callers copy before handing values to a response."""

    scan_history: dict[tuple[str, str], dict[str, Any]]
    gateway: dict[tuple[str, str], dict[str, Any]]
    blast_rows_by_agent: dict[str, list[dict[str, Any]]]
    estate_agents: list[dict[str, Any]]
    # Completed parent jobs that reported agents, newest first, for ``/v1/inventory``.
    inventory_jobs: list[dict[str, str]] = field(default_factory=list)

    def blast_rows(self, agent_id: str) -> list[dict[str, Any]]:
        return self.blast_rows_by_agent.get(agent_id, []) if agent_id else []


def _object_id(value: dict[str, Any]) -> str:
    return str(value.get("canonical_id") or value.get("stable_id") or value.get("id") or "")


def _report_servers(report: dict[str, Any]) -> Iterable[tuple[str, str, dict[str, Any]]]:
    for agent in report.get("agents", []) or []:
        if not isinstance(agent, dict):
            continue
        agent_id = _object_id(agent)
        agent_name = str(agent.get("name") or agent.get("agent_name") or "").strip()
        # ``servers`` is the back-compat key of older pushed reports and gateway seed data.
        for key in ("mcp_servers", "servers"):
            for server in agent.get(key, []) or []:
                if isinstance(server, dict):
                    yield agent_id, agent_name, server


def _history_and_gateway(jobs: list[Any]) -> tuple[dict[tuple[str, str], dict[str, Any]], dict[tuple[str, str], dict[str, Any]]]:
    history: dict[tuple[str, str], dict[str, Any]] = {}
    gateway: dict[tuple[str, str], dict[str, Any]] = {}
    for job in jobs:
        report = job.result or {}
        sources = [str(source) for source in report.get("scan_sources", []) or [] if source]
        created_at = str(job.created_at or "")
        completed_at = str(job.completed_at or created_at)
        for agent_id, agent_name, server in _report_servers(report):
            server_id = _object_id(server)
            if not agent_id or not server_id:
                continue
            key = (agent_id, server_id)
            record = history.setdefault(key, {"scan_sources": set(), "first_seen": "", "last_seen": ""})
            record["scan_sources"].update(sources)
            if created_at and (not record["first_seen"] or created_at < record["first_seen"]):
                record["first_seen"] = created_at
            if completed_at and completed_at > record["last_seen"]:
                record["last_seen"] = completed_at
            if str(server.get("url") or "").strip().startswith(("http://", "https://")):
                gate = gateway.setdefault(key, {"gateway_registered": True, "source_agents": set()})
                if agent_name:
                    gate["source_agents"].add(agent_name)
    return (
        {
            key: {
                "present": True,
                "scan_sources": sorted(value["scan_sources"]),
                "first_seen": value["first_seen"] or None,
                "last_seen": value["last_seen"] or None,
            }
            for key, value in history.items()
        },
        {key: {"gateway_registered": True, "source_agents": sorted(value["source_agents"])} for key, value in gateway.items()},
    )


def _current_blast_rows_by_agent(jobs: list[Any]) -> dict[str, list[dict[str, Any]]]:
    by_agent: dict[str, list[dict[str, Any]]] = {}
    for job in current_scan_jobs(jobs, since=None, scan_id=None):
        for row in (getattr(job, "result", None) or {}).get("blast_radius", []) or []:
            if not isinstance(row, dict):
                continue
            ids = row.get("affected_agent_ids")
            for agent_id in dict.fromkeys(ids if isinstance(ids, list) else []):
                if isinstance(agent_id, str) and row_reaches_agent(row, agent_id):
                    by_agent.setdefault(agent_id, []).append(row)
    return by_agent


def build_agent_evidence(jobs: Iterable[Any]) -> AgentEvidence:
    """Project completed jobs; the same selection the routes applied per request."""
    from agent_bom.api.estate_agents import scanned_estate_agents

    stored = list(jobs)
    completed = [job for job in stored if job.status == JobStatus.DONE and job.result]
    history, gateway = _history_and_gateway(completed)
    return AgentEvidence(
        scan_history=history,
        gateway=gateway,
        # A newer empty successful scan retires a scope, so selection sees every job.
        blast_rows_by_agent=_current_blast_rows_by_agent(stored),
        estate_agents=scanned_estate_agents(completed),
        inventory_jobs=[
            {"job_id": job.job_id, "created_at": job.created_at, "completed_at": job.completed_at or ""}
            for job in completed
            if not job.child_job_ids and any(isinstance(item, dict) for item in (job.result or {}).get("agents", []) or [])
        ],
    )


def job_revision(store: Any, tenant_id: str) -> str | None:
    """Durable job-store mutation token, or ``None`` for stores without one."""
    reader = getattr(store, "overview_evidence_revision", None)
    return str(reader(tenant_id)) if callable(reader) else None


def agent_evidence(store: Any, tenant_id: str) -> AgentEvidence:
    """The tenant's projection at the store's current revision."""
    require_explicit_tenant_id(tenant_id)
    revision = job_revision(store, tenant_id)
    if revision is None:
        return build_agent_evidence(store.list_all(tenant_id=tenant_id))
    key = (id(store), tenant_id)
    hit = _lookup(key, store, revision)
    if hit is not None:
        return hit
    with _cache_lock:
        gate = _build_locks.setdefault(key, threading.Lock())
    with gate:
        for _ in range(_REVISION_ATTEMPTS):
            revision = job_revision(store, tenant_id) or ""
            hit = _lookup(key, store, revision)
            if hit is not None:
                return hit
            evidence = build_agent_evidence(store.list_all(tenant_id=tenant_id))
            if job_revision(store, tenant_id) == revision:
                _remember(key, store, revision, evidence)
                return evidence
        # History kept moving: serve this consistent read, keep nothing.
        return evidence


def _lookup(key: tuple[int, str], store: Any, revision: str) -> AgentEvidence | None:
    with _cache_lock:
        entry = _cache.get(key)
        if entry is None or entry[0] is not store or entry[1] != revision:
            return None
        _cache.move_to_end(key)
        return entry[2]


def _remember(key: tuple[int, str], store: Any, revision: str, evidence: AgentEvidence) -> None:
    with _cache_lock:
        _cache[key] = (store, revision, evidence)
        _cache.move_to_end(key)
        while len(_cache) > _MAX_TENANTS:
            _cache.popitem(last=False)


def clear_agent_evidence_cache() -> None:
    with _cache_lock:
        _cache.clear()
        _build_locks.clear()


__all__ = ["AgentEvidence", "agent_evidence", "build_agent_evidence", "clear_agent_evidence_cache", "job_revision"]
