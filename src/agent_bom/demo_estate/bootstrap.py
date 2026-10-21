"""Bootstrap a labeled demo estate on first API start."""

from __future__ import annotations

import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from functools import cache, partial
from typing import Any

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import _now
from agent_bom.api.store import DEMO_ESTATE_TRIGGERED_BY
from agent_bom.demo_estate import demo_estate_enabled as demo_estate_enabled
from agent_bom.demo_estate.boot_seed import serialized_seed
from agent_bom.demo_estate.showcase_findings import append_showcase_graph_findings, bind_mcp_auth_findings, estate_scan_evidence
from agent_bom.demo_estate.showcase_graph import (
    SHOWCASE_AGENTS,
    SHOWCASE_BASELINE_SCAN_ID,
    SHOWCASE_PACKAGES,
    SHOWCASE_SCAN_ID,
    SHOWCASE_SERVERS,
    SHOWCASE_TENANT,
    seed_showcase_fleet_and_runtime,
    seed_showcase_graph_if_empty,
    seed_showcase_identities,
)
from agent_bom.demo_estate.showcase_history import HISTORY_SCOPE_ID, HistoryStage, history_stages, stage_report
from agent_bom.demo_estate.showcase_packages import showcase_package_holders
from agent_bom.security import sanitize_error

_logger = logging.getLogger(__name__)

_TRUTHY = {"1", "true", "yes", "on"}

# The UTC day the day-scoped demo evidence was last refreshed for. Guards the
# per-request hook down to one string compare once the day is current.
_daily_evidence_lock = threading.Lock()
_daily_evidence_day: str | None = None

# The bootstrap runs at API start and from the maintenance loop, while the
# read-only status route can be served concurrently. Keep the last outcome per
# tenant so the product can explain *why* the showcase graph was not made the
# default instead of discarding the only code path that knows that decision.
_bootstrap_status_lock = threading.Lock()
_bootstrap_status_by_tenant: dict[str, dict[str, Any]] = {}


def _demo_seed_block_reason(graph_store: Any | None, tenant_id: str) -> str | None:
    """Why seeding would mix demo data with operator data, or ``None`` if safe.

    Fails closed on two conditions: the process state dir is not the pinned
    demo directory (so default stores would resolve to the operator's product
    data), or the graph store already holds a non-showcase snapshot for the
    tenant (an explicit store override points the demo at operator evidence).
    """
    from agent_bom.storage.state_home import demo_state_isolated

    if not demo_state_isolated():
        return "demo_state_not_isolated"
    if graph_store is not None:
        from agent_bom.demo_estate.showcase_graph import _existing_snapshots

        showcase_ids = {SHOWCASE_SCAN_ID, SHOWCASE_BASELINE_SCAN_ID}
        if any(str(row.get("scan_id")) not in showcase_ids for row in _existing_snapshots(graph_store, tenant_id)):
            return "non_demo_snapshot_present"
    return None


def _blocked_summary(tenant_id: str, reason: str) -> dict[str, Any]:
    _logger.error(
        "demo estate bootstrap refused tenant=%s reason=%s: demo data must not mix with product data; "
        "run demo mode against its own data directory (AGENT_BOM_DEMO_STATE_DIR)",
        tenant_id,
        reason,
    )
    return _remember_bootstrap_status(
        tenant_id,
        {"enabled": True, "tenant_id": tenant_id, "seeded": False, "graph_seeded": False, "blocked": reason},
    )


def reset_daily_evidence_day() -> None:
    """Forget which day the evidence was refreshed for. For tests and resets."""
    global _daily_evidence_day
    with _daily_evidence_lock:
        _daily_evidence_day = None


def _remember_bootstrap_status(tenant_id: str, summary: dict[str, Any]) -> dict[str, Any]:
    """Publish one immutable-by-convention copy of the latest bootstrap result."""
    published = dict(summary)
    with _bootstrap_status_lock:
        _bootstrap_status_by_tenant[tenant_id] = published
    return summary


def get_demo_estate_bootstrap_status(*, tenant_id: str = SHOWCASE_TENANT) -> dict[str, Any]:
    """Return the latest bootstrap decision for one tenant, if one has run."""
    with _bootstrap_status_lock:
        return dict(_bootstrap_status_by_tenant.get(tenant_id, {}))


def reset_demo_estate_bootstrap_status() -> None:
    """Forget published bootstrap decisions. For process-lifecycle tests."""
    with _bootstrap_status_lock:
        _bootstrap_status_by_tenant.clear()


def refresh_demo_daily_evidence(*, tenant_id: str = SHOWCASE_TENANT, now: datetime | None = None) -> dict[str, Any]:
    """Re-seed the demo evidence that is scoped to a single UTC day.

    The gateway KPI header, proxy status, firewall stats and the cost page all
    window on ``[UTC midnight, request time]``. Evidence seeded at boot carries
    the boot day's timestamps, so the moment the UTC day advances every one of
    those surfaces reads 0 — a demo that claims no traffic on an estate the same
    page describes as busy. Seeding once was never enough; the day has to be
    re-checked, and the 60s maintenance loop alone leaves a visible window right
    after midnight.

    The day marker is claimed BEFORE seeding, so a concurrent burst of requests
    at rollover produces one reseed rather than a stampede, and a seeding
    failure is retried by the maintenance loop rather than by every request.
    """
    global _daily_evidence_day

    if not demo_estate_enabled():
        return {"refreshed": False, "reason": "disabled"}

    today = (now or datetime.now(timezone.utc)).date().isoformat()
    with _daily_evidence_lock:
        if _daily_evidence_day == today:
            return {"refreshed": False, "reason": "current", "day": today}
    if get_demo_estate_bootstrap_status(tenant_id=tenant_id).get("blocked") or _demo_seed_block_reason(None, tenant_id):
        return {"refreshed": False, "reason": "blocked"}
    with _daily_evidence_lock:
        if _daily_evidence_day == today:
            return {"refreshed": False, "reason": "current", "day": today}
        _daily_evidence_day = today

    summary: dict[str, Any] = {"refreshed": True, "day": today, "tenant_id": tenant_id}
    try:
        from agent_bom.demo_estate.showcase_gateway import seed_showcase_gateway_events

        summary["gateway_feed"] = seed_showcase_gateway_events(tenant_id=tenant_id, now=now)
    except Exception:
        _logger.warning("demo estate daily gateway refresh failed", exc_info=True)
        summary["gateway_feed_error"] = True
    try:
        from agent_bom.demo_estate.showcase_governance import seed_showcase_governance_and_cost

        summary["governance_cost"] = seed_showcase_governance_and_cost(tenant_id=tenant_id, now=now)
    except Exception:
        _logger.warning("demo estate daily cost refresh failed", exc_info=True)
        summary["governance_cost_error"] = True
    return summary


def demo_estate_force_reseed() -> bool:
    """Operator override: always reseed scan jobs even when usable ones exist."""
    return os.environ.get("AGENT_BOM_DEMO_ESTATE_FORCE", "").strip().lower() in _TRUTHY


def _job_has_demo_source(job: Any) -> bool:
    result = getattr(job, "result", None) or {}
    sources = result.get("scan_sources") or []
    if any("demo" in str(src).lower() for src in sources):
        return True
    return getattr(job, "triggered_by", None) == DEMO_ESTATE_TRIGGERED_BY


def _job_has_findings(job: Any) -> bool:
    result = getattr(job, "result", None) or {}
    findings = result.get("findings") or result.get("vulnerabilities") or []
    return bool(findings)


def _tenant_has_demo_jobs(store: Any, tenant_id: str) -> bool:
    """True when the tenant already has a *usable* demo scan job.

    Presence alone is not enough: an empty or FAILED demo marker (or a job
    whose findings were never persisted) must not block reseed — that is how
    the public demo can boot with graph/catalog populated but findings=[].
    """
    exists = getattr(store, "has_usable_demo_job", None)
    if callable(exists):
        return bool(exists(tenant_id))
    list_fn = getattr(store, "list_all", None)
    if not callable(list_fn):
        return False
    jobs = list_fn(tenant_id=tenant_id)
    for job in jobs:
        status = getattr(job, "status", None)
        if status is not None and status != JobStatus.DONE and str(status).lower() != "done":
            continue
        if _job_has_demo_source(job) and _job_has_findings(job):
            return True
    return False


def _stamp_showcase_graph_reachability(blast_radii: list[Any], agents: list[Any]) -> None:
    """Join demo vulnerability rows to the exact persisted showcase paths.

    The hand-built graph is the evidence authority for these paths.  Matching
    stays deliberately exact on package version and vulnerability identity so
    the demo never upgrades structural proximity into exploitability proof.
    """
    agents_by_name = {agent.name: agent for agent in agents}
    servers_by_name = {server.name: server for agent in agents for server in agent.mcp_servers}
    holders = showcase_package_holders()

    for blast_radius in blast_radii:
        package = blast_radius.package
        package_key = f"{package.name}@{package.version}".lower()
        path = SHOWCASE_PACKAGES.get(package_key)
        if path is None:
            continue
        _server_name, vulnerability_id, _severity, _score = path
        if blast_radius.vulnerability.id.upper() != vulnerability_id.upper():
            continue

        # Every server the graph draws holding this package, and the agent using each.
        drawn: list[tuple[Any, Any]] = []
        for name in holders.get((package.name, package.version, package.ecosystem), []):
            agent = agents_by_name.get(SHOWCASE_SERVERS[name][0]) if name in SHOWCASE_SERVERS else None
            server = servers_by_name.get(name)
            if agent is not None and server is not None:
                drawn.append((agent, server))
        if not drawn:
            continue
        for agent, server in drawn:
            if all(existing.name != agent.name for existing in blast_radius.affected_agents):
                blast_radius.affected_agents.append(agent)
            if all(existing.name != server.name for existing in blast_radius.affected_servers):
                blast_radius.affected_servers.append(server)

        blast_radius.graph_reachable = True
        blast_radius.graph_min_hop_distance = 3
        blast_radius.graph_reachable_from_agents = sorted({f"agent:{agent.name}" for agent, _server in drawn})
        blast_radius.calculate_risk_score()


def _run_demo_scan_report(*, tenant_id: str) -> dict[str, Any]:
    from agent_bom.demo import DEMO_INVENTORY
    from agent_bom.demo_estate.showcase_owners import assign_showcase_owners
    from agent_bom.finding import blast_radius_to_finding
    from agent_bom.inventory import build_agents_from_inventory
    from agent_bom.mcp_auth_posture import evaluate_mcp_auth_posture
    from agent_bom.mcp_blocklist import blocklist_findings_for_agents
    from agent_bom.models import AIBOMReport
    from agent_bom.output import to_json
    from agent_bom.scanners import scan_agents_sync

    agents = build_agents_from_inventory(DEMO_INVENTORY, "agent-bom --demo")
    blast_radii = scan_agents_sync(
        agents,
        compliance_enabled=True,
        show_scan_banner=False,
        offline=True,
        demo_advisories=True,
    )
    # Only the demo inventory's own blast radii sit on the hand-built path. An
    # estate package of the same version is another asset whose graph node has
    # no edge from that server; stamping it claimed a path the graph never draws
    # and left the server's nested package rows with no single finding to join.
    _stamp_showcase_graph_reachability(blast_radii, agents)
    findings = [blast_radius_to_finding(br) for br in blast_radii]
    agent_by_finding = {
        id(finding): (br.affected_agents[0].name if br.affected_agents else None) for br, finding in zip(blast_radii, findings, strict=True)
    }
    assign_showcase_owners(findings, agent_of=lambda finding: agent_by_finding.get(id(finding)))
    # Both halves of the vulnerability lane, paired in order (see
    # ``estate_scan_evidence``).
    estate_pairs, estate_findings = estate_scan_evidence(tenant_id)
    blast_radii = [*blast_radii, *(br for br, _ in estate_pairs)]
    findings.extend(finding for _, finding in estate_pairs)
    findings.extend(blocklist_findings_for_agents(agents))
    findings.extend(bind_mcp_auth_findings(evaluate_mcp_auth_posture(agents), SHOWCASE_SERVERS))
    findings.extend(estate_findings)
    report = to_json(
        AIBOMReport(
            agents=agents,
            blast_radii=blast_radii,
            findings=findings,
            scan_sources=["demo", "demo-estate"],
            scan_id="showcase",
        )
    )
    append_showcase_graph_findings(
        report,
        tenant_id=tenant_id,
        agent_ids_by_label={label: f"agent:{agent_id}" for agent_id, label in SHOWCASE_AGENTS.items()},
    )

    report.setdefault("scan_sources", [])
    if "demo" not in report["scan_sources"]:
        report["scan_sources"].append("demo")
    if "demo-estate" not in report["scan_sources"]:
        report["scan_sources"].append("demo-estate")

    # Overlay a curated multi-cloud CIS benchmark posture so the CIS/compliance
    # surfaces render a believable AWS/GCP/Azure pass-fail spread. The keys are
    # exactly what build_cis_benchmark_check_rows() reads from a scan result.
    from agent_bom.demo_estate.showcase_cis import demo_cis_benchmarks

    for key, benchmark in demo_cis_benchmarks().items():
        report.setdefault(key, benchmark)
    return report


def _store_demo_scan_job(report: dict[str, Any], *, tenant_id: str, job_id: str = "", completed_at: str = "") -> str:
    from agent_bom.api.stores import _get_store, _jobs_put

    job = ScanJob(
        job_id=job_id or str(uuid.uuid4()),
        tenant_id=tenant_id,
        triggered_by=DEMO_ESTATE_TRIGGERED_BY,
        created_at=completed_at or _now(),
        request=ScanRequest(offline=True),
    )
    job.status = JobStatus.DONE
    job.completed_at = completed_at or _now()
    job.result = report
    job.progress.append("Seeded demo estate scan (offline curated sample)")
    store = _get_store()
    store.put(job)
    _jobs_put(job.job_id, job)
    return job.job_id


def _record_showcase_trend(report: dict[str, Any], stage: HistoryStage, *, tenant_id: str) -> int:
    from agent_bom.api.trend_recording import record_scan_trend_best_effort

    recorded = record_scan_trend_best_effort(
        report,
        tenant_id=tenant_id,
        scan_id=stage.scan_id,
        completed_at=stage.timestamp,
        scope_id=HISTORY_SCOPE_ID,
        headline_posture=True,
    )
    return int(recorded)


def _seed_showcase_history_stages(report: dict[str, Any], *, tenant_id: str) -> int:
    """Persist and trend every earlier scan of the showcase scope, oldest first.

    Each stage is stored as its own demo job before its point is recorded, so
    the point's grade and issue counts are what the posture endpoints served
    once that scan landed. Stable job and scan ids keep reseeds idempotent.
    """
    recorded = 0
    for index, stage in enumerate(history_stages()[:-1]):
        staged = stage_report(report, index)
        _store_demo_scan_job(staged, tenant_id=tenant_id, job_id=stage.job_id, completed_at=stage.timestamp)
        recorded += _record_showcase_trend(staged, stage, tenant_id=tenant_id)
    return recorded


def _graph_owner_scan_id(graph_store: Any, tenant_id: str) -> str:
    """Return the scan id whose snapshot the graph read path will serve."""
    try:
        latest = getattr(graph_store, "latest_snapshot_id", None)
        if callable(latest):
            return str(latest(tenant_id=tenant_id, snapshot_kind="scan") or "")
    except Exception:  # noqa: BLE001 - never block the demo boot on a read
        _logger.debug("could not resolve graph owner scan id", exc_info=True)
    return ""


@serialized_seed
def maybe_bootstrap_demo_estate(*, tenant_id: str = SHOWCASE_TENANT) -> dict[str, Any]:
    """Seed showcase graph + curated findings when demo estate mode is enabled."""
    if not demo_estate_enabled():
        return _remember_bootstrap_status(
            tenant_id,
            {"enabled": False, "tenant_id": tenant_id, "seeded": False},
        )

    from agent_bom.api.stores import _get_graph_store, _get_store

    if _demo_seed_block_reason(None, tenant_id):
        return _blocked_summary(tenant_id, "demo_state_not_isolated")
    graph_store = _get_graph_store()
    block_reason = _demo_seed_block_reason(graph_store, tenant_id)
    if block_reason:
        return _blocked_summary(tenant_id, block_reason)
    store = _get_store()
    summary: dict[str, Any] = {"enabled": True, "tenant_id": tenant_id, "seeded": False}
    force = demo_estate_force_reseed()
    if force:
        summary["force"] = True

    # Validate and fingerprint the versioned synthetic-estate contract on every
    # demo boot. PRs that project this evidence into graph/runtime/UI surfaces
    # can now consume one deterministic source instead of inventing unrelated
    # rows per screen. A malformed fixture remains an explicit bootstrap error.
    try:
        from agent_bom.demo_estate.enterprise import CollectionStatus
        from agent_bom.demo_estate.enterprise_composition import build_demo_estate

        enterprise = build_demo_estate(tenant_id=tenant_id)
        summary["enterprise_contract"] = {
            "schema_version": enterprise.schema_version,
            "estate_id": enterprise.estate_id,
            "content_hash": enterprise.content_hash,
            "assets": len(enterprise.assets),
            "observations": len(enterprise.observations),
            "snapshots": len(enterprise.snapshots),
            "partial_sources": sorted(run.source.value for run in enterprise.collection_runs if run.status is CollectionStatus.PARTIAL),
        }
    except Exception:
        _logger.warning("demo enterprise contract validation failed", exc_info=True)
        summary["enterprise_contract_error"] = True

    # Graph seed is isolated and stale-aware: a real scan is left untouched, a
    # current demo seed is a no-op, and a stale demo seed is refreshed (see
    # seed_showcase_graph_if_empty). Any failure must NOT block the findings/scan
    # or identity seeding below — those keep posture + NHI non-empty on start.
    graph_seeded, demo_report = False, cache(partial(_run_demo_scan_report, tenant_id=tenant_id))  # one scan: graph links + job
    try:
        graph_seeded = seed_showcase_graph_if_empty(graph_store, tenant_id=tenant_id, force=force, scan_report=demo_report)
    except Exception:
        _logger.warning("demo estate graph seeding failed", exc_info=True)
        summary["graph_error"] = True
    summary["graph_seeded"] = graph_seeded
    # Populate one invariant for both outcomes. On a successful seed this is
    # ``showcase``; when seeding declines it names the operator snapshot that
    # remains the default graph.
    summary["graph_owner_scan_id"] = _graph_owner_scan_id(graph_store, tenant_id)

    # Seed the live agent-identity store (NHI estate) independently of the graph
    # snapshot so the NHI/Identity overview tile and the nhi-governance posture
    # survive a restart even when the graph already exists. Idempotent.
    try:
        summary["identities"] = seed_showcase_identities(tenant_id=tenant_id)
    except Exception:
        _logger.warning("demo estate identity seeding failed", exc_info=True)
        summary["identity_error"] = True

    # The AI BOM page reads the fleet registry and the MCP observation store —
    # neither of which the graph/findings seeds touch, so it rendered every
    # count as 0 on a fully populated estate. Same isolation as the identity
    # seed above: its failure must not block the rest of the bootstrap.
    try:
        summary["fleet_runtime"] = seed_showcase_fleet_and_runtime(tenant_id=tenant_id)
    except Exception:
        _logger.warning("demo estate fleet/runtime seeding failed", exc_info=True)
        summary["fleet_runtime_error"] = True

    # Seed the runtime gateway feed (proxy alerts + metrics + firewall
    # decisions) so the gateway/proxy/runtime dashboards show the AI-firewall in
    # action on the demo. Idempotent and independent of the scan-job seeding
    # below, so it must run even when demo jobs already exist.
    try:
        from agent_bom.demo_estate.showcase_gateway import seed_showcase_gateway_events

        summary["gateway_feed"] = seed_showcase_gateway_events(tenant_id=tenant_id)
    except Exception:
        _logger.warning("demo estate gateway feed seeding failed", exc_info=True)
        summary["gateway_feed_error"] = True

    # build_showcase_graph computes drift incidents into a private store it hands
    # back to its caller, while every drift surface reads the process-global
    # drift store. Without this the demo described drift in its own graph and
    # reported 0 incidents on every tile above it.
    try:
        from agent_bom.demo_estate.showcase_drift import seed_showcase_drift_incidents

        summary["drift_incidents"] = seed_showcase_drift_incidents(tenant_id=tenant_id)
    except Exception:
        _logger.warning("demo estate drift seeding failed", exc_info=True)
        summary["drift_error"] = True

    try:
        from agent_bom.demo_estate.showcase_catalog import seed_showcase_catalog_if_empty

        summary["catalog"] = seed_showcase_catalog_if_empty(tenant_id=tenant_id)
    except Exception:
        _logger.warning("demo estate catalog seeding failed", exc_info=True)
        summary["catalog_error"] = True

    # Skills, CWPP lifecycle, and the campaign verification queue each read a
    # dedicated tenant-scoped store. Seed small, explicitly synthetic records
    # through those stores' public contracts so the corresponding demo journeys
    # are evidence-backed rather than empty shells.
    try:
        from agent_bom.demo_estate.showcase_surfaces import seed_showcase_auxiliary_surfaces

        summary["auxiliary_surfaces"] = seed_showcase_auxiliary_surfaces(tenant_id=tenant_id)
    except Exception:
        _logger.warning("demo estate auxiliary surface seeding failed", exc_info=True)
        summary["auxiliary_surfaces_error"] = True

    # Governance blueprints and LLM spend live in their own stores, which the
    # graph/findings seeds never touch — the same gap the fleet/runtime seed
    # above closed for the AI BOM page. Without this the governance page showed
    # `count: 0` and the cost page a single call on an estate with thousands of
    # assets, which reads as a broken product rather than an unconfigured one.
    try:
        from agent_bom.demo_estate.showcase_governance import seed_showcase_governance_and_cost

        summary["governance_cost"] = seed_showcase_governance_and_cost(tenant_id=tenant_id)
    except Exception:
        _logger.warning("demo estate governance/cost seeding failed", exc_info=True)
        summary["governance_cost_error"] = True

    # A refreshed demo graph must also receive matching scan evidence. Keep
    # prior demo jobs as history, then make subsequent boots a no-op again.
    if not force and not graph_seeded and _tenant_has_demo_jobs(store, tenant_id):
        summary["reason"] = "demo_jobs_present"
        return _remember_bootstrap_status(tenant_id, summary)

    try:
        report = demo_report()
        finding_count = len(report.get("findings") or report.get("vulnerabilities") or [])
        if finding_count < 1:
            raise RuntimeError("demo estate scan produced zero findings")
        trend_points = 0
        try:
            trend_points = _seed_showcase_history_stages(report, tenant_id=tenant_id)
        except Exception as exc:
            _logger.warning("demo estate scan history seeding failed: %s", sanitize_error(exc, generic=True))
            summary["posture_trend_error"] = True
        stages = history_stages()
        current = stage_report(report, len(stages) - 1)
        job_id = _store_demo_scan_job(current, tenant_id=tenant_id)
        summary["posture_trend_points"] = trend_points + _record_showcase_trend(current, stages[-1], tenant_id=tenant_id)
        summary.update(
            {
                "seeded": True,
                "job_id": job_id,
                "agents": len(report.get("agents") or []),
                "findings": finding_count,
            }
        )
        _logger.info(
            "demo estate bootstrap complete tenant=%s graph_seeded=%s graph_owner_scan_id_present=%s job_id=%s findings=%s",
            tenant_id,
            graph_seeded,
            bool(summary.get("graph_owner_scan_id")),
            job_id,
            summary.get("findings"),
        )
    except Exception:
        _logger.warning("demo estate scan bootstrap failed", exc_info=True)
        summary["seeded"] = graph_seeded
        summary["scan_error"] = True

    return _remember_bootstrap_status(tenant_id, summary)
