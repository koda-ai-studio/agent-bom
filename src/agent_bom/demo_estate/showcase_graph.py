"""Dense showcase graph for demos, screenshots, and first-session proof."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime
from typing import TYPE_CHECKING, Any

from agent_bom.api.agent_identity_store import (
    InMemoryAgentIdentityStore,
)
from agent_bom.demo_estate.compute_identity_lane import project_compute_lane
from agent_bom.demo_estate.id_schemes import record_retired_showcase_ids, showcase_misconfig_id
from agent_bom.demo_estate.showcase_constants import _SHOWCASE_CURRENT_STAMP as _SHOWCASE_CURRENT_STAMP
from agent_bom.demo_estate.showcase_constants import _SHOWCASE_CURRENT_TARGET as _SHOWCASE_CURRENT_TARGET
from agent_bom.demo_estate.showcase_constants import _SHOWCASE_IMPORT_NOW as _SHOWCASE_IMPORT_NOW
from agent_bom.demo_estate.showcase_constants import SHOWCASE_AGENTS as SHOWCASE_AGENTS
from agent_bom.demo_estate.showcase_constants import SHOWCASE_BASELINE_CREATED_AT as SHOWCASE_BASELINE_CREATED_AT
from agent_bom.demo_estate.showcase_constants import SHOWCASE_BASELINE_SCAN_ID as SHOWCASE_BASELINE_SCAN_ID
from agent_bom.demo_estate.showcase_constants import SHOWCASE_CURRENT_CREATED_AT as SHOWCASE_CURRENT_CREATED_AT
from agent_bom.demo_estate.showcase_constants import SHOWCASE_ORG_ID as SHOWCASE_ORG_ID
from agent_bom.demo_estate.showcase_constants import SHOWCASE_PACKAGES as SHOWCASE_PACKAGES
from agent_bom.demo_estate.showcase_constants import SHOWCASE_SCAN_ID as SHOWCASE_SCAN_ID
from agent_bom.demo_estate.showcase_constants import SHOWCASE_SERVERS as SHOWCASE_SERVERS
from agent_bom.demo_estate.showcase_constants import SHOWCASE_SOURCE as SHOWCASE_SOURCE
from agent_bom.demo_estate.showcase_constants import SHOWCASE_TENANT as SHOWCASE_TENANT
from agent_bom.demo_estate.showcase_constants import ShowcaseProfile as ShowcaseProfile
from agent_bom.demo_estate.showcase_credentials import seed_showcase_credentials
from agent_bom.demo_estate.showcase_findings import (
    SHOWCASE_DRIFT_INCIDENTS,
    bind_mcp_auth_findings,
    demo_mcp_auth_findings,
    project_mcp_auth_findings,
)
from agent_bom.demo_estate.showcase_fleet import seed_showcase_fleet_and_runtime as seed_showcase_fleet_and_runtime
from agent_bom.demo_estate.showcase_identities import _DEMO_IDENTITIES as _DEMO_IDENTITIES
from agent_bom.demo_estate.showcase_identities import _DEMO_JIT_GRANTS as _DEMO_JIT_GRANTS
from agent_bom.demo_estate.showcase_identities import _annotate_demo_identity_risk as _annotate_demo_identity_risk
from agent_bom.demo_estate.showcase_identities import _demo_identity_id as _demo_identity_id
from agent_bom.demo_estate.showcase_identities import build_demo_identity_store as build_demo_identity_store
from agent_bom.demo_estate.showcase_identities import demo_identity_records as demo_identity_records
from agent_bom.demo_estate.showcase_identities import seed_showcase_identities as seed_showcase_identities
from agent_bom.demo_estate.showcase_ids import (
    record_retired_showcase_inventory_ids,
    showcase_agent_id,
    showcase_credential_id,
    showcase_ids,
    showcase_retired_server_id,
    showcase_server_id,
    showcase_tool_id,
)
from agent_bom.demo_estate.showcase_packages import seed_showcase_packages
from agent_bom.graph.asset_entity import link_report_findings_to_graph
from agent_bom.graph.cnapp_overlay import apply_cnapp_overlay
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import fixture_edge_evidence
from agent_bom.graph.effective_permissions import apply_effective_permissions
from agent_bom.graph.governance_overlay import apply_governance_overlay
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

if TYPE_CHECKING:
    from agent_bom.graph.ports import GraphStoreProtocol


_logger = logging.getLogger(__name__)


class _DriftIncident:
    """Shape the governance overlay expects (attribute access)."""

    def __init__(self, *, incident_id, blueprint_id, drift_score, violation_count, top_violations):
        self.incident_id = incident_id
        self.blueprint_id = blueprint_id
        self.drift_score = drift_score
        self.violation_count = violation_count
        self.occurrences = violation_count
        self.status = "open"
        self.top_violations = top_violations


class _DriftStore:
    """Minimal drift store projecting behavioral-drift incidents."""

    def __init__(self, incidents: list[_DriftIncident]) -> None:
        self._incidents = incidents

    def list(self, *_a, **_k) -> list[_DriftIncident]:
        return list(self._incidents)


def build_showcase_graph(
    *,
    tenant_id: str = SHOWCASE_TENANT,
    scan_id: str = SHOWCASE_SCAN_ID,
    profile: ShowcaseProfile = "current",
    identity_store: InMemoryAgentIdentityStore | None = None,
) -> tuple[UnifiedGraph, InMemoryAgentIdentityStore, _DriftStore]:
    is_baseline = profile == "baseline"
    recorded_at = SHOWCASE_BASELINE_CREATED_AT if is_baseline else SHOWCASE_CURRENT_CREATED_AT
    g = UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id, created_at=recorded_at)

    def node(i: str, t: EntityType, label: str, **attrs) -> str:
        severity = attrs.pop("severity", "")
        risk_score = attrs.pop("risk_score", 0.0)
        g.add_node(UnifiedNode(id=i, entity_type=t, label=label, severity=severity, risk_score=risk_score, attributes=attrs))
        return i

    def edge(s: str, d: str, r: RelationshipType, evidence: dict[str, Any] | None = None, **kw) -> None:
        g.add_edge(UnifiedEdge(source=s, target=d, relationship=r, evidence=fixture_edge_evidence(r, SHOWCASE_SOURCE, evidence), **kw))

    provider = showcase_ids().provider
    node(provider, EntityType.PROVIDER, provider.removeprefix("provider:"), provider=provider.removeprefix("provider:"))
    for aid, label in SHOWCASE_AGENTS.items():
        node(showcase_agent_id(aid), EntityType.AGENT, label, environment="production")
        edge(provider, showcase_agent_id(aid), RelationshipType.HOSTS)

    for sid, (owner, tools) in SHOWCASE_SERVERS.items():
        node(showcase_server_id(sid), EntityType.SERVER, sid)
        edge(showcase_agent_id(owner), showcase_server_id(sid), RelationshipType.USES)
        for tname in tools:
            tid = showcase_tool_id(sid, tname)
            node(tid, EntityType.TOOL, tname)
            edge(showcase_server_id(sid), tid, RelationshipType.PROVIDES_TOOL)

    # Real CVEs on real package@versions, under every server the demo inventory records.
    seed_showcase_packages(node, edge, SHOWCASE_PACKAGES)

    seed_showcase_credentials(node, edge)

    # Hero blast-radius chain: the PyYAML RCE on shell-runner-server reaches an
    # AWS credential AND the run_shell tool → potential RCE. This is the top
    # exposure path the graph/posture surfaces should headline.
    aws_secret = showcase_credential_id("shell-runner-server", "AWS_SECRET_ACCESS_KEY")
    run_shell = showcase_tool_id("shell-runner-server", "run_shell")
    eval_expression = showcase_tool_id("llm-orchestrator-server", "eval_expression")
    edge("vuln:CVE-2020-14343", aws_secret, RelationshipType.EXPLOITABLE_VIA, weight=9.8)
    edge("vuln:CVE-2020-14343", run_shell, RelationshipType.EXPLOITABLE_VIA, weight=9.8)
    edge(aws_secret, run_shell, RelationshipType.REACHES_TOOL)
    # Second high-signal chain: LangChain RCE reaches the eval_expression tool.
    edge("vuln:CVE-2023-36258", eval_expression, RelationshipType.EXPLOITABLE_VIA, weight=9.8)
    edge(
        "vuln:CVE-2023-36258",
        showcase_credential_id("llm-orchestrator-server", "OPENAI_API_KEY"),
        RelationshipType.EXPLOITABLE_VIA,
        weight=9.8,
    )

    for i, (aid, tid) in enumerate(
        [
            ("cursor", run_shell),
            ("data-pipeline", showcase_tool_id("warehouse-server", "execute_sql")),
            ("langchain-service", eval_expression),
        ]
    ):
        cid = f"call:{i}"
        node(cid, EntityType.TOOL_CALL, "observed invocation")
        edge(showcase_agent_id(aid), cid, RelationshipType.INVOKED)
        edge(cid, tid, RelationshipType.CALLED)

    node(
        "cloud:pii-bucket",
        EntityType.CLOUD_RESOURCE,
        "customer-pii-prod (S3)",
        resource_type="s3",
        compliance_tags=["PII", "GDPR"],
        severity="" if is_baseline else "high",
        risk_score=0.0 if is_baseline else 8.2,
        internet_exposed=False if is_baseline else True,
    )
    if is_baseline:
        node(
            showcase_misconfig_id("pii-private"),
            EntityType.MISCONFIGURATION,
            "S3 bucket customer-pii-prod blocks public ACLs",
        )
        edge(showcase_misconfig_id("pii-private"), "cloud:pii-bucket", RelationshipType.AFFECTS)
    else:
        node(
            showcase_misconfig_id("pii-public"),
            EntityType.MISCONFIGURATION,
            "S3 bucket customer-pii-prod is publicly readable",
            severity="high",
            risk_score=8.2,
        )
        edge(showcase_misconfig_id("pii-public"), "cloud:pii-bucket", RelationshipType.AFFECTS)
        edge("cloud:pii-bucket", showcase_misconfig_id("pii-public"), RelationshipType.CONTAINS)

    node(
        "cloud:payments-db",
        EntityType.CLOUD_RESOURCE,
        "payments-db (RDS PostgreSQL)",
        resource_type="rds",
        compliance_tags=["PCI", "financial"],
    )

    node("cloud:bastion", EntityType.CLOUD_RESOURCE, "prod-bastion (EC2)", resource_type="ec2")
    node(
        showcase_misconfig_id("sg-open"),
        EntityType.MISCONFIGURATION,
        "Security group sg-prod allows 0.0.0.0/0 on port 22",
        severity="high",
        network_exposure=[{"resource": "prod-bastion", "from_port": 22, "to_port": 22, "protocol": "tcp", "scope": "internet"}],
    )
    edge(showcase_misconfig_id("sg-open"), "cloud:bastion", RelationshipType.AFFECTS)
    edge("cloud:bastion", showcase_misconfig_id("sg-open"), RelationshipType.CONTAINS)
    record_retired_showcase_ids(g)

    node("cloud:logs-bucket", EntityType.CLOUD_RESOURCE, "app-logs (S3)", resource_type="s3")

    # Cloud estate hierarchy — org → account → resources for rollup/containment demos.
    node("org:corp", EntityType.ORG, "Corp (root org)")
    node("account:aws:123456789012", EntityType.ACCOUNT, "AWS prod (123456789012)", cloud_provider="aws", account_id="123456789012")
    node("env:production", EntityType.ENVIRONMENT, "production")
    edge("org:corp", "account:aws:123456789012", RelationshipType.CONTAINS)
    edge("account:aws:123456789012", "env:production", RelationshipType.CONTAINS)
    # The showcase agents run in that production environment: they are part of the estate, not beside it.
    for aid in SHOWCASE_AGENTS:
        edge("env:production", showcase_agent_id(aid), RelationshipType.CONTAINS)
    for cloud_id in (
        "cloud:pii-bucket",
        "cloud:payments-db",
        "cloud:bastion",
        "cloud:logs-bucket",
    ):
        edge("account:aws:123456789012", cloud_id, RelationshipType.CONTAINS)

    # Hero exposure path: internet-facing bastion reaches the PII bucket.
    edge(
        "cloud:bastion",
        "cloud:pii-bucket",
        RelationshipType.EXPOSED_TO,
        evidence={"reason": "bastion_ssh_to_pii_bucket_network_path"},
    )

    node("user:alice", EntityType.USER, "alice@corp (developer)")
    node("user:bob", EntityType.USER, "bob@contractor (external)")
    node("role:prod-admin", EntityType.ROLE, "prod-admin-role")
    node("role:data-pipeline", EntityType.ROLE, "data-pipeline-role")
    node("role:readonly", EntityType.ROLE, "readonly-role")
    node("pol:admin", EntityType.POLICY, "AdministratorAccess", privilege_level="admin")
    node("pol:team-custom", EntityType.POLICY, "team-utility-policy", privilege_level="admin")
    node("pol:s3-write", EntityType.POLICY, "s3-write-policy", privilege_level="write")
    node("pol:readonly", EntityType.POLICY, "ViewOnlyAccess", privilege_level="read")

    edge("role:prod-admin", "pol:admin", RelationshipType.ATTACHED)
    edge("role:data-pipeline", "pol:team-custom", RelationshipType.ATTACHED)
    edge("role:data-pipeline", "pol:s3-write", RelationshipType.ATTACHED)
    edge("role:readonly", "pol:readonly", RelationshipType.ATTACHED)

    edge("user:alice", "role:prod-admin", RelationshipType.ASSUMES)
    if is_baseline:
        edge("user:bob", "role:readonly", RelationshipType.ASSUMES)
    else:
        edge("user:bob", "role:data-pipeline", RelationshipType.ASSUMES)
        edge("user:bob", "role:prod-admin", RelationshipType.ASSUMES)

    edge("role:prod-admin", "cloud:pii-bucket", RelationshipType.CAN_ACCESS)
    edge("role:prod-admin", "cloud:payments-db", RelationshipType.CAN_ACCESS)
    edge("role:prod-admin", "cloud:bastion", RelationshipType.CAN_ACCESS)
    edge("role:data-pipeline", "cloud:payments-db", RelationshipType.CAN_ACCESS)
    edge("role:data-pipeline", "cloud:logs-bucket", RelationshipType.CAN_ACCESS)
    edge("role:readonly", "cloud:logs-bucket", RelationshipType.CAN_ACCESS)

    # cursor drives the shell-runner (AWS creds + run_shell) → toxic combo with
    # prod-admin; data-pipeline maps to the least-privilege pipeline role.
    edge(showcase_agent_id("cursor"), "role:prod-admin", RelationshipType.ASSUMES)
    edge(showcase_agent_id("data-pipeline"), "role:data-pipeline", RelationshipType.ASSUMES)

    # Retired MCP server — removed in the current snapshot so drift shows a removal.
    if is_baseline:
        legacy = showcase_retired_server_id()
        node(legacy, EntityType.SERVER, "legacy-chat-server")
        edge(showcase_agent_id("support-copilot"), legacy, RelationshipType.USES)
        node(f"tool:{legacy}:send_message", EntityType.TOOL, "send_message")
        edge(legacy, f"tool:{legacy}:send_message", RelationshipType.PROVIDES_TOOL)

    # Enriched, deterministic NHI estate (owner / last_used / standing scopes) so
    # the governance overlay projects a real identity story. Shared with the live
    # identity-store seed via ``demo_identity_records`` so ids/attributes match.
    store = identity_store if identity_store is not None else build_demo_identity_store(tenant_id)

    drift = _DriftStore(
        [
            _DriftIncident(incident_id=i, blueprint_id=bp, drift_score=score, violation_count=n, top_violations=[{"tool_name": tool}])
            for i, bp, score, n, tool in SHOWCASE_DRIFT_INCIDENTS
        ]
    )
    record_retired_showcase_inventory_ids(g)
    if not is_baseline:
        project_mcp_auth_findings(g, bind_mcp_auth_findings(demo_mcp_auth_findings(), SHOWCASE_SERVERS))
    return g, store, drift


def apply_showcase_overlays(
    graph: UnifiedGraph,
    *,
    tenant_id: str = SHOWCASE_TENANT,
    identity_store: InMemoryAgentIdentityStore,
    drift_store: _DriftStore,
) -> dict[str, object]:
    cnapp = apply_cnapp_overlay(graph)
    eff = apply_effective_permissions(graph)
    gov = apply_governance_overlay(graph, tenant_id=tenant_id, identity_store=identity_store, drift_store=drift_store)
    return {"cnapp": cnapp, "effective_permissions": eff, "governance": gov}


def _ensure_showcase_edge(
    graph: UnifiedGraph,
    source: str,
    target: str,
    relationship: RelationshipType,
    **kwargs: Any,
) -> None:
    for edge in graph.edges:
        if edge.source == source and edge.target == target and edge.relationship == relationship:
            return
    kwargs["evidence"] = fixture_edge_evidence(relationship, SHOWCASE_SOURCE, kwargs.get("evidence"))
    graph.add_edge(UnifiedEdge(source=source, target=target, relationship=relationship, **kwargs))


def finalize_showcase_snapshot(graph: UnifiedGraph, *, profile: ShowcaseProfile) -> None:
    """Pin deliberate drift markers after overlays that may rewrite attributes."""
    _ensure_showcase_edge(
        graph,
        "cloud:bastion",
        "cloud:pii-bucket",
        RelationshipType.EXPOSED_TO,
        evidence={"reason": "bastion_ssh_to_pii_bucket_network_path"},
    )
    for cloud_id in (
        "cloud:pii-bucket",
        "cloud:payments-db",
        "cloud:bastion",
        "cloud:logs-bucket",
    ):
        _ensure_showcase_edge(
            graph,
            "account:aws:123456789012",
            cloud_id,
            RelationshipType.CONTAINS,
        )

    bucket = graph.nodes.get("cloud:pii-bucket")
    if bucket is None:
        return
    if profile == "baseline":
        bucket.attributes["internet_exposed"] = False
        bucket.attributes["encryption_at_rest"] = True
        bucket.severity = ""
        bucket.risk_score = 0.0
        bucket.compliance_tags = ["PII", "GDPR"]
        return
    bucket.attributes["internet_exposed"] = True
    bucket.attributes["encryption_at_rest"] = False
    bucket.severity = "high"
    bucket.risk_score = 8.2
    bucket.compliance_tags = ["PII", "GDPR", "public-exposure"]

    for node_id in ("call:0", "call:1", "call:2"):
        node = graph.nodes.get(node_id)
        if node is not None:
            node.attributes["evidence_tier"] = "runtime_observed"
    blocked_tool = graph.nodes.get(showcase_tool_id("shell-runner-server", "run_shell"))
    if blocked_tool is not None:
        blocked_tool.attributes["evidence_tier"] = "runtime_blocked"


def build_showcase_snapshot(
    *,
    tenant_id: str = SHOWCASE_TENANT,
    profile: ShowcaseProfile = "current",
    identity_records: InMemoryAgentIdentityStore | None = None,
    scan_report: Callable[[], dict[str, Any]] | None = None,
) -> UnifiedGraph:
    """One finished showcase snapshot, stamped with its profile's recorded time."""
    scan_id = SHOWCASE_BASELINE_SCAN_ID if profile == "baseline" else SHOWCASE_SCAN_ID
    graph, identity_store, drift_store = build_showcase_graph(
        tenant_id=tenant_id,
        scan_id=scan_id,
        profile=profile,
        identity_store=identity_records,
    )
    apply_showcase_overlays(graph, tenant_id=tenant_id, identity_store=identity_store, drift_store=drift_store)
    finalize_showcase_snapshot(graph, profile=profile)
    _annotate_demo_identity_risk(graph)
    project_estate_onto_showcase(graph, tenant_id=tenant_id, profile=profile, scan_report=scan_report)
    if _materialize_showcase_attack_paths(graph):
        _record_showcase_attack_path_analysis(graph)
    return graph


def _existing_snapshots(graph_store: GraphStoreProtocol, tenant_id: str) -> list[dict[str, Any]]:
    """Return the tenant's snapshots (scan_id + created_at) for staleness checks.

    Prefers ``list_snapshots`` so we can tell a real scan and a stale demo seed
    apart. Minimal stores that only expose ``latest_snapshot_id`` degrade to a
    single-entry view with an unknown ``created_at`` (which reads as stale).
    """
    list_snapshots = getattr(graph_store, "list_snapshots", None)
    if callable(list_snapshots):
        try:
            return list(list_snapshots(tenant_id=tenant_id))
        except Exception:  # noqa: BLE001 — fall back rather than block seeding
            _logger.warning("showcase seed could not list snapshots", exc_info=True)
    latest_snapshot_id = getattr(graph_store, "latest_snapshot_id", None)
    if callable(latest_snapshot_id):
        scan_id = latest_snapshot_id(tenant_id=tenant_id, snapshot_kind="scan")
        if scan_id:
            return [{"scan_id": scan_id, "created_at": ""}]
    return []


def _showcase_seed_is_current(snapshots: list[dict[str, Any]]) -> bool:
    """True when both showcase snapshots are present at the expected timestamps."""
    created_at_by_id = {str(row.get("scan_id")): str(row.get("created_at") or "") for row in snapshots}
    return (
        created_at_by_id.get(SHOWCASE_SCAN_ID) == SHOWCASE_CURRENT_CREATED_AT
        and created_at_by_id.get(SHOWCASE_BASELINE_SCAN_ID) == SHOWCASE_BASELINE_CREATED_AT
    )


def _showcase_would_displace_real_snapshot(
    foreign_snapshots: list[dict[str, Any]],
) -> bool:
    """Fail closed when fixed showcase time would become the default owner."""
    try:
        showcase_created_at = datetime.fromisoformat(SHOWCASE_CURRENT_CREATED_AT)
        foreign_created_at = [datetime.fromisoformat(str(row["created_at"])) for row in foreign_snapshots if row.get("created_at")]
    except (KeyError, TypeError, ValueError):
        return True
    if len(foreign_created_at) != len(foreign_snapshots):
        return True
    return max(foreign_created_at) <= showcase_created_at


def seed_showcase_graph_if_empty(
    graph_store: GraphStoreProtocol,
    *,
    tenant_id: str = SHOWCASE_TENANT,
    force: bool = False,
    scan_report: Callable[[], dict[str, Any]] | None = None,
) -> bool:
    """Persist baseline + current showcase snapshots, stale-aware (issue #3964).

    Seeding is gated on *what* already occupies the tenant, not merely whether
    anything does:

    * A real (non-showcase) scan is never shadowed — if any snapshot has a
      scan id outside the showcase set, a fresh scan owns the graph and the demo
      seed is skipped. The read path already defaults to the newest snapshot, so
      the fresh scan stays the one served. This preservation boundary applies
      even when the demo ``force`` override is set: force may refresh showcase
      snapshots, never delete operator scan evidence.
    * A *current* showcase seed (both snapshots at the expected ``created_at``)
      is idempotent — nothing is rewritten.
    * A *stale* showcase seed (missing baseline, or an out-of-date ``created_at``
      left by an older build / polluted DB) is cleared and re-seeded so
      ``--demo-estate`` boots on today's curated estate.
    """
    showcase_ids = {SHOWCASE_SCAN_ID, SHOWCASE_BASELINE_SCAN_ID}
    snapshots = _existing_snapshots(graph_store, tenant_id)
    foreign = [row for row in snapshots if str(row.get("scan_id")) not in showcase_ids]
    if foreign and not force:
        # An ordinary boot never shadows a real scan.
        return False
    if foreign and _showcase_would_displace_real_snapshot(foreign):
        # Force authorizes refreshing demo evidence, not changing the tenant's
        # default read owner. An imported or clock-skewed real snapshot can be
        # older than the deterministic showcase stamp, so adding the showcase
        # would silently make it the newest graph. Keep the real owner instead.
        return False
    if not force and snapshots and _showcase_seed_is_current(snapshots):
        return False
    if snapshots and not foreign:
        # Only showcase snapshots remain. Wipe them so the refreshed seed does
        # not leave orphaned nodes/edges behind.
        delete_tenant = getattr(graph_store, "delete_tenant", None)
        if callable(delete_tenant):
            delete_tenant(tenant_id=tenant_id)
    # With a preserved operator scan present, the showcase snapshots are still
    # written -- an explicit demo request needs a graph to address -- but they
    # keep their fixed, older timestamps. The newest-wins read path therefore
    # still defaults to the operator's scan; only a caller that asks for the
    # showcase scan id by name is served the estate.
    # One shared, enriched identity estate feeds both snapshots so the persisted
    # MANAGED_IDENTITY node ids match the live identity store the API re-projects.
    identity_records = build_demo_identity_store(tenant_id)

    baseline_graph = build_showcase_snapshot(tenant_id=tenant_id, profile="baseline", identity_records=identity_records)
    current_graph = build_showcase_snapshot(
        tenant_id=tenant_id, profile="current", identity_records=identity_records, scan_report=scan_report
    )
    graph_store.save_graph(current_graph)
    graph_store.save_graph(baseline_graph)
    return True


def _link_scan_report(graph: UnifiedGraph, scan_report: Callable[[], dict[str, Any]] | None) -> None:
    """Link the curated scan's findings onto the snapshot as a scan's persist path does.

    Each advisory then names the finding behind every occurrence. Best-effort:
    a failed curated scan leaves the seed as it was and never blocks it.
    """
    if scan_report is None:
        return
    try:
        report = scan_report()
    except Exception:  # broad-except: seed steps are isolated; the scan step reports its own failure
        _logger.warning("demo estate scan report unavailable for graph finding links", exc_info=True)
        return
    link_report_findings_to_graph(report, graph)


def project_estate_onto_showcase(
    graph: UnifiedGraph,
    *,
    tenant_id: str = SHOWCASE_TENANT,
    profile: ShowcaseProfile = "current",
    scan_report: Callable[[], dict[str, Any]] | None = None,
) -> dict[str, object]:
    """Extend a showcase snapshot with the enterprise estate.

    *Extend*, not replace. The showcase's hand-built incident chain
    (Cursor → shell-runner-server → ``pkg:pypi:pyyaml@5.3`` →
    ``vuln:CVE-2020-14343`` → its AWS secret credential) is the demo's headline and is
    asserted by ``tests/test_demo_estate_bootstrap.py``; it is untouched here.
    Seeding the estate as a *separate* snapshot was the alternative and was
    rejected: the read path serves the newest snapshot, so a prospect would land
    on one of the two estates and the correlation between them — the AWS account
    the hand-built chain runs in is an account the estate inventories — would
    never be drawn.

    ``profile`` follows the estate's own stage semantics: the baseline snapshot
    predates the collection window, so it carries the inventory but neither the
    posture findings nor the correlated chain that the window's evidence
    produced. Both appear in ``current``, which is what makes the drift lens show
    posture arriving rather than a relabelling of the same set.
    """
    from agent_bom.demo_estate.enterprise_composition import build_demo_estate
    from agent_bom.demo_estate.enterprise_correlation import build_estate_correlations
    from agent_bom.demo_estate.enterprise_findings import build_estate_findings
    from agent_bom.demo_estate.estate_graph import (
        estate_org_node_id,
        project_estate_into_graph,
    )

    estate = build_demo_estate(tenant_id=tenant_id)
    is_baseline = profile == "baseline"
    summary = project_estate_into_graph(
        graph,
        estate,
        findings=() if is_baseline else build_estate_findings(estate),
        correlations=() if is_baseline else build_estate_correlations(estate),
    )
    _ensure_showcase_edge(graph, estate_org_node_id(estate), SHOWCASE_ORG_ID, RelationshipType.CONTAINS)
    project_compute_lane(graph, tenant_id=tenant_id, evidence=not is_baseline, org_node_id=estate_org_node_id(estate))
    _link_scan_report(graph, scan_report)
    return summary


def _materialize_showcase_attack_paths(graph: UnifiedGraph) -> bool:
    """Populate the demo queue with the production snapshot path projection."""
    # Hop receipts copy the analyzer status at annotation time.
    _record_showcase_attack_path_analysis(graph, count_paths=False)
    try:
        from agent_bom.graph.edge_freshness import stamp_edge_freshness
        from agent_bom.graph.snapshot_paths import materialize_snapshot_paths

        stamp_edge_freshness(graph)
        # The projector detaches existing rows, applies occurrence-specific
        # exclusions, and ranks all path families without mutating the originals.
        graph.attack_paths = [row.path for row in materialize_snapshot_paths(graph)]
    except Exception:  # noqa: BLE001 — never block the snapshot save on path shaping
        _logger.warning("demo estate attack-path materialization failed", exc_info=True)
        graph.analysis_status.pop("attack_path_fusion", None)
        return False
    return True


def _record_showcase_attack_path_analysis(graph: UnifiedGraph, *, count_paths: bool = True) -> None:
    """Record the showcase path analysis as complete (``count_paths=False`` before derivation)."""

    # Persistence keys paths by chain within a scan, so duplicate in-memory
    # variants collapse to one served path. Report the persisted cardinality
    # instead of the pre-upsert list length.
    observed: dict[str, int] = {}
    if count_paths:
        from agent_bom.graph.snapshot_paths import path_identity

        observed["paths"] = len({path_identity(path) for path in graph.attack_paths})

    # Record that the run completed. Without this the snapshot reads
    # ``not_recorded`` and the graph header says "Analysis status unavailable"
    # while sitting on top of the paths this function just derived — the header
    # is right to distrust a snapshot that never claims one, so the seed has to
    # make the claim it has actually earned.
    from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus

    graph.analysis_status["attack_path_fusion"] = GraphAnalysisStatus(status=GraphAnalysisState.COMPLETE, observed=observed)
