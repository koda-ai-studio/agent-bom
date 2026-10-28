/**
 * Sample answers the read-only demo needs beyond the product-proof fixture
 * routes: the Investigation journey's Impact (graph impact walk), Owner
 * (finding ownership and SLA), Verify (campaign re-verification queue), the
 * findings lane counts and recorded audit outcomes. Every answer is derived
 * from the same fixture estate the other pages show, never hand-typed counts.
 *
 * Registered after `installRoutes`, so these handlers win for the paths they
 * cover (Playwright matches routes in reverse registration order).
 */
const DAY_MS = 86_400_000;
const LANE_BY_FINDING_TYPE = {
  vulnerability: "vulnerabilities", malicious_package: "vulnerabilities", misconfiguration: "cloud", iac: "iac",
  secret: "secrets", identity: "identity", pii_exposure: "data",
};

function fulfill(route, json) {
  return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(json) });
}

/** Breadth-first walk over recorded edges; reverse = what reaches this node, forward = what it reaches. */
export function graphImpact(graph, nodeId, { maxDepth = 4, direction = "reverse" } = {}) {
  const byId = new Map(graph.nodes.map((node) => [node.id, node]));
  const next = new Map();
  for (const edge of graph.edges) {
    const [from, to] = direction === "reverse" ? [edge.target, edge.source] : [edge.source, edge.target];
    if (!next.has(from)) next.set(from, []);
    next.get(from).push(to);
  }
  const depth = new Map([[nodeId, 0]]);
  const queue = [nodeId];
  while (queue.length) {
    const current = queue.shift();
    const level = depth.get(current);
    if (level >= maxDepth) continue;
    for (const neighbor of next.get(current) ?? []) {
      if (depth.has(neighbor) || !byId.has(neighbor)) continue;
      depth.set(neighbor, level + 1);
      queue.push(neighbor);
    }
  }
  depth.delete(nodeId);
  const detail = [...depth].map(([id, level]) => ({ id, label: byId.get(id).label, entity_type: byId.get(id).entity_type, depth: level }))
    .sort((left, right) => left.depth - right.depth || left.label.localeCompare(right.label));
  const byType = {};
  for (const item of detail) byType[item.entity_type] = (byType[item.entity_type] ?? 0) + 1;
  return {
    affected_nodes: detail.map((item) => item.id),
    affected_nodes_detail: detail,
    affected_by_type: byType,
    affected_count: detail.length,
    max_depth_reached: detail.reduce((max, item) => Math.max(max, item.depth), 0),
  };
}

/** Lane, owner, SLA and graph anchors the findings page and the Owner step read. */
export function enrichFindings(findings, graph, { snapshotAt, owner = "data-platform" }) {
  const cveNodes = new Map(graph.nodes.filter((node) => node.entity_type === "vulnerability").map((node) => [node.label, node.id]));
  const due = new Date(Date.parse(snapshotAt) + 7 * DAY_MS).toISOString();
  return findings.map((finding) => ({
    ...finding,
    lane: LANE_BY_FINDING_TYPE[finding.finding_type] ?? "other",
    node_id: cveNodes.get(finding.cve_id) ?? null,
    package: finding.package_name && finding.package_version ? `${finding.package_name}@${finding.package_version}` : null,
    owner,
    owner_type: "team",
    sla_due_at: due,
    sla_due_at_source: "severity-kev/v1",
  }));
}

export function findingFacets(findings) {
  const count = (key) => findings.reduce((acc, finding) => {
    const value = key(finding);
    acc[value] = (acc[value] ?? 0) + 1;
    return acc;
  }, {});
  return {
    lane: count((finding) => finding.lane),
    finding_class: { vulnerability: 0, misconfiguration: 0, secret: 0, pii: 0, identity: 0, unclassified: 0, ...count((finding) => finding.finding_type === "vulnerability" ? "vulnerability" : "unclassified") },
    severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0, ...count((finding) => finding.severity) },
    status: { open: findings.length, resolved: 0 },
    domain: { cspm: 0, vuln: findings.length, aspm: 0, dspm: 0, aispm: 0 },
    freshness: { last_24_hours: 0, last_7_days: findings.length, last_30_days: 0, older: 0, unavailable: 0 },
    fixability: count((finding) => finding.fixed_version ? "fix_available" : "no_fix_available"),
    ownership: count((finding) => finding.owner ? "owned" : "unowned"),
  };
}

const AUDIT_OUTCOMES = {
  "scan.completed": { outcome: "completed" },
  "gateway.policy.denied": { decision: "denied" },
  "agent_identity.issued": { status: "issued" },
  "agent_identity.rotated": { status: "rotated" },
  "agent_identity.revoked": { status: "revoked" },
  "compliance.bundle.signed": { outcome: "signed" },
};

/** The fixture audit trail with the outcome each action recorded. */
export function auditEntriesWithOutcomes(entries) {
  return entries.map((entry) => ({ ...entry, details: { ...AUDIT_OUTCOMES[entry.action], ...entry.details } }));
}

export async function installStaticDemoRoutes(page, { graph, findings, auditEntries, scanId, tenantId, snapshotAt }) {
  const enriched = enrichFindings(findings, graph, { snapshotAt });
  await page.route("**/v1/graph/impact?**", (route) => {
    const url = new URL(route.request().url());
    const nodeId = url.searchParams.get("node") ?? "";
    const maxDepth = Number(url.searchParams.get("max_depth") ?? 4);
    const direction = url.searchParams.get("direction") === "forward" ? "forward" : "reverse";
    return fulfill(route, {
      scan_id: url.searchParams.get("scan_id") ?? scanId,
      tenant_id: tenantId,
      snapshot_generation: graph.snapshot_generation ?? "a".repeat(32),
      interpretation: { basis: "recorded_reverse_reachability", execution: "not_established", collection_coverage: "unknown", traversable_only: false, max_depth: maxDepth },
      completeness: { complete: true, truncated: false, sampled: false, status: "complete", total: null, returned: 0, missing_endpoint_count: 0, scope: "impact" },
      node_id: nodeId,
      direction,
      ...graphImpact(graph, nodeId, { maxDepth, direction }),
    });
  });
  await page.route("**/v1/findings?**", (route) => {
    const url = new URL(route.request().url());
    const query = (url.searchParams.get("q") ?? url.searchParams.get("query") ?? "").trim().toLowerCase();
    const lane = url.searchParams.get("lane");
    const rows = enriched.filter((finding) => (!query || `${finding.cve_id} ${finding.title} ${finding.package_name}`.toLowerCase().includes(query))
      && (!lane || lane === "all" || finding.lane === lane));
    return fulfill(route, {
      schema_version: "findings.v1",
      findings: rows,
      count: rows.length,
      total: rows.length,
      limit: Number(url.searchParams.get("limit") ?? 50),
      offset: 0,
      sort: "risk",
      scan_id: scanId,
      facets: findingFacets(enriched),
      warnings: [],
    });
  });
  await page.route("**/v1/campaigns/verification-queue**", (route) => fulfill(route, {
    schema_version: "risk-campaign-verification-queue.v1",
    tenant_id: tenantId,
    entries: [{
      campaign_id: "campaign-demo-next-middleware",
      title: "Upgrade next to 15.2.3 on the GitHub Enterprise MCP path",
      original_member_count: 1,
      owner: "data-platform",
      sla_due_at: new Date(Date.parse(snapshotAt) + 7 * DAY_MS).toISOString(),
      state: "verifying",
      verification_status: "unverified",
      active: false,
      version: 2,
      updated_at: snapshotAt,
    }],
    count: 1,
    limit: 25,
    has_more: false,
    next_cursor: null,
  }));
  await page.route("**/v1/audit?**", (route) => {
    const url = new URL(route.request().url());
    const resource = url.searchParams.get("resource") ?? "";
    const action = url.searchParams.get("action") ?? "";
    const since = url.searchParams.get("since") ?? "";
    const entries = auditEntriesWithOutcomes(auditEntries).filter((entry) => (!resource || entry.resource.startsWith(resource))
      && (!action || entry.action === action) && (!since || entry.timestamp >= since));
    const offset = Number(url.searchParams.get("offset") ?? 0);
    const limit = Number(url.searchParams.get("limit") ?? 100);
    return fulfill(route, { entries: entries.slice(offset, offset + limit), total: entries.length });
  });
}
