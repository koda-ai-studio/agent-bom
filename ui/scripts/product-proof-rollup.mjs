// Roll-up and node-aggregate responses for the product-proof graph, served from
// the fixture the backend roll-up writes (scripts/generate_product_proof_rollup.py).
import fixture from "../tests/fixtures/product-proof-rollup.json" with { type: "json" };

export function rollupResponse() {
  return structuredClone(fixture.rollup);
}

/** The node ids the precomputed aggregate table covers. */
export function nodeAggregatesFixtureIds() {
  return fixture.node_aggregates;
}

export function nodeAggregatesResponse(url, snapshotGeneration = null) {
  const ids = [...new Set(url.searchParams.getAll("node_id").map((id) => id.trim()).filter(Boolean))];
  const known = ids.filter((id) => id in fixture.node_aggregates);
  return {
    scan_id: url.searchParams.get("scan_id") || fixture.rollup.scan_id,
    tenant_id: fixture.rollup.tenant_id,
    snapshot_generation: url.searchParams.get("snapshot_generation") || snapshotGeneration,
    aggregates: known.map((id) => ({ node_id: id, ...structuredClone(fixture.node_aggregates[id]) })),
    missing_node_ids: ids.filter((id) => !(id in fixture.node_aggregates)),
  };
}

const SEVERITY_RANK = { none: 0, info: 1, low: 2, medium: 3, high: 4, critical: 5 };

/** The node-aggregates read for a graph fixture without a precomputed table: each asset's recorded findings by worst
 * severity, as the API derives them. Unknown ids come back missing. */
export function graphNodeAggregatesResponse(url, graph) {
  const findings = new Map(graph.nodes.filter((node) => ["vulnerability", "misconfiguration"].includes(node.entity_type)).map((node) => [node.id, node]));
  const owned = new Map();
  for (const link of graph.edges) {
    const pair = findings.has(link.target) && !findings.has(link.source) ? [link.source, link.target]
      : findings.has(link.source) && link.relationship === "affects" ? [link.target, link.source] : null;
    if (pair) owned.set(pair[0], new Set([...(owned.get(pair[0]) ?? []), pair[1]]));
  }
  const ids = [...new Set(url.searchParams.getAll("node_id").map((id) => id.trim()).filter(Boolean))];
  const aggregate = (id) => {
    const severities = [...owned.get(id)].map((finding) => String(findings.get(finding).severity ?? "none").toLowerCase());
    const worst = severities.sort((a, b) => (SEVERITY_RANK[b] ?? 0) - (SEVERITY_RANK[a] ?? 0))[0] ?? "none";
    return { node_id: id, aggregate: { issue_count: owned.get(id).size, worst_severity: worst, worst_severity_rank: SEVERITY_RANK[worst] ?? 0 } };
  };
  return {
    scan_id: url.searchParams.get("scan_id") || graph.scan_id,
    tenant_id: graph.tenant_id ?? fixture.rollup.tenant_id,
    snapshot_generation: url.searchParams.get("snapshot_generation"),
    aggregates: ids.filter((id) => owned.has(id)).map(aggregate),
    missing_node_ids: ids.filter((id) => !owned.has(id)),
  };
}
