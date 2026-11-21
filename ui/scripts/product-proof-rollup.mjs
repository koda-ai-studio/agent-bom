// Roll-up and node-aggregate responses for the product-proof graph, served from
// the fixture the backend roll-up writes (scripts/generate_product_proof_rollup.py).
import fixture from "../tests/fixtures/product-proof-rollup.json" with { type: "json" };

export function rollupResponse() {
  return structuredClone(fixture.rollup);
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
