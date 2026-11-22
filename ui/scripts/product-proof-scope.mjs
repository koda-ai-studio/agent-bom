import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// The generated schema's meta tables are JSON object literals; read them rather than duplicate the taxonomy.
const SCHEMA_PATH = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../lib/graph-schema.generated.ts");
const SCHEMA = readFileSync(SCHEMA_PATH, "utf8");
const metaTable = (name) => JSON.parse(new RegExp(`export const ${name}: Record<[^>]+> = (\\{[\\s\\S]*?\\n\\});`).exec(SCHEMA)[1].replace(/,(\s*\})/g, "$1"));
const GRAPH_NODE_KIND_META = metaTable("GRAPH_NODE_KIND_META");
const GRAPH_SEMANTIC_LAYER_META = metaTable("GRAPH_SEMANTIC_LAYER_META");

/** Reject fixture responses that belong to a different selected snapshot. */
export function assertCaptureSnapshotScope(requestUrl, expectedScanId, responseScanIds) {
  const requestedScanId = new URL(requestUrl).searchParams.get("scan_id");
  if (
    requestedScanId !== expectedScanId ||
    responseScanIds.length === 0 ||
    responseScanIds.some((scanId) => scanId !== requestedScanId)
  ) {
    throw new Error("Capture fixture snapshot scope mismatch");
  }
}

/** The layer the API stamps on every node record (agent_bom.graph.semantic_layer): a recorded layer, else the kind's. */
export function withSemanticLayer(node) {
  const recorded = node.attributes?.semantic_layer;
  if (typeof recorded === "string" && Object.hasOwn(GRAPH_SEMANTIC_LAYER_META, recorded)) return { ...node, semantic_layer: recorded };
  return { ...node, semantic_layer: GRAPH_NODE_KIND_META[node.entity_type]?.layer ?? "asset" };
}

export function graphResponseWithPagination(data, collection = "nodes") {
  return {
    ...data,
    ...(Array.isArray(data.nodes) ? { nodes: data.nodes.map(withSemanticLayer) } : {}),
    pagination: { total: data[collection].length, offset: 0, limit: data[collection].length, has_more: false },
  };
}
