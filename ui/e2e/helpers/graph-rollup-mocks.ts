import type { Page } from "@playwright/test";
import { GRAPH_NODE_KIND_META, type GraphNodeKindKey } from "../../lib/graph-schema.generated";

type RollupEntry = { entity_type: string; semantic_layer?: string };
type NodeAggregate = { semantic_layer: string; aggregate: Record<string, unknown> };

/** The layer the API stamps on a roll-up entry: the schema legend's layer for its kind, else ``asset``. */
export function withSemanticLayer<T extends RollupEntry>(entry: T): T & { semantic_layer: string } {
  const layer = GRAPH_NODE_KIND_META[entry.entity_type as GraphNodeKindKey]?.layer ?? "asset";
  return { ...entry, semantic_layer: entry.semantic_layer ?? layer };
}

/** Serve ``/v1/graph/node-aggregates``; ids without a supplied aggregate come back missing, as the API reports unknown ids. */
export async function routeNodeAggregates(page: Page, aggregates: Record<string, NodeAggregate> = {}): Promise<string[][]> {
  const requests: string[][] = [];
  await page.route("**/v1/graph/node-aggregates?**", (route) => {
    const url = new URL(route.request().url());
    const ids = [...new Set(url.searchParams.getAll("node_id"))];
    requests.push(ids);
    return route.fulfill({ json: {
      scan_id: url.searchParams.get("scan_id") ?? "",
      tenant_id: "default",
      snapshot_generation: url.searchParams.get("snapshot_generation"),
      aggregates: ids.filter(id => id in aggregates).map(id => ({ node_id: id, ...aggregates[id] })),
      missing_node_ids: ids.filter(id => !(id in aggregates)),
    } });
  });
  return requests;
}

type GraphNode = { entity_type: string; semantic_layer?: string; attributes?: Record<string, unknown> };

/** Stamp every node the way the API serves it: a recorded ``attributes.semantic_layer``, else the legend layer for its kind. */
export function withNodeLayers<T extends { nodes: GraphNode[] }>(graph: T): T {
  return {
    ...graph,
    nodes: graph.nodes.map(node => {
      const recorded = node.attributes?.semantic_layer;
      return typeof recorded === "string" ? { ...node, semantic_layer: node.semantic_layer ?? recorded } : withSemanticLayer(node);
    }),
  };
}

/** What the API's node-aggregates read returns for this fixture: each asset's recorded findings, by worst severity. */
export function ownedFindingAggregates(nodes: { id: string; entity_type: string; severity: string; semantic_layer?: string }[], links: { source: string; target: string; relationship: string }[]) {
  const rank: Record<string, number> = { none: 0, info: 1, low: 2, medium: 3, high: 4, critical: 5 };
  const findings = new Map(nodes.filter(n => ["vulnerability", "misconfiguration"].includes(n.entity_type)).map(n => [n.id, n]));
  const owned = new Map<string, Set<string>>();
  for (const link of links) {
    const pair = findings.has(link.target) && !findings.has(link.source) ? [link.source, link.target]
      : findings.has(link.source) && link.relationship === "affects" ? [link.target, link.source] : null;
    if (pair) owned.set(pair[0]!, new Set([...(owned.get(pair[0]!) ?? []), pair[1]!]));
  }
  return Object.fromEntries([...owned].map(([id, ids]) => {
    const worst = [...ids].map(f => findings.get(f)!.severity).sort((a, b) => (rank[b] ?? 0) - (rank[a] ?? 0))[0] ?? "none";
    const layer = nodes.find(n => n.id === id)!.semantic_layer ?? "";
    const severity_counts: Record<string, number> = {};
    for (const finding of ids) { const severity = findings.get(finding)!.severity; severity_counts[severity] = (severity_counts[severity] ?? 0) + 1; }
    return [id, { semantic_layer: layer, aggregate: { issue_count: ids.size, severity_counts, worst_severity: worst, worst_severity_rank: rank[worst] ?? 0 } }];
  }));
}
