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
