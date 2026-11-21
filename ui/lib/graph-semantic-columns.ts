import type { GraphSemanticLayerKey } from "@/lib/graph-schema.generated";

/** The only UI ordering of backend semantic layers. Packages/findings attach
 * below their owner unless they are explicit hops of the selected path. */
export const SEMANTIC_LAYER_COLUMNS: Record<GraphSemanticLayerKey, number> = {
  user: 0, app: 1, api_gateway: 1, infra: 1, ci: 1,
  orchestration: 2, mcp_server: 3, tool: 4, identity: 4,
  runtime_evidence: 5, asset: 5, code: 1, package: 5, finding: 5,
};

export type SemanticNode = {
  id: string;
  data: { entityType?: string | undefined; nodeType?: string | undefined; semanticLayer?: string | null | undefined };
};
export type SemanticEdge = { source: string; target: string; data?: Record<string, unknown> | undefined };

export function semanticLayer(node: SemanticNode): GraphSemanticLayerKey | null {
  const layer = node.data.semanticLayer;
  if (!layer || !Object.hasOwn(SEMANTIC_LAYER_COLUMNS, layer)) {
    return null;
  }
  return layer as GraphSemanticLayerKey;
}

/** Position only: no relationship, identity, evidence or reachability is inferred. */
export function semanticColumns(nodes: SemanticNode[], _edges: SemanticEdge[], primary: readonly string[] = []): Map<string, number> {
  const layers = new Map(nodes.map(node => {
    const layer = semanticLayer(node);
    return [node.id, layer === null ? 6 : SEMANTIC_LAYER_COLUMNS[layer]];
  }));
  // Multiple explicit hops in one backend layer need separate slots on the
  // straight spine. Widen that layer without changing its semantic order.
  const spine = [...new Set(primary)].filter(id => layers.has(id));
  const starts = new Map<number, number>();
  let next = 0;
  for (let layer = 0; layer <= 6; layer++) {
    starts.set(layer, next);
    next += Math.max(1, spine.filter(id => layers.get(id) === layer).length);
  }
  return new Map(nodes.map(node => {
    const layer = layers.get(node.id)!;
    const slot = spine.filter(id => layers.get(id) === layer).indexOf(node.id);
    return [node.id, starts.get(layer)! + Math.max(0, slot)];
  }));
}
