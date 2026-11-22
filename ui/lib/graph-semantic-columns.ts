import { GRAPH_SEMANTIC_LAYER_META, type GraphSemanticLayerKey } from "@/lib/graph-schema.generated";

const UNKNOWN_COLUMN = Math.max(...Object.values(GRAPH_SEMANTIC_LAYER_META).map(meta => meta.column)) + 1;

export type SemanticNode = {
  id: string;
  data: { entityType?: string | undefined; nodeType?: string | undefined; semanticLayer?: string | null | undefined };
};
export type SemanticEdge = { source: string; target: string; data?: Record<string, unknown> | undefined };

export function semanticLayer(node: SemanticNode): GraphSemanticLayerKey | null {
  const layer = node.data.semanticLayer;
  if (!layer || !Object.hasOwn(GRAPH_SEMANTIC_LAYER_META, layer)) {
    return null;
  }
  return layer as GraphSemanticLayerKey;
}

/** Position only: no relationship, identity, evidence or reachability is inferred. */
export function semanticColumns(nodes: SemanticNode[], _edges: SemanticEdge[], primary: readonly string[] = []): Map<string, number> {
  const layers = new Map(nodes.map(node => {
    const layer = semanticLayer(node);
    return [node.id, layer === null ? UNKNOWN_COLUMN : GRAPH_SEMANTIC_LAYER_META[layer].column];
  }));
  // Multiple explicit hops in one backend layer need separate slots on the
  // straight spine. Widen that layer without changing its semantic order.
  const spine = [...new Set(primary)].filter(id => layers.has(id));
  const starts = new Map<number, number>();
  let next = 0;
  for (let layer = 0; layer <= UNKNOWN_COLUMN; layer++) {
    starts.set(layer, next);
    next += Math.max(1, spine.filter(id => layers.get(id) === layer).length);
  }
  return new Map(nodes.map(node => {
    const layer = layers.get(node.id)!;
    const slot = spine.filter(id => layers.get(id) === layer).indexOf(node.id);
    return [node.id, starts.get(layer)! + Math.max(0, slot)];
  }));
}
