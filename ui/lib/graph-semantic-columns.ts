import { GRAPH_NODE_KIND_META, GRAPH_SEMANTIC_LAYER_META, type GraphSemanticLayerKey } from "@/lib/graph-schema.generated";

const UNKNOWN_COLUMN = Math.max(...Object.values(GRAPH_SEMANTIC_LAYER_META).map(meta => meta.column)) + 1;

export type SemanticNode = {
  id: string;
  data: { entityType?: string | undefined; nodeType?: string | undefined; semanticLayer?: string | null | undefined };
};
export type SemanticEdge = { source: string; target: string; data?: Record<string, unknown> | undefined };

const isLayer = (value: unknown): value is GraphSemanticLayerKey => typeof value === "string" && Object.hasOwn(GRAPH_SEMANTIC_LAYER_META, value);

/** A node record's layer by the API's own rule (agent_bom.graph.semantic_layer): the stamped layer, else a layer the
 * producer recorded, else a surface that names one, else the entity kind's. Records some endpoints return unstamped
 * (lifecycle, neighbours, queries) land in the same column as on /v1/graph. */
export function recordSemanticLayer(record: { entity_type?: unknown; semantic_layer?: unknown; attributes?: Record<string, unknown> | null; dimensions?: { surface?: unknown } | null }): GraphSemanticLayerKey | undefined {
  if (isLayer(record.semantic_layer)) return record.semantic_layer;
  if (isLayer(record.attributes?.semantic_layer)) return record.attributes.semantic_layer;
  if (isLayer(record.dimensions?.surface)) return record.dimensions.surface;
  const kind = String(record.entity_type ?? "");
  return Object.hasOwn(GRAPH_NODE_KIND_META, kind) ? GRAPH_NODE_KIND_META[kind as keyof typeof GRAPH_NODE_KIND_META].layer : undefined;
}

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
