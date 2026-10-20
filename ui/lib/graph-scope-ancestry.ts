import type { GraphNodeDetailResponse } from "@/lib/api-types";
import type { ScopeCrumb } from "@/lib/graph-scope-crumbs";

/** Deepest containment chain resolved for a deep link; real estates nest org → account → environment → workload. */
export const SCOPE_ANCESTRY_MAX_DEPTH = 8;

type NodeReader = (nodeId: string, scanId?: string) => Promise<Pick<GraphNodeDetailResponse, "node" | "edges_in">>;

/**
 * Ancestors of a deep-linked scope, root first, from recorded CONTAINS edges.
 * A failed read or a cycle ends the walk; ancestors are never guessed.
 */
export async function resolveScopeAncestry(read: NodeReader, nodeId: string, scanId: string): Promise<ScopeCrumb[]> {
  const chain: ScopeCrumb[] = [];
  const seen = new Set([nodeId]);
  let current = nodeId;
  for (let depth = 0; depth < SCOPE_ANCESTRY_MAX_DEPTH; depth++) {
    let detail: Awaited<ReturnType<NodeReader>>;
    try {
      detail = await read(current, scanId);
    } catch {
      break;
    }
    if (depth > 0) chain[0] = { id: current, label: detail.node?.label || current };
    const parent = detail.edges_in?.find(edge => String(edge.relationship) === "contains")?.source;
    if (!parent || seen.has(parent)) break;
    seen.add(parent);
    chain.unshift({ id: parent, label: parent });
    current = parent;
  }
  return chain;
}
