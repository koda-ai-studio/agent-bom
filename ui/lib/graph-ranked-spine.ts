/** Select a complete visible witness in server ranking order, never a partial chain. */
export function rankedVisiblePath(
  nodes: readonly { id: string; hidden?: boolean }[],
  edges: readonly { source: string; target: string; hidden?: boolean; data?: Record<string, unknown> }[],
  paths: readonly { hops: string[]; edges?: string[]; composite_risk: number }[],
) {
  const ids = new Set(nodes.filter(node => !node.hidden).map(node => node.id));
  const links = new Map<string, Set<unknown>>();
  for (const edge of edges) {
    if (edge.hidden || edge.data?.traversable !== true) continue;
    const key = JSON.stringify([edge.source, edge.target]);
    const relationships = links.get(key) ?? new Set();
    relationships.add(edge.data.relationship); links.set(key, relationships);
  }
  return paths.find(path => path.hops.length > 1 && path.hops.every(id => ids.has(id))
    && (!path.edges?.length || path.edges.length === path.hops.length - 1)
    && path.hops.slice(1).every((id, i) => {
      const relationships = links.get(JSON.stringify([path.hops[i], id]));
      return relationships && (!path.edges?.length || relationships.has(path.edges[i]));
    }));
}

export function rankedVisibleSpine(...args: Parameters<typeof rankedVisiblePath>): string[] {
  return rankedVisiblePath(...args)?.hops ?? [];
}
