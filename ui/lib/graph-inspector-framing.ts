/** Camera targets only: keep immediate recorded context beside a selected entity. */
export function graphInspectorTargets(anchorId: string, visibleIds: string[], edges: { source: string; target: string }[]) {
  const visible = new Set(visibleIds);
  const ids = new Set([anchorId]);
  for (const edge of edges) {
    if (edge.source === anchorId && visible.has(edge.target)) ids.add(edge.target);
    if (edge.target === anchorId && visible.has(edge.source)) ids.add(edge.source);
  }
  return [...(ids.size <= 6 ? ids : new Set([anchorId]))].map(id => ({ id }));
}
