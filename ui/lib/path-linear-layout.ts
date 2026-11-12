type PathNode = { id: string; position: { x: number; y: number }; data: object };

/** Preserve every recorded hop, with room for full labels and relationship captions. */
export function linearPathLayout<T extends PathNode>(
  nodes: T[], hops: readonly string[], containerWidth: number,
): { nodes: T[]; width: number } | null {
  const ordered = [...new Set(hops)];
  const onCanvas = new Set(nodes.map(node => node.id));
  if (!nodes.length || ordered.length !== nodes.length || ordered.some(id => !onCanvas.has(id))) return null;
  const index = new Map(ordered.map((id, position) => [id, position]));
  // Reserve a 300-unit caption footprint, a 120-unit edge gap and 0.75 zoom.
  // The scroll surface grows instead of shrinking the path below readable size.
  const width = Math.ceil(((nodes.length - 1) * 420 + 300) * 0.75 + 120);
  return {
    width: Math.max(Number.isFinite(containerWidth) ? containerWidth : 0, width),
    nodes: nodes.map(node => ({ ...node, position: { x: index.get(node.id)! * 420, y: 0 },
      data: { ...node.data, reverseFlow: false } })),
  };
}
