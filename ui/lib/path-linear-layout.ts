type PathNode = { id: string; position: { x: number; y: number }; data: object };

/** Preserve every recorded hop, with room for full labels and relationship captions. */
export function linearPathLayout<T extends PathNode>(
  nodes: T[], hops: readonly string[], containerWidth: number,
): { nodes: T[]; width: number } | null {
  const ordered = [...new Set(hops)];
  const onCanvas = new Set(nodes.map(node => node.id));
  if (!nodes.length || ordered.length !== nodes.length || ordered.some(id => !onCanvas.has(id))) return null;
  const index = new Map(ordered.map((id, position) => [id, position]));
  // Seven hops fit a full-width desktop canvas with 220-unit captions.
  // Preserve the readable zoom floor for longer paths or an expanded queue.
  const width = Math.ceil(((nodes.length - 1) * 240 + 220) * 0.7 + 96);
  return {
    width: Math.max(Number.isFinite(containerWidth) ? containerWidth : 0, width),
    nodes: nodes.map(node => ({ ...node, position: { x: index.get(node.id)! * 240, y: 0 },
      data: { ...node.data, reverseFlow: false } })),
  };
}
