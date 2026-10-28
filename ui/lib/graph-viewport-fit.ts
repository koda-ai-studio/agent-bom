type MeasuredNode = {
  id: string;
  position: { x: number; y: number };
  measured?: { width?: number | undefined; height?: number | undefined } | undefined;
  width?: number | undefined;
  height?: number | undefined;
};

type Viewport = { x: number; y: number; zoom: number };

/**
 * Whether a viewport (restored from storage or persisted by an earlier
 * automatic fit on a differently sized canvas) still shows every node on the
 * canvas: each node's centre must lie inside it. Node chrome scales with the
 * zoom level, so an edge-to-edge test would reject a correct fit and shrink
 * the graph on every pass. Unmeasured nodes or an unsized canvas cannot be
 * judged yet and count as shown, so the caller waits for React Flow to
 * measure them.
 */
export function viewportShowsNodes(nodes: readonly MeasuredNode[], viewport: Viewport, canvas: { width: number; height: number }): boolean {
  if (!canvas.width || !canvas.height || nodes.length === 0) return true;
  for (const node of nodes) {
    const width = node.measured?.width ?? node.width;
    const height = node.measured?.height ?? node.height;
    if (!width || !height) return true;
    const centerX = (node.position.x + width / 2) * viewport.zoom + viewport.x;
    const centerY = (node.position.y + height / 2) * viewport.zoom + viewport.y;
    if (centerX < 0 || centerY < 0 || centerX > canvas.width || centerY > canvas.height) return false;
  }
  return true;
}
