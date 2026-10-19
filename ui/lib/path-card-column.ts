/** Longest path stacked whole on a phone; longer paths keep the node stepper. */
export const COLUMN_MAX_NODES = 6;
/** Vertical distance between hops, in flow units: card plus a gap for the edge chip. */
export const COLUMN_STEP = 250;
/** Fitted zoom for the column; keeps names at full width and leaves the chip gap legible. */
export const COLUMN_ZOOM = 0.7;
const CARD_FLOW_HEIGHT = 180;
const TOOLBAR_PX = 56;
const FIT_PADDING_PX = { top: 16, bottom: 56 };
const MIN_PX = 288;
const MAX_PX = 1080;

export const COLUMN_FIT_OPTIONS = {
  padding: { top: `${FIT_PADDING_PX.top}px`, bottom: `${FIT_PADDING_PX.bottom}px`, x: "12px" },
  maxZoom: COLUMN_ZOOM,
  minZoom: 0.3,
} as const;

export function usesColumnPath({ narrow, focusMode, nodeCount }: {
  narrow: boolean; focusMode: boolean; nodeCount: number;
}): boolean {
  return narrow && focusMode && nodeCount > 0 && nodeCount <= COLUMN_MAX_NODES;
}

type PositionedNode = { id: string; position: { x: number; y: number }; data: object };

/** One hop per row, in path order; anything other than exactly the path is returned unchanged. */
export function applyColumnPath<T extends PositionedNode>(nodes: T[], pathIds: readonly string[]): T[] {
  const onCanvas = new Set(nodes.map(node => node.id));
  const ordered = pathIds.filter((id, index) => onCanvas.has(id) && pathIds.indexOf(id) === index);
  if (ordered.length !== nodes.length || nodes.length === 0) return nodes;
  const row = new Map(ordered.map((id, index) => [id, index]));
  return nodes.map(node => ({
    ...node,
    position: { x: 0, y: row.get(node.id)! * COLUMN_STEP },
    data: { ...node.data, reverseFlow: false },
  }));
}

/** Canvas tall enough to show every row at the column zoom, plus toolbar and controls. */
export function columnCanvasHeight(rows: number): number {
  if (rows <= 0) return MIN_PX;
  const content = ((rows - 1) * COLUMN_STEP + CARD_FLOW_HEIGHT) * COLUMN_ZOOM;
  const height = Math.ceil(TOOLBAR_PX + FIT_PADDING_PX.top + FIT_PADDING_PX.bottom + content);
  return Math.min(MAX_PX, Math.max(MIN_PX, height));
}

/**
 * A stacked hop runs from under the source card (clear of its name) to the top
 * of the next glyph. Both glyph handles sit on the shared centre line, so the
 * centre and radius follow from the right-hand source and left-hand target port.
 */
export function columnEdgePath(
  edge: { sourceX: number; sourceY: number; targetX: number; targetY: number },
  sourceBottom: number,
): [string, number, number] {
  const centre = (edge.sourceX + edge.targetX) / 2;
  const radius = Math.abs(edge.sourceX - edge.targetX) / 2;
  const end = edge.targetY - radius;
  const start = Math.min(sourceBottom, end);
  return [`M${centre},${start} L${centre},${end}`, centre, (start + end) / 2];
}

/** Mark the links between consecutive hops; other recorded links keep their routing. */
export function columnFlowEdges<T extends { source: string; target: string; data?: Record<string, unknown> | undefined }>(
  edges: T[],
  pathIds: readonly string[],
): T[] {
  const index = new Map(pathIds.map((id, position) => [id, position]));
  return edges.map(edge => {
    const from = index.get(edge.source);
    const to = index.get(edge.target);
    const consecutive = from !== undefined && to !== undefined && to === from + 1;
    return consecutive ? { ...edge, data: { ...edge.data, columnFlow: true } } : edge;
  });
}
