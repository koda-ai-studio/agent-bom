/**
 * Serpentine layout for a single ordered path. A long path laid out on one row
 * forces fit-to-canvas to shrink labels below legibility; wrapping it into
 * rows that alternate direction keeps every hop adjacent to the next and lets
 * each row turn on one side (see `relationship-routing.ts`).
 */
export interface SerpentineStep {
  column: number;
  row: number;
  nodeWidth: number;
  nodeHeight: number;
  /** Horizontal room reserved for the row-turn lane and its caption. */
  lane: number;
}

export const PATH_SERPENTINE_STEP: SerpentineStep = {
  column: 340,
  row: 280,
  nodeWidth: 240,
  nodeHeight: 200,
  lane: 80,
};

export interface SerpentinePlan {
  columns: number;
  rows: number;
  zoom: number;
  width: number;
  height: number;
  canvasHeight: number;
}

const NARROW_CANVAS_PX = 640;

export function planSerpentinePath(
  count: number,
  {
    containerWidth,
    maxCanvasHeight,
    minCanvasHeight = 260,
    maxZoom = 1.15,
    padding = 0.06,
    step = PATH_SERPENTINE_STEP,
  }: {
    containerWidth: number;
    maxCanvasHeight: number;
    minCanvasHeight?: number;
    maxZoom?: number;
    padding?: number;
    step?: SerpentineStep;
  },
): SerpentinePlan {
  const total = Math.max(1, Math.floor(Number.isFinite(count) ? count : 1));
  const width = Number.isFinite(containerWidth) && containerWidth > 0 ? containerWidth : NARROW_CANVAS_PX;
  const frame = 1 + 2 * padding;
  const measure = (columns: number) => {
    const rows = Math.ceil(total / columns);
    const contentWidth = (columns - 1) * step.column + step.nodeWidth + (rows > 1 ? 2 * step.lane : 0);
    const contentHeight = (rows - 1) * step.row + step.nodeHeight;
    const zoom = Math.min(maxZoom, width / (contentWidth * frame), maxCanvasHeight / (contentHeight * frame));
    return { columns, rows, zoom, width: contentWidth, height: contentHeight };
  };
  let best = measure(1);
  if (width >= NARROW_CANVAS_PX) {
    for (let columns = 2; columns <= total; columns += 1) {
      const candidate = measure(columns);
      if (candidate.zoom >= best.zoom - 1e-6) best = candidate;
    }
  }
  const canvasHeight = Math.min(
    maxCanvasHeight,
    Math.max(minCanvasHeight, Math.ceil(best.height * best.zoom * frame)),
  );
  return { ...best, canvasHeight };
}

export function serpentinePositions(
  orderedIds: readonly string[],
  columns: number,
  step: Pick<SerpentineStep, "column" | "row">,
): Map<string, { x: number; y: number; reverse: boolean }> {
  const perRow = Math.max(1, Math.floor(columns));
  return new Map(orderedIds.map((id, index) => {
    const row = Math.floor(index / perRow);
    const column = index % perRow;
    const reverse = row % 2 === 1;
    return [id, { x: (reverse ? perRow - 1 - column : column) * step.column, y: row * step.row, reverse }];
  }));
}

type PositionedNode = { id: string; position: { x: number; y: number }; data: object };

/** Reflow a canvas that holds exactly one ordered path; anything else is returned unchanged. */
export function applySerpentinePath<T extends PositionedNode>(
  nodes: T[],
  pathIds: readonly string[],
  columns: number,
  step: Pick<SerpentineStep, "column" | "row"> = PATH_SERPENTINE_STEP,
): T[] {
  const onCanvas = new Set(nodes.map((node) => node.id));
  const ordered = pathIds.filter((id, index) => onCanvas.has(id) && pathIds.indexOf(id) === index);
  if (ordered.length !== nodes.length || nodes.length === 0) return nodes;
  const positions = serpentinePositions(ordered, columns, step);
  return nodes.map((node) => {
    const next = positions.get(node.id)!;
    return { ...node, position: { x: next.x, y: next.y }, data: { ...node.data, reverseFlow: next.reverse } };
  });
}
