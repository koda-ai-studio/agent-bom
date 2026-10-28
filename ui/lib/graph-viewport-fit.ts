type MeasuredNode = {
  id: string;
  position: { x: number; y: number };
  measured?: { width?: number | undefined; height?: number | undefined } | undefined;
  width?: number | undefined;
  height?: number | undefined;
};

type Viewport = { x: number; y: number; zoom: number };

/** Screen-pixel box, anchored bottom-left, that canvas controls cover. */
export type CanvasOverlay = { width: number; height: number };

/** React Flow's zoom controls at the canvas bottom-left (three 26px buttons at a 15px offset). */
export const CONTROLS_OVERLAY: Record<"vertical" | "horizontal", CanvasOverlay> = {
  vertical: { width: 41, height: 95 },
  horizontal: { width: 93, height: 41 },
};

/**
 * Readable node chrome re-measures larger after a fit (text and badges scale
 * with the zoom level), so the bottom row ends up this much lower than the
 * fit planned for. Reserved below the controls so no label lands under them.
 */
export const LABEL_GROWTH_PX = 56;

/** React Flow's pixel reading of a numeric fit padding on one axis (`@xyflow/system` parsePadding). */
export function fitPaddingPx(padding: number, size: number): number {
  return Math.floor((size - size / (1 + padding)) * 0.5);
}

/**
 * Fit padding that keeps nodes, labels included, clear of a bottom-left
 * control overlay: the numeric padding on top/right, and on bottom/left the
 * larger of that padding and the overlay, as pixels.
 */
export function fitPaddingAroundOverlay(padding: number, canvas: { width: number; height: number }, overlay: CanvasOverlay, labelGrowth = LABEL_GROWTH_PX): {
  top: number; right: number; bottom: number | `${number}px`; left: number | `${number}px`;
} {
  const gap = 8;
  if (!canvas.width || !canvas.height) return { top: padding, right: padding, bottom: padding, left: padding };
  const px = (value: number): `${number}px` => `${value}px`;
  return {
    top: padding,
    right: padding,
    bottom: px(Math.max(fitPaddingPx(padding, canvas.height), overlay.height + gap + labelGrowth)),
    left: px(Math.max(fitPaddingPx(padding, canvas.width), overlay.width + gap)),
  };
}

/**
 * Whether a viewport (restored from storage or persisted by an earlier
 * automatic fit on a differently sized canvas) still shows every node on the
 * canvas: each node's centre must lie inside it. Node chrome scales with the
 * zoom level, so an edge-to-edge test would reject a correct fit and shrink
 * the graph on every pass. Unmeasured nodes or an unsized canvas cannot be
 * judged yet and count as shown, so the caller waits for React Flow to
 * measure them.
 */
export function viewportShowsNodes(nodes: readonly MeasuredNode[], viewport: Viewport, canvas: { width: number; height: number }, overlay?: CanvasOverlay): boolean {
  if (!canvas.width || !canvas.height || nodes.length === 0) return true;
  for (const node of nodes) {
    const width = node.measured?.width ?? node.width;
    const height = node.measured?.height ?? node.height;
    if (!width || !height) return true;
    const left = node.position.x * viewport.zoom + viewport.x;
    const top = node.position.y * viewport.zoom + viewport.y;
    const right = left + width * viewport.zoom;
    const bottom = top + height * viewport.zoom;
    const centerX = (left + right) / 2;
    const centerY = (top + bottom) / 2;
    if (centerX < 0 || centerY < 0 || centerX > canvas.width || centerY > canvas.height) return false;
    // A node (label included) under the controls is covered, not shown.
    if (overlay && left < overlay.width && bottom > canvas.height - overlay.height) return false;
  }
  return true;
}
