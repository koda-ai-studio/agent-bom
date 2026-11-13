import type { AttackPathLayout } from "@/lib/attack-path-graph-layout";

/** Frame padding in screen px; the bottom keeps nodes clear of the zoom controls in that corner. */
export const ATTACK_PATH_FIT_PADDING = { top: 24, right: 24, bottom: 56, left: 24 } as const;

export type AttackPathViewport = {
  x: number;
  y: number;
  zoom: number;
  /** True when the whole graph would fall below the readable floor and the selected path is framed instead. */
  fallback: boolean;
  /** Nodes not wholly inside the pane at this camera. */
  hiddenNodeIds: string[];
};

type Box = { x: number; y: number; width: number; height: number };

function boundsOf(layout: Pick<AttackPathLayout, "positions" | "nodeWidth" | "nodeHeight">, ids: readonly string[]): Box | null {
  const points = ids.map(id => layout.positions.get(id)).filter((point): point is { x: number; y: number } => Boolean(point));
  if (points.length === 0) return null;
  const x = Math.min(...points.map(point => point.x)), y = Math.min(...points.map(point => point.y));
  return {
    x, y,
    width: Math.max(...points.map(point => point.x)) + layout.nodeWidth - x,
    height: Math.max(...points.map(point => point.y)) + layout.nodeHeight - y,
  };
}

/**
 * The camera for the path graph. The whole graph is fitted inside the padded
 * pane; only when that would need a zoom below `floor` does the camera keep
 * `floor`, centre the selected path (or start at its entry when even the path
 * is wider) and report what is left off screen.
 */
export function attackPathViewport(
  layout: Pick<AttackPathLayout, "positions" | "width" | "height" | "nodeWidth" | "nodeHeight"> & Partial<Pick<AttackPathLayout, "direction">>,
  spineIds: readonly string[],
  pane: { width: number; height: number },
  floor: number,
  options: { maxZoom?: number; minZoom?: number } = {},
): AttackPathViewport {
  const pad = ATTACK_PATH_FIT_PADDING;
  const usableWidth = Math.max(1, pane.width - pad.left - pad.right);
  const usableHeight = Math.max(1, pane.height - pad.top - pad.bottom);
  const whole: Box = { x: 0, y: 0, width: layout.width, height: layout.height };
  const fitted = Math.min(options.maxZoom ?? 1, usableWidth / whole.width, usableHeight / whole.height);
  const lowest = options.minZoom ?? floor;
  const centre = (box: Box, zoom: number) => ({
    x: pad.left + (usableWidth - box.width * zoom) / 2 - box.x * zoom,
    y: pad.top + (usableHeight - box.height * zoom) / 2 - box.y * zoom,
  });
  let zoom = Math.max(fitted, lowest);
  let { x, y } = centre(whole, zoom);
  const fallback = fitted < lowest;
  const spineBox = boundsOf(layout, spineIds);
  if (!fallback && layout.direction === "TB" && spineBox) {
    // A vertical path reads down the middle of the phone: centre its column. Branches pushed past the
    // edge are listed in `hiddenNodeIds`, which the canvas names with a "Fit all" action.
    x = centre(spineBox, zoom).x;
  }
  if (fallback) {
    zoom = lowest;
    const spine = boundsOf(layout, spineIds) ?? whole;
    const spineFits = spine.width * zoom <= usableWidth;
    x = spineFits ? centre(spine, zoom).x : pad.left - spine.x * zoom;
    // Rows above and below stay centred on the path when they cannot all fit.
    y = whole.height * zoom <= usableHeight ? centre(whole, zoom).y : centre(spine, zoom).y;
  }
  const hiddenNodeIds = [...layout.positions].filter(([, position]) => {
    const left = x + position.x * zoom, top = y + position.y * zoom;
    return left < -0.5 || top < -0.5 || left + layout.nodeWidth * zoom > pane.width + 0.5 || top + layout.nodeHeight * zoom > pane.height + 0.5;
  }).map(([id]) => id);
  return { x, y, zoom, fallback, hiddenNodeIds };
}
