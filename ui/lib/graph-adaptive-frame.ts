import { getViewportForBounds, type Rect } from "@xyflow/react";

/** Largest camera zoom for an automatic fit; card text already scales against zoom. */
export const GRAPH_FIT_MAX_ZOOM = 1;
/** Lowest automatic fit at which card names and metadata render at 12px or more. */
export const GRAPH_LEGIBLE_FIT_ZOOM = 0.4;
/** A phone's 220px cards wrap long names past their caption clamp below this zoom. */
export const GRAPH_PHONE_LEGIBLE_FIT_ZOOM = 0.7;

/** A phone's Graph view opens a dense graph on one full card, never a shrunken overview. */
export const GRAPH_PHONE_FOCUS_MIN_ZOOM = 0.85;

export function legibleFitZoom(width: number): number {
  return width >= 640 ? GRAPH_LEGIBLE_FIT_ZOOM : GRAPH_PHONE_LEGIBLE_FIT_ZOOM;
}

/** Geometry, not node count, determines the useful canvas and initial camera. */
export function graphAdaptiveFrame({ bounds, width, availableHeight, inspector, focusHeight = 0, focusPadding = 0.08 }: {
  bounds: Rect;
  width: number;
  availableHeight: number;
  inspector: boolean;
  /** Loaded cards. Accepted for callers; legibility is decided by zoom, not count. */
  nodeCount?: number;
  /** Measured height of the card a phone focuses when the graph is too dense to fit. */
  focusHeight?: number;
  /** React Flow numeric fit padding: the fitted box occupies height / (1 + padding). */
  focusPadding?: number;
}) {
  const ceiling = Math.max(240, availableHeight);
  const floor = Math.min(ceiling, inspector ? 432 : 320);
  const readableScale = Math.min(GRAPH_FIT_MAX_ZOOM, width / Math.max(1, bounds.width));
  const height = Math.round(Math.min(ceiling, Math.max(floor, bounds.height * readableScale + 64)));
  const viewport = getViewportForBounds(bounds, width, height, 0.05, 2, 0.08);
  // Zoom-compensated captions stay at 12px or more down to this scale, so the
  // whole graph opens framed. Denser graphs start at a neighbourhood; Fit all
  // still makes the complete returned topology available.
  const fitAll = viewport.zoom >= legibleFitZoom(width);
  // Chrome above a phone canvas can leave less room than one focused card at
  // its minimum zoom; the page scrolls, so grow the frame rather than clip it.
  const focusFloor = width < 640 && !fitAll && focusHeight > 0
    ? Math.ceil(focusHeight * GRAPH_PHONE_FOCUS_MIN_ZOOM * (1 + focusPadding))
    : 0;
  return { height: Math.max(height, focusFloor), fitAll, layoutAspect: Math.round(width / ceiling * 100) / 100 };
}
