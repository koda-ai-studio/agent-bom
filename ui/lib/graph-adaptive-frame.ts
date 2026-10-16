import { getViewportForBounds, type Rect } from "@xyflow/react";

/** Geometry, not node count, determines the useful canvas and initial camera. */
export function graphAdaptiveFrame({ bounds, width, availableHeight, inspector }: {
  bounds: Rect;
  width: number;
  availableHeight: number;
  inspector: boolean;
}) {
  const ceiling = Math.max(240, availableHeight);
  const floor = Math.min(ceiling, inspector ? 432 : 320);
  const readableScale = Math.min(1.25, width / Math.max(1, bounds.width));
  const height = Math.round(Math.min(ceiling, Math.max(floor, bounds.height * readableScale + 64)));
  const viewport = getViewportForBounds(bounds, width, height, 0.05, 2, 0.08);
  // Below this scale full cards become hard to read. Start at a neighborhood;
  // explicit Fit all still makes the complete returned topology available.
  return { height, fitAll: viewport.zoom >= 0.7 };
}
