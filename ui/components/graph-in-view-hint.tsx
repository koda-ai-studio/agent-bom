"use client";

import { Panel, useStore } from "@xyflow/react";

const FALLBACK_WIDTH = 220, FALLBACK_HEIGHT = 224;

/** Says how much of a map too large for one screen is in view, and how to reach the rest. */
export function GraphInViewHint() {
  const counts = useStore(state => {
    const [x, y, zoom] = state.transform;
    let total = 0, inView = 0;
    for (const node of state.nodes) {
      if (node.hidden || (node.data as { displayOnly?: boolean }).displayOnly) continue;
      total++;
      const left = node.position.x * zoom + x, top = node.position.y * zoom + y;
      const right = left + (node.measured?.width ?? FALLBACK_WIDTH) * zoom, bottom = top + (node.measured?.height ?? FALLBACK_HEIGHT) * zoom;
      if (left >= -1 && top >= -1 && right <= state.width + 1 && bottom <= state.height + 1) inView++;
    }
    return `${inView}/${total}`;
  });
  const [inView, total] = counts.split("/").map(Number) as [number, number];
  if (!total || inView >= total) return null;
  return <Panel position="bottom-center" className="pointer-events-none">
    <p data-testid="graph-in-view" className="rounded-md border border-outline bg-surface px-2 py-1 text-center text-xs text-ink-secondary shadow-sm">
      Showing {inView} of {total} nodes · Fit all shows the rest · drag to move
    </p>
  </Panel>;
}
