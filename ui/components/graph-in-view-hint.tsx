"use client";

import { useStore } from "@xyflow/react";

const FALLBACK_WIDTH = 220, FALLBACK_HEIGHT = 224;

export interface EdgeNote {
  drawn: number;
  total: number;
  /** Connections set aside until an operator asks for them; zero when none are. */
  held: number;
  allShown: boolean;
  onToggle: (showAll: boolean) => void;
}

/** Says how much of a map too large for one screen is in view, and how to reach the rest; a strip, so it never covers a card. */
export function GraphInViewHint({ edges }: { edges?: EdgeNote | undefined }) {
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
  const partial = total > 0 && inView < total;
  const quieting = Boolean(edges && (edges.held > 0 || edges.allShown));
  if (!partial && !quieting) return null;
  return <div data-testid="graph-in-view-strip" className="flex shrink-0 flex-wrap items-center justify-center gap-x-3 border-b border-outline px-2 py-0.5 text-center text-xs text-ink-secondary">
    {partial && <p data-testid="graph-in-view">Showing {inView} of {total} nodes · drag to see the rest<span className="max-sm:hidden"> · Fit all stays readable</span></p>}
    {quieting && edges && <p data-testid="graph-edge-note">
      {edges.drawn.toLocaleString()} of {edges.total.toLocaleString()} connections drawn
      {edges.held > 0 && <> · <span className="max-sm:hidden">hover or select a node for the rest</span><span className="sm:hidden">tap a node</span> · </>}
      {edges.allShown
        ? <> · <button type="button" className="text-foreground underline underline-offset-2" onClick={() => edges.onToggle(false)}>Quiet long connections</button></>
        : edges.held > 0 && <button type="button" className="text-foreground underline underline-offset-2" onClick={() => edges.onToggle(true)}>Show all</button>}
    </p>}
  </div>;
}
