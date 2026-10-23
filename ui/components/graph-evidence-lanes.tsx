"use client";

import { ViewportPortal } from "@xyflow/react";
import type { InvestigationLane } from "@/lib/graph-investigation-context";

/** Presentation guides stay outside the graph's entity/edge data. */
export function GraphEvidenceLanes({ lanes, zoom }: { lanes: InvestigationLane[]; zoom: number }) {
  return <ViewportPortal>
    {lanes.map(lane => <section key={lane.id} data-testid="graph-evidence-lane" aria-label={lane.label}
      className="pointer-events-none absolute rounded-2xl border-2 border-outline bg-surface-elevated/40"
      style={{ left: lane.x, top: lane.y, width: lane.width, height: lane.height, zIndex: -1 }}>
      <div className="px-8 pt-4 font-semibold text-foreground" style={{ fontSize: Math.min(34, 15 / Math.max(zoom, 0.16)) }}>
        {lane.label}
      </div>
    </section>)}
  </ViewportPortal>;
}
