"use client";

import { useStore } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { GraphProviderMark } from "@/components/graph-provider-mark";
import { entitySource } from "@/lib/agent-source";

/** Recorded scope and related investigation context, with its own visible boundary. */
export function GraphBoundaryFrame({ data }: { data: LineageNodeData }) {
  const provider = entitySource(data);
  // The title reads at caption size on screen whatever the fit zoom, as captions do.
  const zoom = useStore(state => state.transform[2]);
  const size = 14 / Math.max(zoom, 0.16);
  return (
    <div data-boundary-frame={data.frameFor} data-frame-links={data.frameLinks ?? 0} className="graph-boundary-frame pointer-events-none h-full w-full rounded-2xl border">
      <div className="graph-boundary-frame-title flex items-center" style={{ fontSize: size, gap: size * 0.5, top: size, left: size * 1.2 }}>
        {provider && <GraphProviderMark source={provider} attributes={data.attributes} className="graph-provider-mark-frame" style={{ width: size * 1.7, height: size * 1.7 }} />}
        <span className="graph-boundary-frame-name">{data.label}</span>
        <span className="graph-boundary-frame-kind" title={`${data.frameLinks ?? 0} recorded containment links; remaining links show related investigation context`}>{data.readingLabel ?? "Environment"} context</span>
      </div>
    </div>
  );
}
