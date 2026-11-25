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
  const size = 18 / Math.max(zoom, 0.16);
  return (
    <div data-boundary-frame={data.frameFor} data-frame-links={data.frameLinks ?? 0} className="graph-boundary-frame pointer-events-none h-full w-full rounded-2xl border">
      <div className="graph-boundary-frame-title flex items-center" style={{ fontSize: size, gap: size * 0.6, top: size * 0.8, left: size, right: size }}>
        {provider && <GraphProviderMark source={provider} attributes={data.attributes} className="graph-provider-mark-frame" style={{ width: size * 1.7, height: size * 1.7 }} />}
        <div className="min-w-0 leading-tight">
          <div className="graph-boundary-frame-name truncate" title={data.label}>{data.label}</div>
          <div className="graph-boundary-frame-kind" style={{ fontSize: size * 0.72 }} title={`${data.frameLinks ?? 0} recorded containment links; remaining links show related investigation context`}>{provider?.label ? `${provider.label} · ` : ""}{data.readingLabel ?? "Environment"} context</div>
        </div>
      </div>
    </div>
  );
}
