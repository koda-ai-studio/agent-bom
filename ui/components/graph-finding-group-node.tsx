"use client";
import { Handle, Position } from "@xyflow/react";
import { Binoculars } from "lucide-react";
import type { LineageNodeData } from "@/components/lineage-nodes";

/** A display group opens canonical finding nodes; it is never fetched as an asset. */
export function GraphFindingGroupNode({ data }: { data: LineageNodeData }) {
  const count = data.readingFindings?.count ?? 0;
  return <div className="relative flex w-60 flex-col items-center gap-2 text-center" data-graph-entity="finding-group">
    <button type="button" onClick={event => { event.stopPropagation(); data.readingFindings?.toggle(); }}
      aria-label={`Expand ${count} finding${count === 1 ? "" : "s"} for ${data.description ?? "component"}`}
      style={{ width: "var(--graph-node-glyph-size, 72px)", height: "var(--graph-node-glyph-size, 72px)" }}
      className="nodrag nopan graph-entity-glyph relative flex h-20 w-20 items-center justify-center rounded-full border-2 border-red-500 bg-red-50 text-red-700 shadow-sm dark:bg-red-950 dark:text-red-300 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-ring">
      <Handle type="target" position={Position.Left} className="opacity-0" />
      <Binoculars style={{ width: "var(--graph-node-icon-size, 32px)", height: "var(--graph-node-icon-size, 32px)" }} aria-hidden="true" />
      <span className="absolute -right-2 -top-2 min-w-6 rounded-full bg-red-700 px-1.5 text-sm font-semibold text-white">{count}</span>
    </button>
    <span style={{ fontSize: "var(--graph-node-label-size, 18px)" }} className="text-base font-semibold text-foreground">Findings</span>
    <span style={{ fontSize: "var(--graph-node-meta-size, 12px)" }} className="text-sm text-muted-foreground">Click to expand · {count} loaded</span>
  </div>;
}
