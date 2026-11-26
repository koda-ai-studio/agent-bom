"use client";
import { COMPACT_GLYPH_SCALE } from "@/lib/graph-compact-glyph";
import { Handle, Position } from "@xyflow/react";
import { GraphCountHint } from "@/components/graph-count-hint";
import { Binoculars } from "lucide-react";
import type { LineageNodeData } from "@/components/lineage-nodes";

const HANDLE = "!h-1 !w-1 !border-0 !bg-transparent";
const GLYPH = `calc(var(--graph-node-glyph-size, 56px) * ${COMPACT_GLYPH_SCALE})`;

/** A display group opens canonical finding nodes; it is never fetched as an asset. */
export function GraphFindingGroupNode({ data }: { data: LineageNodeData }) {
  const count = data.readingFindings?.count ?? 0;
  const severity = data.readingFindings?.severity;
  return <div className="relative flex flex-col items-center text-center" style={{ width: "var(--graph-node-card-width, 240px)" }} data-graph-entity="finding-group">
    {/* Handles sit beside the button: an interactive element may not contain another. */}
    <div className="relative" style={{ width: GLYPH, height: GLYPH }}>
      <Handle type="target" position={data.phoneLayout ? Position.Top : Position.Left} className={HANDLE} />
      <Handle type="target" id="context" position={Position.Right} className={HANDLE} />
      {data.phoneLayout && <>
        <Handle type="target" id="phone-left" position={Position.Left} className={HANDLE} />
        <Handle type="target" id="phone-right" position={Position.Right} className={HANDLE} />
        <Handle type="target" id="phone-down" position={Position.Bottom} className={HANDLE} />
      </>}
      <GraphCountHint text={`${data.description}: ${count} linked findings${severity ? ` · highest severity: ${severity}` : " · severity not rated"}. Click to expand.`}><button type="button" onClick={event => { event.stopPropagation(); data.readingFindings?.toggle(); }}
        aria-label={`Expand ${count} finding${count === 1 ? "" : "s"} for ${data.description ?? "component"}`}
        style={{ width: GLYPH, height: GLYPH, ...(severity ? { borderColor: `var(--severity-ring-${severity})` } : {}) }}
        className="nodrag nopan graph-entity-glyph relative flex items-center justify-center rounded-full border-2 border-[var(--graph-edge-risk)] bg-surface text-[var(--graph-edge-risk)] focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-ring">
        <Binoculars style={{ width: `calc(var(--graph-node-icon-size, 28px) * ${COMPACT_GLYPH_SCALE})`, height: `calc(var(--graph-node-icon-size, 28px) * ${COMPACT_GLYPH_SCALE})` }} aria-hidden="true" />
      </button></GraphCountHint>
    </div>
    <span style={{ fontSize: "var(--graph-node-label-size, 14px)" }} className={`mt-[0.4em] whitespace-nowrap ${data.pathPresentation ? "font-normal" : "font-semibold"} leading-tight text-foreground`}>Findings ({count})</span>
    <span style={{ fontSize: "var(--graph-node-meta-size, 12px)" }} className="whitespace-nowrap leading-tight text-ink-secondary">{data.pathPresentation ? `${data.description} scope` : "Click to explore"}<span className="sr-only"> · {count} findings</span></span>
  </div>;
}
