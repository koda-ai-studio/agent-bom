"use client";

import { Handle, Position, type NodeProps, type Node } from "@xyflow/react";
import { Bug, Layers } from "lucide-react";
import { Fragment, type CSSProperties } from "react";

import { entityIcon } from "@/lib/entity-icons";
import { lineageNodeTypeForEntity } from "@/lib/graph-entity-mapping";
import { NODE_COLOR_MAP } from "@/lib/graph-utils";
import type { PathGraphNode } from "@/lib/attack-path-graph-model";
import { MARKER_META, type NodeContextMarker } from "@/lib/attack-path-graph-markers";
import { PATH_NODE } from "@/lib/attack-path-graph-layout";
import { GLYPH_CENTER_Y, glyphInsetX } from "@/lib/attack-path-graph-routes";
import { labelSegments } from "@/lib/graph-label-breaks";

export type AttackPathNodeData = {
  node: PathGraphNode;
  vertical: boolean;
  onOpenFindings: (nodeId: string, findingIds: string[]) => void;
  onExpandGroup: (groupId: string) => void;
};
export type AttackPathFlowNode = Node<AttackPathNodeData, "attackPathNode">;

const GLYPH_INSET_X = glyphInsetX(PATH_NODE.width);
const BOX: CSSProperties = { width: PATH_NODE.width, height: PATH_NODE.height };
/** Names wrap to two lines under the glyph, only at a separator, before truncating; the full name is on hover. */
const NAME = "pointer-events-auto block w-full rounded-t bg-surface px-1 pt-0.5 text-[15px] font-semibold leading-tight line-clamp-2 [overflow-wrap:normal] [word-break:normal]";
const SUBTITLE = "pointer-events-auto block w-full truncate rounded-b bg-surface px-1 pb-0.5 pt-0.5 text-[13px] leading-tight";
const RATED = new Set(["critical", "high", "medium", "low"]);
const ROLE_CAPTION: Record<PathGraphNode["role"], string> = { entry: "Entry", path: "", target: "At risk", branch: "" };

export function severityStyle(severity: string): CSSProperties {
  if (!RATED.has(severity)) return { background: "var(--surface-elevated)", borderColor: "var(--border-strong)", color: "var(--foreground)" };
  return {
    background: `linear-gradient(var(--severity-${severity}-bg), var(--severity-${severity}-bg)), var(--surface)`,
    borderColor: `var(--severity-${severity}-border)`,
    color: `var(--severity-${severity})`,
  };
}

/** The visible name with a break opportunity after each separator, so no line ends inside a token. */
export function NodeName({ label, className }: { label: string; className: string }) {
  return (
    <span data-node-label className={className} title={label} aria-label={label}>
      {labelSegments(label, 16).map((segment, index, all) => <Fragment key={index}>{segment}{index < all.length - 1 ? <wbr /> : null}</Fragment>)}
    </span>
  );
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

/** Counts per severity, worst first, e.g. "1 critical, 1 medium". */
function severityBreakdown(findings: PathGraphNode["findings"]): { severity: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const finding of findings) {
    const severity = RATED.has(finding.severity) ? finding.severity : "unrated";
    counts.set(severity, (counts.get(severity) ?? 0) + 1);
  }
  return [...counts].map(([severity, count]) => ({ severity, count }))
    .sort((a, b) => (SEVERITY_ORDER.indexOf(a.severity) + 5) % 5 - (SEVERITY_ORDER.indexOf(b.severity) + 5) % 5);
}

function FindingBadge({ node, onOpen }: { node: PathGraphNode; onOpen: AttackPathNodeData["onOpenFindings"] }) {
  const count = node.findings.length;
  const worst = node.findings[0]!.severity;
  const breakdown = severityBreakdown(node.findings);
  const top = breakdown[0]!;
  const rest = count - top.count;
  const summary = breakdown.map(item => `${item.count} ${item.severity}`).join(", ");
  const label = `${count} ${count === 1 ? "finding" : "findings"} on ${node.label}, worst ${RATED.has(worst) ? worst : "unrated"} (${summary}). Open findings`;
  return (
    <button type="button" aria-label={label} title={label.replace(". Open findings", "")} data-severity={worst} data-node-badge="findings"
      onClick={event => { event.stopPropagation(); onOpen(node.id, node.findings.map(finding => finding.id)); }}
      className="nodrag nopan absolute left-[calc(100%-12px)] -top-4 z-10 inline-flex h-6 items-center gap-1 whitespace-nowrap rounded-full border px-1.5 text-[13px] font-semibold tabular-nums shadow-sm focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[color:var(--focus-ring)]"
      style={severityStyle(worst)}>
      <Bug className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />{`${top.count} ${top.severity}`}{rest > 0 ? <span className="font-medium opacity-80">{` +${rest}`}</span> : null}
    </button>
  );
}

function Markers({ markers }: { markers: NodeContextMarker[] }) {
  if (markers.length === 0) return null;
  return (
    // A row above the glyph, growing left, so no marker sits where an edge enters.
    <span className="absolute -top-3 right-[calc(100%-14px)] z-10 flex flex-row-reverse gap-0.5">
      {markers.map(marker => {
        const Icon = MARKER_META[marker.kind].Icon;
        return (
          <span key={marker.kind} role="img" aria-label={marker.label} title={marker.label} data-marker={marker.kind}
            className="inline-flex h-6 w-6 items-center justify-center rounded-full border border-outline-strong bg-surface text-foreground shadow-sm">
            <Icon className="h-3.5 w-3.5" aria-hidden="true" />
          </span>
        );
      })}
    </span>
  );
}

function Handles({ vertical }: { vertical: boolean }) {
  const hidden = "!h-1 !w-1 !min-h-0 !min-w-0 !border-0 !bg-transparent";
  return vertical ? <>
    <Handle type="target" position={Position.Top} className={hidden} />
    <Handle type="source" position={Position.Bottom} className={hidden} />
  </> : <>
    <Handle type="target" position={Position.Left} className={hidden} style={{ top: GLYPH_CENTER_Y, left: GLYPH_INSET_X }} />
    <Handle type="source" position={Position.Right} className={hidden} style={{ top: GLYPH_CENTER_Y, right: GLYPH_INSET_X }} />
  </>;
}

export function AttackPathGraphNode({ data }: NodeProps<AttackPathFlowNode>) {
  const { node, vertical } = data;
  if (node.kind === "group") return <GroupNode data={data} />;
  const lineageType = lineageNodeTypeForEntity(node.entityType);
  const Icon = entityIcon(lineageType ?? undefined);
  const tint = lineageType ? NODE_COLOR_MAP[lineageType] : undefined;
  const spine = node.role !== "branch";
  const caption = ROLE_CAPTION[node.role];
  return (
    <div data-testid={`attack-path-node-${node.id}`} data-role={node.role} title={`${node.label} · ${node.typeLabel}`}
      style={BOX} className="pointer-events-none flex flex-col items-center text-center">
      <Handles vertical={vertical} />
      <div data-node-glyph className={`pointer-events-auto relative mt-1.5 flex h-14 w-14 items-center justify-center rounded-full bg-surface-elevated text-foreground ${spine ? "border-[2.5px] border-[color:var(--accent)]" : "border border-outline"}`}
        style={tint ? { backgroundImage: `linear-gradient(color-mix(in srgb, ${tint} ${spine ? 24 : 12}%, transparent), color-mix(in srgb, ${tint} ${spine ? 24 : 12}%, transparent))` } : undefined}>
        <Icon className="h-7 w-7" aria-hidden="true" />
        <Markers markers={node.markers} />
        {node.findings.length > 0 && <FindingBadge node={node} onOpen={data.onOpenFindings} />}
      </div>
      {/* Below the glyph no line ever runs, so the whole name block takes clicks. */}
      <div data-node-label className="pointer-events-auto w-full flex-1 pt-2">
      <NodeName label={node.label} className={`${NAME} ${spine ? "text-foreground" : "text-ink-secondary"}`} />
      <span data-node-label className={`${SUBTITLE} ${spine ? "text-ink-secondary" : "text-ink-tertiary"}`}>
        {node.typeLabel}{caption ? <span className="font-medium text-foreground"> · {caption}</span> : null}
      </span>
      </div>
    </div>
  );
}

function GroupNode({ data }: { data: AttackPathNodeData }) {
  const { node, vertical } = data;
  return (
    <div data-testid={`attack-path-node-${node.id}`} data-role="group" title={`${node.label} share this connection`}
      style={BOX} className="pointer-events-none flex flex-col items-center text-center">
      <Handles vertical={vertical} />
      <div data-node-glyph className="pointer-events-auto relative mt-1.5 flex h-14 w-14 items-center justify-center rounded-full border border-dashed border-outline-strong bg-surface-elevated text-foreground">
        <Layers className="h-5 w-5" aria-hidden="true" />
        {node.findings.length > 0 && <FindingBadge node={node} onOpen={data.onOpenFindings} />}
      </div>
      <NodeName label={node.label} className={`mt-2 ${NAME} text-ink-secondary`} />
      <button type="button" aria-label={`Expand ${node.label}`}
        onClick={event => { event.stopPropagation(); data.onExpandGroup(node.id); }}
        className="pointer-events-auto nodrag nopan rounded-b bg-surface px-1 text-xs font-medium text-[color:var(--accent)] underline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-[color:var(--focus-ring)]">
        Expand
      </button>
    </div>
  );
}

export const attackPathNodeTypes = { attackPathNode: AttackPathGraphNode };
