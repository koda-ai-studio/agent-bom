"use client";

import { Handle, Position, type NodeProps, type Node } from "@xyflow/react";
import { Bug, Crown, Database, Globe, Layers } from "lucide-react";
import type { CSSProperties } from "react";

import { entityIcon } from "@/lib/entity-icons";
import { lineageNodeTypeForEntity } from "@/lib/graph-entity-mapping";
import { NODE_COLOR_MAP } from "@/lib/graph-utils";
import type { PathGraphNode } from "@/lib/attack-path-graph-model";
import type { NodeContextMarker } from "@/lib/attack-path-graph-markers";
import { ATTACK_PATH_NODE } from "@/lib/attack-path-graph-layout";
import { GLYPH_CENTER_Y, glyphInsetX } from "@/lib/attack-path-graph-routes";

export type AttackPathNodeData = {
  node: PathGraphNode;
  vertical: boolean;
  onOpenFindings: (nodeId: string, findingIds: string[]) => void;
  onExpandGroup: (groupId: string) => void;
};
export type AttackPathFlowNode = Node<AttackPathNodeData, "attackPathNode">;

const GLYPH_INSET_X = glyphInsetX(ATTACK_PATH_NODE.width);
const BOX: CSSProperties = { width: ATTACK_PATH_NODE.width };
/** Names wrap to two lines under the glyph before truncating; the full name is on hover. */
const NAME = "pointer-events-auto mt-2 block w-full rounded-t bg-surface px-1 pt-0.5 text-[15px] font-semibold leading-tight line-clamp-2 [overflow-wrap:anywhere]";
const SUBTITLE = "pointer-events-auto block w-full truncate rounded-b bg-surface px-1 pb-0.5 pt-0.5 text-[13px] leading-tight";
const RATED = new Set(["critical", "high", "medium", "low"]);
const MARKER_ICONS = { internet: Globe, sensitive: Database, privileged: Crown } as const;
const ROLE_CAPTION: Record<PathGraphNode["role"], string> = { entry: "Entry", path: "", target: "At risk", branch: "" };

function severityStyle(severity: string): CSSProperties {
  if (!RATED.has(severity)) return { background: "var(--surface-elevated)", borderColor: "var(--border-strong)", color: "var(--foreground)" };
  return {
    background: `linear-gradient(var(--severity-${severity}-bg), var(--severity-${severity}-bg)), var(--surface)`,
    borderColor: `var(--severity-${severity}-border)`,
    color: `var(--severity-${severity})`,
  };
}

function FindingBadge({ node, onOpen }: { node: PathGraphNode; onOpen: AttackPathNodeData["onOpenFindings"] }) {
  const count = node.findings.length;
  const worst = node.findings[0]!.severity;
  const label = `${count} ${count === 1 ? "finding" : "findings"} on ${node.label}, worst ${RATED.has(worst) ? worst : "unrated"}. Open findings`;
  return (
    <button type="button" aria-label={label} title={label.replace(". Open findings", "")} data-severity={worst} data-node-badge="findings"
      onClick={event => { event.stopPropagation(); onOpen(node.id, node.findings.map(finding => finding.id)); }}
      className="nodrag nopan absolute -right-5 -top-2.5 z-10 inline-flex h-7 min-w-7 items-center gap-0.5 rounded-full border px-1.5 text-[13px] font-bold tabular-nums shadow-sm focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[color:var(--focus-ring)]"
      style={severityStyle(worst)}>
      <Bug className="h-3.5 w-3.5" aria-hidden="true" />{count}
    </button>
  );
}

function Markers({ markers }: { markers: NodeContextMarker[] }) {
  if (markers.length === 0) return null;
  return (
    <span className="absolute -left-5 -top-2.5 z-10 flex flex-col gap-0.5">
      {markers.map(marker => {
        const Icon = MARKER_ICONS[marker.kind];
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
      <span data-node-label className={`${NAME} ${spine ? "text-foreground" : "text-ink-secondary"}`}>{node.label}</span>
      <span data-node-label className={`${SUBTITLE} ${spine ? "text-ink-secondary" : "text-ink-tertiary"}`}>
        {node.typeLabel}{caption ? <span className="font-medium text-foreground"> · {caption}</span> : null}
      </span>
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
      <span data-node-label className={`${NAME} text-ink-secondary`}>{node.label}</span>
      <button type="button" aria-label={`Expand ${node.label}`}
        onClick={event => { event.stopPropagation(); data.onExpandGroup(node.id); }}
        className="pointer-events-auto nodrag nopan rounded-b bg-surface px-1 text-xs font-medium text-[color:var(--accent)] underline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-[color:var(--focus-ring)]">
        Expand
      </button>
    </div>
  );
}

export const attackPathNodeTypes = { attackPathNode: AttackPathGraphNode };
