"use client";

import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { ArrowLeftRight, Bot, Bug, CircleHelp, CornerUpLeft, Flag, Layers, ListTree, Route, Workflow, type LucideIcon } from "lucide-react";
import type { CSSProperties } from "react";

import { severityStyle } from "@/components/attack-path-graph-node";
import { ATTACK_PATH_NODE } from "@/lib/attack-path-graph-layout";
import { GLYPH_CENTER_Y, glyphInsetX } from "@/lib/attack-path-graph-routes";
import { FLOW_KIND_LABEL, type ArchitectureNode } from "@/lib/agent-architecture-model";

export type ArchitectureNodeData = {
  node: ArchitectureNode;
  vertical: boolean;
  onOpen: (nodeId: string) => void;
  onExpand: (groupId: string) => void;
};
export type ArchitectureFlowNode = Node<ArchitectureNodeData, "architectureNode">;

const BOX: CSSProperties = { width: ATTACK_PATH_NODE.width, height: ATTACK_PATH_NODE.height };
const INSET = glyphInsetX(ATTACK_PATH_NODE.width);
const RATED = new Set(["critical", "high", "medium", "low"]);
const NAME = "pointer-events-auto block w-full rounded-t bg-surface px-1 pt-0.5 text-[15px] font-semibold leading-tight line-clamp-2 [overflow-wrap:anywhere]";
const SUBTITLE = "pointer-events-auto block w-full truncate rounded-b bg-surface px-1 pb-0.5 pt-0.5 text-[13px] leading-tight";

export function architectureIcon(node: Pick<ArchitectureNode, "kind" | "role">): LucideIcon {
  if (node.kind === "group") return Layers;
  if (node.kind === "stub") return CircleHelp;
  if (node.kind === "terminal") return Flag;
  return node.role === "harness" ? Workflow : node.role === "orchestrator" ? Route : node.role === "subgraph" ? ListTree : Bot;
}

export function findingsLabel(node: Pick<ArchitectureNode, "findings" | "findingSeverity" | "label">): string {
  return `${node.findings} ${node.findings === 1 ? "finding" : "findings"} on ${node.label}, worst ${RATED.has(node.findingSeverity) ? node.findingSeverity : "unrated"}`;
}

function FindingBadge({ node, onOpen }: { node: ArchitectureNode; onOpen: (id: string) => void }) {
  const label = findingsLabel(node);
  return (
    <button type="button" aria-label={`${label}. Open details`} title={label} data-severity={node.findingSeverity || "unrated"} data-node-badge="findings"
      onClick={event => { event.stopPropagation(); onOpen(node.id); }}
      className="nodrag nopan absolute -right-5 -top-2.5 z-10 inline-flex h-7 min-w-7 items-center gap-0.5 rounded-full border px-1.5 text-[13px] font-bold tabular-nums shadow-sm focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[color:var(--focus-ring)]"
      style={severityStyle(node.findingSeverity)}>
      <Bug className="h-3.5 w-3.5" aria-hidden="true" />{node.findings}
    </button>
  );
}

function Markers({ node }: { node: ArchitectureNode }) {
  const markers = [
    ...node.returnsTo.map(item => ({ key: `r-${item.id}-${item.kind}`, Icon: CornerUpLeft, label: `Returns to ${item.label} (${FLOW_KIND_LABEL[item.kind].toLowerCase()})` })),
    ...node.peers.map(item => ({ key: `p-${item.id}`, Icon: ArrowLeftRight, label: `Shares a server with ${item.label}` })),
  ];
  if (markers.length === 0) return null;
  return (
    <span className="absolute -left-5 -top-2.5 z-10 flex flex-col gap-0.5">
      {markers.map(({ key, Icon, label }) => (
        <span key={key} role="img" aria-label={label} title={label} data-marker={key.startsWith("r-") ? "returns" : "peer"}
          className="inline-flex h-6 w-6 items-center justify-center rounded-full border border-outline-strong bg-surface text-foreground shadow-sm">
          <Icon className="h-3.5 w-3.5" aria-hidden="true" />
        </span>
      ))}
    </span>
  );
}

function Handles({ vertical }: { vertical: boolean }) {
  const hidden = "!h-1 !w-1 !min-h-0 !min-w-0 !border-0 !bg-transparent";
  return vertical ? <>
    <Handle type="target" position={Position.Top} className={hidden} />
    <Handle type="source" position={Position.Bottom} className={hidden} />
  </> : <>
    <Handle type="target" position={Position.Left} className={hidden} style={{ top: GLYPH_CENTER_Y, left: INSET }} />
    <Handle type="source" position={Position.Right} className={hidden} style={{ top: GLYPH_CENTER_Y, right: INSET }} />
  </>;
}

function glyphClass(node: ArchitectureNode): string {
  if (node.kind === "group" || node.kind === "stub") return "border border-dashed border-outline-strong";
  if (node.kind === "terminal") return "border border-outline";
  return node.role === "harness" || node.role === "orchestrator" || node.entry ? "border-[2.5px] border-[color:var(--accent)]" : "border border-outline-strong";
}

/** Round icon, short name and type under it; findings as a severity badge, returns and peers as markers. */
export function ArchitectureGraphNode({ data }: NodeProps<ArchitectureFlowNode>) {
  const { node, vertical } = data;
  const Icon = architectureIcon(node);
  const muted = node.kind === "stub" || node.kind === "terminal";
  return (
    <div data-testid={`architecture-node-${node.id}`} data-kind={node.kind} title={`${node.label} · ${node.subtitle}`}
      style={BOX} className="pointer-events-none flex flex-col items-center text-center">
      <Handles vertical={vertical} />
      <div data-node-glyph className={`pointer-events-auto relative mt-1.5 flex h-14 w-14 items-center justify-center rounded-full bg-surface-elevated text-foreground ${glyphClass(node)}`}>
        <Icon className={node.kind === "agent" ? "h-7 w-7" : "h-5 w-5"} aria-hidden="true" />
        <Markers node={node} />
        {node.findings > 0 && <FindingBadge node={node} onOpen={data.onOpen} />}
      </div>
      <div data-node-label className="pointer-events-auto w-full flex-1 pt-2">
        <span data-node-label className={`${NAME} ${muted ? "text-ink-secondary" : "text-foreground"}`}>{node.label}</span>
        {node.kind === "group" ? (
          <button type="button" aria-label={`Expand ${node.label}`}
            onClick={event => { event.stopPropagation(); data.onExpand(node.id); }}
            className="nodrag nopan rounded-b bg-surface px-1 text-[13px] font-medium text-[color:var(--accent)] underline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-[color:var(--focus-ring)]">
            Expand
          </button>
        ) : (
          <span data-node-label className={`${SUBTITLE} text-ink-secondary`}>
            {node.subtitle}{node.entry ? <span className="font-medium text-foreground"> · Entry</span> : null}
          </span>
        )}
      </div>
    </div>
  );
}

export const architectureNodeTypes = { architectureNode: ArchitectureGraphNode };
