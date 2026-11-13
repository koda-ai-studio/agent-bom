"use client";

import { ArrowLeftRight, Bug, CornerUpLeft, Layers } from "lucide-react";

import { EDGE_STYLE } from "@/components/agent-architecture/architecture-edge";
import { FLOW_KIND_LABEL, type ArchitectureEdgeKind, type ArchitectureModel } from "@/lib/agent-architecture-model";

const KIND_ORDER: ArchitectureEdgeKind[] = ["entry", "sequential", "conditional", "handoff", "fan_out", "subgraph", "member", "contains", "finish", "unresolved"];

function Swatch({ kind }: { kind: ArchitectureEdgeKind }) {
  const style = EDGE_STYLE[kind];
  return (
    <svg width="28" height="8" aria-hidden="true" className="shrink-0">
      <line x1="1" y1="4" x2="27" y2="4" style={{ stroke: style.color, strokeWidth: style.width, strokeDasharray: style.dash, strokeLinecap: style.round ? "round" : undefined }} />
    </svg>
  );
}

/** Explains only the line kinds and markers this harness draws. */
export function ArchitectureLegend({ model, lines = true }: { model: ArchitectureModel; lines?: boolean }) {
  // The phone step list draws no lines, so it lists no line styles.
  const kinds = lines ? KIND_ORDER.filter(kind => model.edges.some(edge => edge.kind === kind)) : [];
  const item = "inline-flex items-center gap-1.5";
  const icon = "h-3.5 w-3.5 text-foreground";
  return (
    <ul aria-label="Graph legend" className="flex flex-wrap items-center gap-x-4 gap-y-1.5 border-t border-outline bg-surface px-3 py-2 text-xs text-ink-secondary">
      {kinds.map(kind => <li key={kind} className={item}><Swatch kind={kind} />{FLOW_KIND_LABEL[kind]}</li>)}
      {model.nodes.some(node => node.findings > 0) && <li className={item}><Bug className={icon} aria-hidden="true" />Findings on agent · worst severity</li>}
      {model.nodes.some(node => node.returnsTo.length > 0) && <li className={item}><CornerUpLeft className={icon} aria-hidden="true" />Returns to an earlier step</li>}
      {model.nodes.some(node => node.peers.length > 0) && <li className={item}><ArrowLeftRight className={icon} aria-hidden="true" />Shares a server</li>}
      {model.nodes.some(node => node.kind === "group") && <li className={item}><Layers className={icon} aria-hidden="true" />Collapsed agents</li>}
      {kinds.length > 0 && <li className="text-ink-tertiary">Hover or focus a line for its relationship</li>}
    </ul>
  );
}
