"use client";

import { Bug, Crown, Database, Globe } from "lucide-react";

import { LINE_STYLE, PATH_STROKE } from "@/components/attack-path-graph-edge";
import type { AttackPathGraphModel, EdgeEvidenceStyle } from "@/lib/attack-path-graph-model";

const EVIDENCE_LABELS: Record<EdgeEvidenceStyle, string> = {
  recorded: "Recorded",
  inferred: "Modeled or inferred",
  unrecorded: "No per-edge receipt",
};
const MARKERS = [
  { kind: "internet", label: "Internet-exposed", Icon: Globe },
  { kind: "sensitive", label: "Sensitive data", Icon: Database },
  { kind: "privileged", label: "Privileged", Icon: Crown },
] as const;

function LineSwatch({ dash, stroke, width = 2, round, dots }: { dash?: string | undefined; stroke: string; width?: number; round?: boolean; dots?: boolean }) {
  return (
    <svg width="28" height="8" aria-hidden="true" className="shrink-0">
      <line x1={dots ? 4 : 1} y1="4" x2={dots ? 24 : 27} y2="4" style={{ stroke, strokeWidth: width, strokeDasharray: dash, strokeLinecap: round ? "round" : undefined }} />
      {dots && <><circle cx="3" cy="4" r="2.5" style={{ fill: stroke }} /><circle cx="25" cy="4" r="2.5" style={{ fill: stroke }} /></>}
    </svg>
  );
}

/** Explains only the line styles, colours and markers this graph actually draws. */
export function AttackPathGraphLegend({ model }: { model: AttackPathGraphModel }) {
  const evidence = (Object.keys(EVIDENCE_LABELS) as EdgeEvidenceStyle[]).filter(kind => model.edges.some(edge => edge.evidence === kind));
  const branches = model.nodes.some(node => node.role === "branch");
  const markers = MARKERS.filter(marker => model.nodes.some(node => node.markers.some(item => item.kind === marker.kind)));
  const findings = model.nodes.some(node => node.findings.length > 0);
  const twoWay = model.edges.some(edge => edge.bidirectional);
  const item = "inline-flex items-center gap-1.5";
  return (
    <ul aria-label="Graph legend" className="flex flex-wrap items-center gap-x-4 gap-y-1.5 border-t border-outline bg-surface px-3 py-2 text-xs text-ink-secondary">
      <li className={item}><LineSwatch stroke={PATH_STROKE.selected.color} width={PATH_STROKE.selected.width} />Selected path</li>
      {branches && <li className={item}><LineSwatch stroke={PATH_STROKE.connected.color} width={PATH_STROKE.connected.width} />Connected path</li>}
      {evidence.map(kind => (
        <li key={kind} className={item}><LineSwatch stroke="var(--text-secondary)" dash={LINE_STYLE[kind].dash} round={kind === "unrecorded"} />{EVIDENCE_LABELS[kind]}</li>
      ))}
      {twoWay && <li className={item}><LineSwatch stroke="var(--text-secondary)" width={1.5} dots />Two-way relationship</li>}
      {findings && <li className={item}><Bug className="h-3.5 w-3.5 text-foreground" aria-hidden="true" />Findings on asset · worst severity</li>}
      {markers.map(({ kind, label, Icon }) => (
        <li key={kind} className={item}><Icon className="h-3.5 w-3.5 text-foreground" aria-hidden="true" />{label}</li>
      ))}
      <li className="text-ink-tertiary">Hover or focus a line for its relationship</li>
    </ul>
  );
}
