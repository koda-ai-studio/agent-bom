"use client";

import { useEffect, useRef } from "react";
import { X } from "lucide-react";
import { GraphRelationshipExplanation } from "@/components/graph-relationship-explanation";
import { GraphRelationshipEvidence } from "@/components/graph-relationship-evidence";
import { Drawer } from "@/components/drawer";
import type { GraphRollupEdge } from "@/lib/api-types";
import type { UnifiedEdge } from "@/lib/graph-schema";
import { relationshipEdgeLabelText } from "@/lib/graph-utils";
import { graphEdgeEvidenceMode } from "@/lib/unified-graph-flow";
import { plainRelationshipSummary } from "@/lib/graph-relationship-plain";

export function GraphRelationshipDetail({ edge, scanId, sourceLabel, targetLabel, onClose, mobile = false }: {
  edge: UnifiedEdge;
  scanId: string;
  sourceLabel: string;
  targetLabel: string;
  onClose: () => void;
  mobile?: boolean;
}) {
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    if (mobile) return;
    const close = (event: KeyboardEvent) => { if (event.key === "Escape") closeRef.current(); };
    document.addEventListener("keydown", close);
    return () => document.removeEventListener("keydown", close);
  }, [mobile]);
  useEffect(() => {
    if (mobile) return;
    const previous = document.activeElement;
    closeButtonRef.current?.focus();
    return () => {
      if ((previous instanceof HTMLElement || previous instanceof SVGElement) && previous.isConnected) previous.focus();
    };
  }, [mobile, edge.id]);
  const title = relationshipEdgeLabelText(edge.relationship, { evidenceMode: graphEdgeEvidenceMode(edge) });
  const plain = plainRelationshipSummary(edge, sourceLabel, targetLabel);
  const content = <div className="space-y-4 text-sm [overflow-wrap:anywhere]">
    <p className="font-medium">{sourceLabel} {edge.direction === "bidirectional" ? "↔" : "→"} {targetLabel}</p>
    <dl aria-label="Relationship summary" className="space-y-3 rounded-lg border border-outline bg-surface-muted p-3">
      {([["Why linked", plain.why], ["Source", plain.source], ["Evidence", plain.kind], ["Freshness", plain.freshness], ["Still unknown", plain.unknown]] as const).map(([label, value]) =>
        <div key={label}><dt className="text-[11px] font-semibold uppercase tracking-wide text-ink-secondary">{label}</dt><dd className="mt-0.5">{value}</dd></div>)}
    </dl>
    <p className="text-xs text-ink-secondary">This recorded relationship does not establish execution or successful data access.</p>
    <details className="rounded-lg border border-outline p-3"><summary className="cursor-pointer font-medium">Technical details</summary>
      <div className="mt-3 space-y-4">
        <section aria-label="Why linked" className="space-y-2"><h4 className="text-xs font-semibold">Recorded relationship type</h4><GraphRelationshipExplanation edge={edge} /></section>
        <GraphRelationshipEvidence edge={edge} />
        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-xs">
          <dt className="text-ink-secondary">Snapshot</dt><dd>{scanId}</dd>
          <dt className="text-ink-secondary">Graph first seen</dt><dd>{edge.first_seen || "Not recorded"}</dd>
        </dl>
        <details><summary className="cursor-pointer font-medium">Recorded evidence</summary>
          {Object.keys(edge.evidence ?? {}).length ? <pre className="mt-2 whitespace-pre-wrap break-words text-xs text-ink-secondary">{JSON.stringify(edge.evidence, null, 2)}</pre> : <p className="mt-2 text-xs text-ink-secondary">No source receipt recorded for this relationship.</p>}
        </details>
        <details><summary className="cursor-pointer font-medium">Canonical identifiers</summary>
          <dl className="mt-2 space-y-1 text-xs text-ink-secondary"><dt>Relationship</dt><dd>{edge.id}</dd><dt>Source</dt><dd>{edge.source}</dd><dt>Target</dt><dd>{edge.target}</dd></dl>
        </details>
      </div>
    </details>
  </div>;
  if (mobile) return <Drawer open onClose={onClose} title={title} eyebrow="Relationship" ariaLabel="Relationship details" closeLabel="Close relationship details" backdropLabel="Dismiss relationship details">{content}</Drawer>;
  return <aside aria-label="Relationship details" className="w-[min(24rem,36vw)] shrink-0 self-stretch overflow-y-auto border-l border-outline bg-surface text-foreground">
    <header className="sticky top-0 z-10 flex items-center justify-between gap-3 border-b border-outline bg-surface p-4"><div><p className="mb-1 text-[10px] uppercase tracking-wider text-ink-secondary">Recorded relationship</p><h3 className="text-base font-semibold">{title}</h3></div><button ref={closeButtonRef} type="button" aria-label="Close relationship details" onClick={onClose} className="rounded p-2 hover:bg-surface-muted"><X className="h-4 w-4" aria-hidden="true" /></button></header>
    <div className="p-4">{content}</div>
  </aside>;
}


/** An aggregate is a summary of receipts, never a synthetic direct edge. */
export function GraphRollupRelationshipDetail({ edge, scanId, sourceLabel, targetLabel, onClose, onInspectNode }: {
  edge: GraphRollupEdge; scanId: string; sourceLabel: string; targetLabel: string;
  onClose: () => void; onInspectNode: (id: string) => void;
}) {
  const directions = edge.directions ?? [];
  return <Drawer open onClose={onClose} title={`${edge.count} recorded relationship${edge.count === 1 ? "" : "s"}`} eyebrow="Between scopes" ariaLabel="Scope relationship details" closeLabel="Close relationship details" backdropLabel="Dismiss relationship details" size="md">
    <div className="space-y-4 text-sm [overflow-wrap:anywhere]">
      <p className="font-medium">{sourceLabel} · {targetLabel}</p>
      <p className="text-ink-secondary">These relationships connect entities inside the two scopes. Explore a scope to inspect the actual endpoints and their evidence.</p>
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-2 text-xs">
        <dt>Snapshot</dt><dd>{scanId}</dd>
        <dt>Recorded directions</dt><dd>{directions.length > 1 ? `Mixed: ${directions.join(", ")}` : directions[0] || "Not recorded"}</dd>
        {edge.relationships.map(relationship => <div key={relationship} className="contents"><dt>{relationshipEdgeLabelText(relationship, { evidenceMode: "unknown" })}</dt><dd>{edge.relationship_counts?.[relationship] ?? "Count unavailable"}</dd></div>)}
      </dl>
      <p className="text-xs text-ink-secondary">Aggregate links do not establish an end-to-end executable path. Counts cover the source graph used for this view.</p>
      <div className="flex flex-wrap gap-2">{[[edge.source, sourceLabel], [edge.target, targetLabel]].map(([id, label]) =>
        <button key={id} type="button" className="rounded-lg border border-outline px-3 py-2 text-xs hover:bg-surface-muted" onClick={() => { onClose(); onInspectNode(id!); }}>Explore {label}</button>)}</div>
    </div>
  </Drawer>;
}
