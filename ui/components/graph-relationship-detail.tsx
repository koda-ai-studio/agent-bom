"use client";

import { useEffect, useRef } from "react";
import { X } from "lucide-react";
import { GraphRelationshipExplanation } from "@/components/graph-relationship-explanation";
import { Drawer } from "@/components/drawer";
import type { UnifiedEdge } from "@/lib/graph-schema";
import { relationshipEdgeLabelText } from "@/lib/graph-utils";
import { graphEdgeEvidenceMode } from "@/lib/unified-graph-flow";

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
  const content = <div className="space-y-4 text-sm [overflow-wrap:anywhere]">
    <p className="font-medium">{sourceLabel} {edge.direction === "bidirectional" ? "↔" : "→"} {targetLabel}</p>
    <section aria-label="Why linked" className="space-y-2 rounded-lg border border-outline bg-surface-muted p-3">
      <h4 className="text-xs font-semibold">Why linked</h4>
      <GraphRelationshipExplanation edge={edge} />
    </section>
    <p className="text-xs text-ink-secondary">This recorded relationship does not establish execution or successful data access.</p>
    <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-xs">
      <dt className="text-ink-secondary">Snapshot</dt><dd>{scanId}</dd>
      <dt className="text-ink-secondary">First seen</dt><dd>{edge.first_seen || "Not recorded"}</dd>
      <dt className="text-ink-secondary">Last seen</dt><dd>{edge.last_seen || "Not recorded"}</dd>
      <dt className="text-ink-secondary">Traversal</dt><dd>{edge.traversable ? "Recorded as traversable" : "Not established"}</dd>
    </dl>
    <details><summary className="cursor-pointer font-medium">Recorded evidence</summary>
      {Object.keys(edge.evidence ?? {}).length ? <pre className="mt-2 whitespace-pre-wrap break-words text-xs text-ink-secondary">{JSON.stringify(edge.evidence, null, 2)}</pre> : <p className="mt-2 text-xs text-ink-secondary">No source receipt recorded for this relationship.</p>}
    </details>
    <details><summary className="cursor-pointer font-medium">Canonical identifiers</summary>
      <dl className="mt-2 space-y-1 text-xs text-ink-secondary"><dt>Relationship</dt><dd>{edge.id}</dd><dt>Source</dt><dd>{edge.source}</dd><dt>Target</dt><dd>{edge.target}</dd></dl>
    </details>
  </div>;
  if (mobile) return <Drawer open onClose={onClose} title={title} eyebrow="Relationship" ariaLabel="Relationship details" closeLabel="Close relationship details" backdropLabel="Dismiss relationship details">{content}</Drawer>;
  return <aside aria-label="Relationship details" className="w-[min(28rem,40vw)] shrink-0 self-stretch overflow-y-auto border-l border-outline bg-surface text-foreground">
    <header className="flex items-center justify-between gap-3 border-b border-outline p-4"><h3 className="font-semibold">{title}</h3><button ref={closeButtonRef} type="button" aria-label="Close relationship details" onClick={onClose} className="rounded p-2 hover:bg-surface-muted"><X className="h-4 w-4" aria-hidden="true" /></button></header>
    <div className="p-4">{content}</div>
  </aside>;
}
