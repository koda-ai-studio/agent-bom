"use client";

import { X } from "lucide-react";
import type { Edge } from "@xyflow/react";
import { Drawer } from "@/components/drawer";

const NOTICE = "This is the assessment recorded in the snapshot, not a connectivity test. It does not change attack-path receipts or reachability. References are shown as recorded and are not resolved to the evidence they name.";

/** What the Internet boundary rests on. It is a display object, so there is no persisted edge to open. */
export function GraphIngressReceipt({ edge, targetLabel, mobile, onClose }: { edge: Edge; targetLabel: string; mobile: boolean; onClose: () => void }) {
  const assessment = (edge.data?.evidence ?? {}) as Record<string, unknown>;
  const refs = Array.isArray(assessment.evidence_refs) ? assessment.evidence_refs.map(String) : [];
  const rows: [string, string][] = [["Decision", String(assessment.decision ?? "Not recorded")], ["Source scope", String(assessment.source_scope ?? "Not recorded")], ["Target", String(assessment.target_id ?? "Not recorded")]];
  const content = <div className="space-y-4 text-sm leading-relaxed [overflow-wrap:anywhere]">
    <p className="text-base font-semibold text-foreground">Internet → {targetLabel}</p>
    <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2">
      {rows.map(([label, value]) => <div key={label} className="contents"><dt className="text-ink-secondary">{label}</dt><dd className="text-foreground">{value}</dd></div>)}
    </dl>
    <section aria-label="Evidence references"><h4 className="text-xs font-semibold">Evidence references</h4>
      <ul className="mt-1 space-y-1 font-mono text-xs text-ink-secondary">{refs.map(ref => <li key={ref}>{ref}</li>)}</ul>
    </section>
    <p className="rounded-lg border border-amber-300/60 bg-amber-50 px-4 py-3 text-foreground dark:border-amber-400/25 dark:bg-amber-400/5">{NOTICE}</p>
  </div>;
  if (mobile) return <Drawer open onClose={onClose} title="Assessed ingress" eyebrow="Snapshot assessment" ariaLabel="Assessed ingress receipt" closeLabel="Close assessed ingress receipt" backdropLabel="Dismiss assessed ingress receipt">{content}</Drawer>;
  return <aside aria-label="Assessed ingress receipt" className="w-[min(24rem,36vw)] shrink-0 self-stretch overflow-y-auto border-l border-outline bg-surface text-foreground">
    <header className="sticky top-0 z-10 flex items-center justify-between gap-3 border-b border-outline bg-surface p-4">
      <div><p className="mb-1 text-[10px] uppercase tracking-[0.2em] text-ink-tertiary">Snapshot assessment</p><h3 className="text-sm font-semibold">Assessed ingress</h3></div>
      <button type="button" aria-label="Close assessed ingress receipt" onClick={onClose} className="rounded-lg p-1 text-ink-secondary hover:bg-surface-muted"><X className="h-4 w-4" aria-hidden="true" /></button>
    </header>
    <div className="p-4">{content}</div>
  </aside>;
}
