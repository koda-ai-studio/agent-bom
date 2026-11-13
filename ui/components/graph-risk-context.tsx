"use client";

import { contextMarkers, MARKER_META, riskContextOf, riskReasonText } from "@/lib/node-risk-context";

/** The node's stored risk verdicts and the recorded facts that establish each one. */
export function GraphRiskContext({ attributes }: { attributes: Record<string, unknown> }) {
  const context = riskContextOf(attributes);
  if (!context) return null;
  return (
    <section aria-label="Risk context" className="space-y-1.5 text-xs text-ink-secondary">
      <p className="text-[11px] font-semibold uppercase tracking-wide text-ink-tertiary">Risk context</p>
      <div className="flex flex-wrap gap-1.5">
        {contextMarkers(context).map(({ kind, label }) => {
          const { Icon, label: name } = MARKER_META[kind];
          return <span key={kind} title={label} className="inline-flex items-center gap-1 rounded border border-outline px-1.5 py-0.5 text-[11px] text-foreground"><Icon className="h-3 w-3" aria-hidden="true" />{name}</span>;
        })}
      </div>
      <ul className="list-disc space-y-0.5 pl-4 break-words [overflow-wrap:anywhere]">
        {context.reasons.map((reason, index) => <li key={index}>{riskReasonText(reason)}</li>)}
      </ul>
      <p className="text-[11px] text-ink-tertiary">Scan {context.scan_id || "unknown"} · sources {context.sources.join(", ") || "unknown"}</p>
    </section>
  );
}
