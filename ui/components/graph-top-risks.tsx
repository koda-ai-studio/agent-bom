"use client";

import { ArrowRight } from "lucide-react";
import type { TopRisk } from "@/lib/graph-top-risk";

const typeName = (nodeType: string) => nodeType.replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase();

export function RiskSeverity({ severity }: { severity?: string | undefined }) {
  if (!severity) return null;
  return <span data-severity={severity} className="inline-flex items-center gap-1 font-medium capitalize text-foreground">
    <span aria-hidden="true" className="inline-block h-2 w-2 rounded-full" style={{ background: `var(--severity-ring-${severity}, var(--severity-none))` }} />
    {severity}
  </span>;
}

/** The first reading of a map too large to label: what the records rank riskiest, and where to start. */
export function GraphTopRisks({ risks, loaded, onSelect }: {
  risks: TopRisk[];
  loaded: number;
  onSelect: (id: string) => void;
}) {
  const lead = risks[0];
  if (!lead) return null;
  return <aside data-testid="graph-top-risks" aria-label="Highest recorded risk" className="flex min-h-0 shrink-0 flex-col border-outline bg-surface max-sm:border-b sm:w-72 sm:border-r">
    <div className="px-3 pb-1 pt-2.5">
      <h2 className="text-sm font-semibold text-foreground">Highest recorded risk</h2>
      <p className="text-xs text-ink-secondary">Ranked by recorded score across {loaded.toLocaleString()} assets in this view</p>
    </div>
    <ol className="min-h-0 flex-1 overflow-y-auto px-1.5 sm:pb-1">
      {risks.map((risk, index) => <li key={risk.id} data-testid="graph-top-risk" className={index > 2 ? "max-sm:hidden" : undefined}>
        <button type="button" onClick={() => onSelect(risk.id)} title={risk.label}
          className="w-full rounded-md px-1.5 py-1.5 text-left hover:bg-surface-muted focus-visible:outline focus-visible:outline-2 focus-visible:outline-emerald-500">
          <span data-risk-label className="line-clamp-2 break-words text-[13px] font-medium leading-snug text-foreground">{risk.label}</span>
          <span className="mt-0.5 flex flex-wrap items-center gap-x-1.5 text-xs text-ink-secondary">
            <RiskSeverity severity={risk.severity} />
            {risk.riskScore !== undefined && <span data-risk-score={risk.riskScore}>· risk {risk.riskScore.toFixed(1)}</span>}
            {risk.kev && <span className="font-medium text-foreground">· KEV</span>}
            <span>· {typeName(risk.nodeType)}</span>
            {risk.count > 1 && <span>· {risk.count} assets</span>}
          </span>
        </button>
      </li>)}
    </ol>
    <div className="px-3 pb-3 pt-1.5">
      <button type="button" onClick={() => onSelect(lead.id)} aria-label={`Investigate top risk: ${lead.label}`}
        className="inline-flex min-h-10 w-full items-center justify-center gap-1.5 rounded-lg bg-emerald-700 px-3 text-sm font-medium text-white hover:bg-emerald-800 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-500">
        Investigate top risk <ArrowRight className="h-4 w-4" aria-hidden="true" />
      </button>
    </div>
  </aside>;
}
