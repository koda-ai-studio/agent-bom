"use client";

import { Handle, Position } from "@xyflow/react";
import { ChevronRight, Layers, TriangleAlert, Bug } from "lucide-react";
import { rollupDisplaySeverity } from "@/lib/graph-rollup-view";
import { severityChipClass } from "@/lib/severity";
import type { GraphRollupContainer } from "@/lib/api-types";

export function scopeTypeLabel(type: string): string {
  return type.replace(/_/g, " ").replace(/^./, letter => letter.toUpperCase());
}

export function GraphScopeNode({ item, dimmed, highlighted, compact, identityContext }: {
  identityContext?: string | undefined;
  item: GraphRollupContainer; compact?: boolean | undefined; dimmed?: boolean | undefined; highlighted?: boolean | undefined;
}) {
  const aggregate = item.aggregate;
  const scope = item.is_container || item.has_children;
  const severity = rollupDisplaySeverity(item);
  const finding = ["misconfiguration", "vulnerability"].includes(item.entity_type);
  const Icon = item.entity_type === "vulnerability" ? Bug : finding ? TriangleAlert : Layers;
  return <div data-graph-entity="true" data-rollup-container={scope ? "true" : undefined} className={`relative w-[280px] rounded-xl border bg-surface-elevated text-left shadow-sm ${finding ? "border-orange-500/60" : highlighted ? "border-cyan-500" : "border-outline-strong"} ${dimmed ? "opacity-30" : ""}`}>
    {[Position.Left, Position.Right, Position.Top, Position.Bottom].flatMap(position => (["source", "target"] as const).map(type =>
      <Handle key={`${type}-${position}`} id={`scope-${type}-${position}`} type={type} position={position} className="!h-1 !w-1 !border-0 !bg-transparent" />))}
    {compact ? <div className="p-3" title={`${item.label} · ${scope ? `${aggregate?.descendant_count ?? "Unknown"} contained entities` : scopeTypeLabel(item.entity_type)} · ${severity || "No"} severity`}><p className="truncate text-sm font-semibold text-foreground">{item.label}</p>{identityContext && <p data-testid="graph-identity-context" className="mt-1 break-words text-xs text-ink-secondary">{identityContext}</p>}<p className="mt-1 text-xs text-ink-secondary">{scope ? `${aggregate?.descendant_count.toLocaleString() ?? "—"} entities · ` : ""}{severity || "No"} severity</p></div> : <><div className="p-4">
      <div className="mb-2 flex items-center gap-2 text-xs text-ink-secondary"><Icon className={`h-4 w-4 ${finding ? "text-orange-600 dark:text-orange-400" : "text-cyan-600 dark:text-cyan-400"}`} aria-hidden="true" />{finding ? "Finding" : scopeTypeLabel(item.entity_type)}</div>
      <p className="text-base font-semibold leading-6 text-foreground [overflow-wrap:anywhere]">{item.label}</p>
      {identityContext && <p data-testid="graph-identity-context" className="mt-1 break-words text-xs text-ink-secondary">{identityContext}</p>}
      {scope && <div className="mt-3 flex items-baseline gap-2 text-ink-secondary"><strong className="text-xl font-semibold tabular-nums text-foreground">{aggregate ? aggregate.descendant_count.toLocaleString() : "—"}</strong><span className="text-xs">contained entities</span></div>}
      <div className="mt-3 flex flex-wrap gap-2 text-xs">
        <span className={`rounded-md border px-2 py-1 ${severityChipClass(severity)}`}>
          {severity && severity !== "none" ? `${scopeTypeLabel(severity)}${scope ? " · highest severity" : " severity"}` : "No severity recorded"}
        </span>
        {!!aggregate?.exposed_count && <span className="rounded-md bg-surface-muted px-2 py-1 text-ink-secondary">{aggregate.exposed_count.toLocaleString()} exposed</span>}
      </div>
    </div>
    <div className="flex items-center justify-between border-t border-outline px-4 py-2 text-xs text-ink-secondary"><span>{scope ? "Inspect scope" : finding ? "Inspect finding" : "Inspect entity"}</span><ChevronRight className="h-3.5 w-3.5" aria-hidden="true" /></div></>}
  </div>;
}
