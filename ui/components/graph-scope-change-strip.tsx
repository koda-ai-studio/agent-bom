"use client";
import type { GraphEstateChangesResponse } from "@/lib/api-types";

/** Page-bounded same-scope deltas. Shared entities may occur in multiple scopes;
 * missing collection or trend evidence never becomes a reassuring zero. */
export function GraphScopeChangeStrip({ changes, onOpen }: { changes: GraphEstateChangesResponse; onOpen: () => void }) {
  const sources = changes.sources.filter(source => source.comparison?.status === "comparable");
  const excluded = changes.sources.length-sources.length;
  const metrics: string[] = [];
  if (sources.length) {
    const knownKev = sources.every(source => source.kev_change != null);
    const kev = sources.reduce((total, source) => total+(source.kev_change?.delta ?? 0),0);
    metrics.push(knownKev ? `KEV ${kev < 0 ? "−" : "+"}${Math.abs(kev)}` : "KEV unavailable");
    const pathsKnown = sources.every(source => [source.highlights.new_attack_paths,source.highlights.removed_attack_paths].every(row => row?.status === "complete"));
    metrics.push(pathsKnown ? `Paths +${sources.reduce((n,s) => n+(s.highlights.new_attack_paths?.count ?? 0),0)} −${sources.reduce((n,s) => n+(s.highlights.removed_attack_paths?.count ?? 0),0)}` : "Paths unavailable");
    for (const [label,type] of [["Agents","agent"],["MCP","server"],["Drift","drift_incident"]]) {
      const added=sources.reduce((n,s) => n+(s.nodes_by_entity_type[type!]?.added ?? 0),0);
      const removed=sources.reduce((n,s) => n+(s.nodes_by_entity_type[type!]?.removed ?? 0),0);
      const changed=sources.reduce((n,s) => n+(s.nodes_by_entity_type[type!]?.changed ?? 0),0);
      metrics.push(`${label} +${added} −${removed}${changed ? ` · ${changed} changed` : ""}`);
    }
  }
  const heading = sources.length ? `Since previous comparable scan · ${sources.length} scope${sources.length === 1 ? "" : "s"}`
    : changes.sources.length ? "Comparison unavailable · collection incomplete or basis not recorded"
      : changes.new_sources.length ? "First observation · no previous comparable scan" : "No comparable scan history";
  return <button type="button" aria-label={`Open comparable scope changes: ${heading}`} onClick={onOpen}
    title="Per-scope occurrences on this page; shared entities can occur in multiple scopes. Decreases mean no longer detected, not verified remediation. Open for exact snapshots and evidence."
    className="flex w-full flex-wrap items-center gap-x-4 gap-y-1 rounded-lg border border-outline bg-surface px-3 py-2 text-left text-xs text-ink-secondary focus-visible:outline-2 focus-visible:outline-offset-2">
    <span className="font-medium text-foreground">{heading}</span>
    {metrics.map(metric => <span key={metric} className="tabular-nums">{metric}</span>)}
    {excluded > 0 && sources.length > 0 && <span>{excluded} scope{excluded === 1 ? "" : "s"} unavailable</span>}
    {changes.new_sources.length > 0 && sources.length > 0 && <span>{changes.new_sources.length} first observation{changes.new_sources.length === 1 ? "" : "s"}</span>}
    {changes.pagination.has_more && <span>Loaded scopes only</span>}
    <span className="ml-auto underline underline-offset-2">Details</span>
  </button>;
}
