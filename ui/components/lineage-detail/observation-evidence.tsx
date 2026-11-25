"use client";

import { useState } from "react";
import { formatValue, prettifyKey } from "./fields";

/** One selected source observation per attribute; a conflict is not proof of an attack. */
export function ObservationEvidence({ attributes }: { attributes: Record<string, unknown> }) {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const raw = attributes.attribute_observations;
  const entries = raw && typeof raw === "object" && !Array.isArray(raw)
    ? Object.entries(raw).filter(([key, value]) => key in attributes && value && typeof value === "object" && !Array.isArray(value)).sort(([a], [b]) => a.localeCompare(b)) : [];
  if (!entries.length) return null;
  const pages = Math.ceil(entries.length / pageSize), current = Math.min(page, pages - 1);
  return <section aria-label="Observation evidence" className="space-y-2 text-xs">
    <h4 className="font-semibold text-foreground">Observation evidence</h4>
    <p className="text-ink-secondary">Selected values and their source timestamps. A conflict means sources or scans disagreed; review the evidence before acting.</p>
    <dl className="divide-y divide-outline rounded border border-outline">
      {entries.slice(current * pageSize, (current + 1) * pageSize).map(([key, value]) => {
        const receipt = value as Record<string, unknown>;
        const time = typeof receipt.observed_at === "string" ? Date.parse(receipt.observed_at) : NaN;
        const sources = Array.isArray(receipt.sources) ? receipt.sources.filter((source): source is string => typeof source === "string") : [];
        const selected = attributes[key];
        return <div key={key} className="space-y-1 px-2 py-2 break-words">
          <dt className="font-medium text-foreground">{prettifyKey(key)}</dt>
          <dd className="text-ink-secondary">{selected == null ? "Unknown value" : typeof selected === "boolean" ? selected ? "True" : "False" : formatValue(selected)}</dd>
          <dd className="text-ink-tertiary">{Number.isFinite(time) ? <time dateTime={new Date(time).toISOString()}>{new Date(time).toISOString().replace("T", " ").replace(".000Z", " UTC")}</time> : "Unknown time"}</dd>
          <dd className="text-ink-secondary">{sources.join(", ") || "Unknown source"}</dd>
          {receipt.conflicted === true && <dd className="text-[color:var(--status-warn)]">Conflicting observations</dd>}
        </div>;
      })}
    </dl>
    <div className="flex flex-wrap items-center gap-2 text-ink-secondary">
      <label>Rows <select aria-label="Observations per page" value={pageSize} onChange={event => { setPageSize(Number(event.target.value)); setPage(0); }} className="rounded border border-outline bg-surface px-1 py-1"><option value={10}>10</option><option value={25}>25</option></select></label>
      <button type="button" aria-label="Previous observations" disabled={current === 0} onClick={() => setPage(current - 1)} className="rounded border border-outline px-2 py-1 disabled:opacity-40">Previous</button>
      <span>Page {current + 1} of {pages}</span>
      <button type="button" aria-label="Next observations" disabled={current + 1 === pages} onClick={() => setPage(current + 1)} className="rounded border border-outline px-2 py-1 disabled:opacity-40">Next</button>
    </div>
  </section>;
}
