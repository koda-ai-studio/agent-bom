"use client";

import { useState } from "react";
import type { GatewayActivity } from "@/lib/gateway-activity";
import { ActivityRows } from "./GatewayActivityRows";

export function ActivityWindow({ events, onFreeze }: { events: GatewayActivity[]; onFreeze: () => void }) {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(50);
  const [grouped, setGrouped] = useState(false);
  const [agent, setAgent] = useState<string | null>(null);
  const groups = new Map<string, { total: number; blocked: number; tools: Set<string> }>();
  for (const event of events) {
    const group = groups.get(event.agent_id) ?? { total: 0, blocked: 0, tools: new Set<string>() };
    group.total += 1;
    if (event.decision === "deny") group.blocked += 1;
    if (event.tool) group.tools.add(event.tool);
    groups.set(event.agent_id, group);
  }
  const scoped = agent === null ? events : events.filter(event => event.agent_id === agent);
  const groupRows = [...groups].sort((a, b) => b[1].blocked - a[1].blocked || b[1].total - a[1].total || a[0].localeCompare(b[0]));
  const count = grouped ? groupRows.length : scoped.length;
  const currentPage = Math.min(page, Math.max(0, Math.ceil(count / pageSize) - 1));
  const start = currentPage * pageSize;
  return <div>
    <div className="mb-3 flex flex-wrap items-center gap-2" aria-label="Activity view">
      <button aria-pressed={!grouped} className="graph-page-action" onClick={() => { setGrouped(false); setPage(0); }}>Events</button>
      <button aria-pressed={grouped} className="graph-page-action" onClick={() => { setGrouped(true); setAgent(null); setPage(0); onFreeze(); }}>By agent</button>
      <span className="text-xs text-[var(--text-secondary)]">{events.length} filtered events in the buffered window</span>
      {agent !== null && <button className="graph-page-action" onClick={() => { setAgent(null); setPage(0); }}>Clear agent: {agent || "Unattributed"}</button>}
    </div>
    {grouped ? <div className="max-h-[36rem] overflow-y-auto" aria-label="Agent activity summary">
      {groupRows.slice(start, start + pageSize).map(([identity, group]) => <button key={identity} onClick={() => { setAgent(identity); setGrouped(false); setPage(0); onFreeze(); }} className="flex w-full flex-wrap items-center justify-between gap-2 border-b border-[var(--border-subtle)] px-2 py-3 text-left hover:bg-[var(--surface-muted)]">
        <span className="min-w-0 break-all text-sm font-medium">{identity || "Unattributed agent"}</span>
        <span className="text-xs text-[var(--text-secondary)]">{group.total} events · {group.blocked} blocked · {group.tools.size} tools</span>
      </button>)}
    </div> : <ActivityRows events={scoped.slice(start, start + pageSize)} />}
    <nav aria-label="Activity pagination" className="mt-3 flex flex-wrap items-center justify-between gap-3 text-xs text-[var(--text-secondary)]">
      <span>{count ? start + 1 : 0}–{Math.min(start + pageSize, count)} of {count} {grouped ? "agents" : "matching events"}</span>
      <label className="flex items-center gap-2">Rows per page<select value={pageSize} onChange={event => { setPageSize(Number(event.target.value)); setPage(0); }} className="rounded border border-[var(--border-subtle)] bg-[var(--background)] p-1">{[50, 100, 250].map(size => <option key={size} value={size}>{size}</option>)}</select></label>
      <div className="flex gap-2"><button className="graph-page-action" disabled={currentPage === 0} onClick={() => { onFreeze(); setPage(currentPage - 1); }}>Previous events</button><button className="graph-page-action" disabled={start + pageSize >= count} onClick={() => { onFreeze(); setPage(currentPage + 1); }}>Next events</button></div>
    </nav>
  </div>;
}
