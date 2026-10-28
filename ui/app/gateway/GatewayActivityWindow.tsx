"use client";

import { useMemo, useState } from "react";
import type { GatewayActivity } from "@/lib/gateway-activity";
import { activityGroups, activityOrigin } from "@/lib/gateway-activity-groups";
import { ActivityRows } from "./GatewayActivityRows";

export function ActivityWindow({ events, onFreeze }: { events: GatewayActivity[]; onFreeze: () => void }) {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(50);
  const [grouped, setGrouped] = useState(true);
  const [agent, setAgent] = useState<string | null>(null);
  const groupRows = useMemo(() => activityGroups(events), [events]);
  const scoped = useMemo(() => agent === null ? events : events.filter(event => activityOrigin(event).key === agent), [events, agent]);
  const count = grouped ? groupRows.length : scoped.length;
  const currentPage = Math.min(page, Math.max(0, Math.ceil(count / pageSize) - 1));
  const start = currentPage * pageSize;
  return <div>
    <div className="mb-3 flex flex-wrap items-center gap-2" aria-label="Activity view">
      <button aria-pressed={!grouped} className="graph-page-action aria-pressed:bg-[var(--surface-muted)] aria-pressed:font-semibold" onClick={() => { setGrouped(false); setPage(0); }}>Events</button>
      <button aria-pressed={grouped} className="graph-page-action aria-pressed:bg-[var(--surface-muted)] aria-pressed:font-semibold" onClick={() => { setGrouped(true); setAgent(null); setPage(0); onFreeze(); }}>Activity groups</button>
      <span className="text-xs text-[var(--text-secondary)]">{events.length} filtered events in the buffered window</span>
      {agent !== null && <button className="graph-page-action" onClick={() => { setAgent(null); setPage(0); }}>Clear group filter</button>}
    </div>
    {grouped ? <section className="max-h-[36rem] overflow-y-auto" aria-label="Reported activity groups">
      <p className="mb-3 text-xs text-[var(--text-secondary)]">Blocked and warning activity first. Groups use reported origin, session and identity; not a verified unique-agent count.</p>
      {groupRows.slice(start, start + pageSize).map(group => {
        const origin = activityOrigin(group.event);
        return <button key={group.key} onClick={() => { setAgent(group.key); setGrouped(false); setPage(0); onFreeze(); }} className="flex w-full flex-col items-stretch gap-2 border-b border-[var(--border-subtle)] px-2 py-3 text-left hover:bg-[var(--surface-muted)] sm:flex-row sm:items-center sm:justify-between">
          <span className="min-w-0 flex-1">
            <span className="block break-all text-sm font-medium">{group.event.agent_id || "Unattributed agent"}</span>
            <span className="mt-1 block break-all text-xs text-[var(--text-secondary)]">{origin.reportedSource || origin.source || "Origin not recorded"}{origin.reportedSource && origin.source ? ` via ${origin.source}` : ""}</span>
            <span className="mt-1 block break-all text-xs text-[var(--text-secondary)]">{group.event.profile_id ? `Profile: ${group.event.profile_id}` : "No profile recorded"}{group.event.identity_id ? ` · Identity: ${group.event.identity_id}` : ""}{(origin.reportedSession || origin.session) ? ` · Session: ${origin.reportedSession || origin.session}` : ""}</span>
            {group.event.submission_provenance?.submitter_principal_id && <span className="mt-1 block break-all text-xs text-[var(--text-secondary)]">Submitter: {group.event.submission_provenance.submitter_principal_id}</span>}
          </span>
          <span className="flex flex-wrap gap-2 text-xs">
            {group.blocked > 0 && <span className="rounded bg-red-50 px-2 py-1 font-medium text-red-800 dark:bg-red-950 dark:text-red-200">{group.blocked} blocked</span>}
            {group.warnings > 0 && <span className="rounded bg-amber-50 px-2 py-1 font-medium text-amber-800 dark:bg-amber-950 dark:text-amber-200">{group.warnings} {group.warnings === 1 ? "warning" : "warnings"}</span>}
            <span className="py-1 text-[var(--text-secondary)]">{group.total} {group.total === 1 ? "event" : "events"} · {group.tools.size} {group.tools.size === 1 ? "tool" : "tools"}</span>
          </span>
        </button>;
      })}
    </section> : <ActivityRows events={scoped.slice(start, start + pageSize)} />}
    <nav aria-label="Activity pagination" className="mt-3 flex flex-wrap items-center justify-between gap-3 text-xs text-[var(--text-secondary)]">
      <span>{count ? start + 1 : 0}–{Math.min(start + pageSize, count)} of {count} {grouped ? "activity groups" : "matching events"}</span>
      <label className="flex items-center gap-2">Rows per page<select value={pageSize} onChange={event => { setPageSize(Number(event.target.value)); setPage(0); }} className="rounded border border-[var(--border-subtle)] bg-[var(--background)] p-1">{[50, 100, 250].map(size => <option key={size} value={size}>{size}</option>)}</select></label>
      <div className="flex gap-2"><button className="graph-page-action" disabled={currentPage === 0} onClick={() => { onFreeze(); setPage(currentPage - 1); }}>Previous events</button><button className="graph-page-action" disabled={start + pageSize >= count} onClick={() => { onFreeze(); setPage(currentPage + 1); }}>Next events</button></div>
    </nav>
  </div>;
}
