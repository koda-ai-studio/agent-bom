"use client";

import { useState } from "react";
import Link from "next/link";
import { Drawer } from "@/components/drawer";
import { formatDate } from "@/lib/api";
import { producerEvidenceLabel, PRODUCER_EVIDENCE_HINT } from "@/lib/gateway-feed";
import type { GatewayActivity } from "@/lib/gateway-activity";

const activityLabels: Record<string, string> = {
  "gateway.tool_call.allowed": "Tool call allowed", "gateway.tool_call.blocked": "Tool call blocked",
  "gateway.dlp.arguments_redacted": "Arguments redacted", "gateway.dlp.result_redacted": "Result redacted",
  "gateway.dlp.result_blocked": "Result blocked", "gateway.visual.redacted": "Visual data redacted",
  "gateway.visual_leak_blocked": "Visual leak blocked", "gateway.runtime_profile.blocked": "Profile blocked",
  "gateway.runtime_profile.warned": "Profile warning", "gateway.runtime_profile.dev_bypass": "Development bypass",
  "gateway.enforcement.warned": "Enforcement warning", "gateway.enforcement.observed": "Enforcement observation",
  "gateway.enforcement.blocked": "Enforcement blocked",
};


export function ActivityRows({ events }: { events: GatewayActivity[] }) {
  const [selected, setSelected] = useState<GatewayActivity | null>(null);
  return <>
    <div className="max-h-[36rem] overflow-y-auto">
      {events.map(event => <article key={event.event_id} className="min-w-0 border-b border-[var(--border-subtle)]" data-testid="gateway-activity-row">
        <button className="grid w-full gap-2 rounded-lg px-2 py-3 text-left hover:bg-[var(--surface-muted)] sm:grid-cols-[5.5rem_minmax(0,1fr)_11rem]" onClick={() => setSelected(event)} aria-label={`Inspect ${event.agent_id || "unattributed agent"} ${event.tool || "gateway decision"}`}>
          <time className="text-xs text-[var(--text-secondary)]" title={event.ingested_at}>{event.ingested_at ? new Date(event.ingested_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "Time unknown"}</time>
          <span className="min-w-0"><span className="block break-words text-sm font-medium">{event.agent_id || "Unattributed agent"}</span><span className="mt-1 block break-all text-xs text-[var(--text-secondary)]">{event.upstream || "Gateway"}{event.tool ? ` / ${event.tool}` : ""}</span></span>
          <span><span className={`block text-xs font-medium ${event.decision === "deny" ? "text-red-700 dark:text-red-300" : "text-[var(--foreground)]"}`}>{activityLabels[event.event_type] ?? "Gateway decision"}</span><span className="mt-1 block text-xs text-[var(--text-secondary)]" title={PRODUCER_EVIDENCE_HINT}>{producerEvidenceLabel(event.submission_provenance?.producer_assurance)}</span></span>
        </button>
      </article>)}
    </div>
    <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} title={selected?.tool || "Gateway decision"} subtitle={selected?.agent_id || "Unattributed agent"} ariaLabel="Activity details" size="lg">
      {selected && <div className="space-y-5 text-sm">
        <p className="font-medium">{activityLabels[selected.event_type] ?? "Gateway decision"}</p>
        <p>{(selected.reason_code || selected.data_action || "No reason recorded").replaceAll("_", " ")}</p>
        {selected.development_mode && <p className="text-amber-800 dark:text-amber-200">Development bypass</p>}
        <dl className="space-y-3">{[
          ["Received", selected.ingested_at ? formatDate(selected.ingested_at) : "Unavailable"], ["Reported time", selected.event_timestamp],
          ["Submitter", selected.submission_provenance?.submitter_principal_id],
          ["Authentication method", selected.submission_provenance?.authentication_method],
          ["Collector source", selected.submission_provenance?.submission_source_id || selected.source_id],
          ["Collector session", selected.submission_provenance?.submission_session_id || selected.session_id],
          ["Reported source", selected.submission_provenance?.reported_source_id], ["Reported session", selected.submission_provenance?.reported_session_id],
          ["Profile", selected.profile_id], ["Profile revision", selected.profile_revision], ["Blueprint", selected.blueprint_id], ["Blueprint revision", selected.blueprint_revision],
          ["Policies", selected.policy_ids?.join(", ") || selected.policy_id], ["Evidence", selected.evidence_id], ["Trace ID", selected.trace_id],
          ["Receipt trace", selected.receipt_trace_id], ["Identity", selected.identity_id], ["Event ID", selected.event_id], ["Event type", selected.event_type],
        ].map(([label, value]) => <div key={label}><dt className="text-xs text-[var(--text-secondary)]">{label}</dt><dd className="mt-1 break-all">{value || "Not recorded"}</dd></div>)}</dl>
        <p className="rounded-lg bg-[var(--background)] p-3 text-xs text-[var(--text-secondary)]">{producerEvidenceLabel(selected.submission_provenance?.producer_assurance)}. {PRODUCER_EVIDENCE_HINT}</p>
        <div className="flex flex-wrap gap-3">
          {selected.trace_id && <Link className="graph-page-action" href={`/security-graph?${new URLSearchParams({ trace: selected.trace_id, agent: selected.agent_id })}`}>Pin trace</Link>}
          {selected.agent_id && <Link className="graph-page-action" href={`/traces?${new URLSearchParams({ agent: selected.agent_id })}`}>Agent traces</Link>}
        </div>
        <p className="text-xs text-[var(--text-secondary)]">Agent traces match the reported agent name across origins in a bounded sample. This is not proof of a unique agent or shared trace.</p>
      </div>}
    </Drawer>
  </>;
}
