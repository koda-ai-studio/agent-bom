"use client";

import { useState } from "react";
import { EXPOSED_BY_IMPACT_NOTE, exposedByImpactLabel } from "@/lib/credential-basis";
import { ChevronDown, ChevronUp, Ticket } from "lucide-react";

import { severityColor, severityDot, type RemediationItem, type TicketLink } from "@/lib/api";
import { TicketStatusChip } from "@/components/ticket-modal";

const plural = (count: number, noun: string) => `${count} ${noun}${count === 1 ? "" : "s"}`;

function RemediationCard({ item, ticket, onCreateTicket }: {
  item: RemediationItem;
  ticket: TicketLink | undefined;
  onCreateTicket: (item: RemediationItem) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const tags = [...(item.owasp_tags ?? []), ...(item.atlas_tags ?? [])];
  const hasDetails = Boolean(item.risk_narrative || item.command || item.verify_command);
  return (
    <li data-testid="remediation-card" className="space-y-2 px-3 py-3">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="flex items-center gap-2 break-words font-mono text-sm text-foreground [overflow-wrap:anywhere]">
            <span aria-hidden className={`h-1.5 w-1.5 shrink-0 rounded-full ${severityDot(item.severity)}`} />
            {item.package}
          </p>
          <p className="mt-0.5 font-mono text-xs text-ink-secondary">current {item.current_version}</p>
        </div>
        <div className="flex shrink-0 items-center gap-1.5">
          <span className={`rounded border px-2 py-0.5 text-xs font-medium ${severityColor(item.severity)}`}>{item.severity}</span>
          {item.is_kev && <span className="rounded border border-[color:var(--severity-critical-border)] bg-[color:var(--severity-critical-bg)] px-1.5 py-0.5 font-mono text-xs text-[color:var(--severity-critical)]">KEV</span>}
        </div>
      </div>
      <dl className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs text-ink-secondary">
        <dd className={item.fixed_version ? "font-mono text-[color:var(--status-success)]" : "text-ink-tertiary"}>
          {item.fixed_version ? `Fix ${item.fixed_version}` : "No fixed version"}
        </dd>
        <dd className="font-mono">Risk {item.impact_score.toFixed(1)}</dd>
        <dd>{plural(item.affected_agents?.length ?? 0, "agent")}</dd>
        <dd title={EXPOSED_BY_IMPACT_NOTE}>{exposedByImpactLabel(item.exposed_credentials?.length ?? 0)}</dd>
      </dl>
      <div className="flex flex-wrap gap-1">
        {item.vulnerabilities.slice(0, 2).map(cve => (
          <span key={cve} className="rounded border border-outline bg-surface px-1.5 py-0.5 font-mono text-xs text-ink-secondary">{cve}</span>
        ))}
        {item.vulnerabilities.length > 2 && <span className="self-center text-xs text-ink-tertiary">+{item.vulnerabilities.length - 2}</span>}
        {tags.slice(0, 3).map(tag => (
          <span key={tag} className="rounded border border-outline bg-surface-elevated px-1.5 py-0.5 font-mono text-xs text-ink-secondary">{tag}</span>
        ))}
      </div>
      <div className="flex flex-wrap gap-2">
        <button type="button" onClick={() => onCreateTicket(item)} title={ticket ? "View or sync ticket" : "Create a ticket"}
          className="flex min-h-11 items-center gap-1.5 rounded bg-surface-elevated px-3 text-xs font-medium text-ink-secondary hover:text-foreground">
          {ticket ? <><span className="font-mono text-foreground">{ticket.key || ticket.external_id || "Ticket"}</span><TicketStatusChip status={ticket.status} /></> : <><Ticket className="h-3.5 w-3.5" />Ticket</>}
        </button>
        {hasDetails && (
          <button type="button" aria-expanded={expanded} onClick={() => setExpanded(value => !value)}
            className="flex min-h-11 items-center gap-1 rounded bg-surface-elevated px-3 text-xs font-medium text-ink-secondary hover:text-foreground">
            {expanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}Details
          </button>
        )}
      </div>
      {expanded && hasDetails && (
        <div className="space-y-2 text-xs">
          {item.risk_narrative && <p className="border-l-2 border-emerald-700 pl-3 leading-relaxed text-ink-secondary">{item.risk_narrative}</p>}
          {item.command && <code className="block whitespace-pre-wrap break-all rounded-lg border border-outline bg-[var(--background)] p-2 font-mono text-emerald-700 dark:text-emerald-300">{item.command}</code>}
          {item.verify_command && <code className="block whitespace-pre-wrap break-all rounded-lg border border-outline bg-[var(--background)] p-2 font-mono text-ink-secondary">{item.verify_command}</code>}
        </div>
      )}
    </li>
  );
}

/** The phone reading of the remediation table: one stacked card per package, no horizontal scroll. */
export function RemediationCardList({ items, ticketFor, onCreateTicket, className = "" }: {
  items: RemediationItem[];
  ticketFor: (item: RemediationItem) => TicketLink | undefined;
  onCreateTicket: (item: RemediationItem) => void;
  className?: string;
}) {
  return (
    <ul aria-label="Packages to remediate" className={`divide-y divide-[var(--border-subtle)] rounded-xl border border-outline bg-[var(--background)] ${className}`}>
      {items.map(item => <RemediationCard key={`${item.package}-${item.current_version}`} item={item} ticket={ticketFor(item)} onCreateTicket={onCreateTicket} />)}
    </ul>
  );
}
