"use client";

import { useState } from "react";

import { AGENT_FACETS, type AgentFacet } from "./agents-list-state";

const FACET_LABEL: Record<AgentFacet, string> = { type: "Type", status: "Status", source: "Source" };
const VISIBLE_CHIPS = 8;

function chipLabel(facet: AgentFacet, value: string): string {
  if (facet === "status" && value === "installed-not-configured") return "not configured";
  return value.replaceAll("_", " ");
}

function FacetGroup({
  facet,
  counts,
  selected,
  onToggle,
}: {
  facet: AgentFacet;
  counts: Record<string, number>;
  selected: string[];
  onToggle: (facet: AgentFacet, value: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  // A selected value stays visible (count 0) so it can always be cleared.
  const entries = Object.entries(counts);
  for (const value of selected) if (!(value in counts)) entries.push([value, 0]);
  if (entries.length === 0) return null;
  const visible = expanded ? entries : entries.filter(([value], index) => index < VISIBLE_CHIPS || selected.includes(value));
  const hidden = entries.length - visible.length;
  return (
    <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label={`Filter by ${FACET_LABEL[facet].toLowerCase()}`}>
      <span className="w-14 shrink-0 text-[11px] font-medium uppercase tracking-[0.1em] text-[color:var(--text-tertiary)]">
        {FACET_LABEL[facet]}
      </span>
      {visible.map(([value, count]) => {
        const pressed = selected.includes(value);
        return (
          <button
            key={value}
            type="button"
            aria-pressed={pressed}
            onClick={() => onToggle(facet, value)}
            className={`inline-flex cursor-pointer items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[color:var(--accent)] ${
              pressed
                ? "border-[color:var(--accent-border)] bg-[color:var(--accent-soft)] text-[color:var(--accent)]"
                : "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)] hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
            }`}
          >
            {chipLabel(facet, value)}
            <span className="font-mono text-[11px] tabular-nums opacity-80">{count.toLocaleString()}</span>
          </button>
        );
      })}
      {hidden > 0 || expanded ? (
        <button
          type="button"
          onClick={() => setExpanded((open) => !open)}
          className="cursor-pointer text-xs text-[color:var(--accent)] hover:underline"
        >
          {expanded ? "Fewer" : `+${hidden} more`}
        </button>
      ) : null}
    </div>
  );
}

export function AgentsFilterChips({
  facets,
  selected,
  onToggle,
}: {
  facets: Partial<Record<string, Record<string, number>>> | undefined;
  selected: Record<AgentFacet, string[]>;
  onToggle: (facet: AgentFacet, value: string) => void;
}) {
  return (
    <div className="space-y-1.5" data-testid="agents-filter-chips">
      {AGENT_FACETS.map((facet) => (
        <FacetGroup key={facet} facet={facet} counts={facets?.[facet] ?? {}} selected={selected[facet]} onToggle={onToggle} />
      ))}
    </div>
  );
}
