"use client";

import { useState, type FormEvent } from "react";
import { Search } from "lucide-react";

import type { AdvisoryAffectedSummary, AffectedVerdictFilter } from "@/lib/advisory-affected";

const PILLS: { key: AffectedVerdictFilter; label: string; count: (s: AdvisoryAffectedSummary) => number }[] = [
  { key: "all", label: "All", count: s => s.affected + s.possibly_affected + s.not_affected },
  { key: "affected", label: "Affected", count: s => s.affected },
  { key: "possibly_affected", label: "Possibly affected", count: s => s.possibly_affected },
  { key: "not_affected", label: "Not affected", count: s => s.not_affected },
];

/** Verdict pills with server counts plus a search box; both are applied through the URL. */
export function AffectedFilterToolbar({
  verdict,
  q,
  summary,
  onVerdict,
  onSearch,
}: {
  verdict: AffectedVerdictFilter;
  q: string;
  summary: AdvisoryAffectedSummary | null;
  onVerdict: (next: AffectedVerdictFilter) => void;
  onSearch: (next: string) => void;
}) {
  const [text, setText] = useState(q);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    onSearch(text.trim());
  };
  return (
    <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex flex-wrap gap-1.5" aria-label="Filter by verdict" role="group">
        {PILLS.map(pill => {
          const pressed = pill.key === verdict;
          return (
            <button key={pill.key} type="button" aria-pressed={pressed} onClick={() => onVerdict(pill.key)}
              className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium transition-colors ${pressed
                ? "border-[color:var(--accent-border)] bg-[color:var(--accent-soft)] text-[color:var(--accent)]"
                : "border-outline bg-surface-muted text-ink-secondary hover:border-outline-strong hover:text-foreground"}`}>
              {pill.label}
              {summary ? <span className="font-mono text-[11px] opacity-80">{pill.count(summary).toLocaleString()}</span> : null}
            </button>
          );
        })}
      </div>
      <form role="search" onSubmit={submit} className="relative w-full sm:w-72">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-tertiary" aria-hidden />
        <input type="search" aria-label="Search asset or package" value={text} onChange={e => setText(e.target.value)} placeholder="Search asset or package"
          className="w-full rounded-lg border border-outline bg-surface-muted py-1.5 pl-8 pr-3 text-sm text-foreground placeholder:text-ink-tertiary focus:border-[color:var(--accent-border)] focus:outline-none" />
      </form>
    </div>
  );
}
