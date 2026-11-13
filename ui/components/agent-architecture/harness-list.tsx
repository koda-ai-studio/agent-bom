"use client";

import { Bug, Loader2 } from "lucide-react";

import { severityStyle } from "@/components/attack-path-graph-node";
import { frameworkLabel } from "@/lib/agent-architecture-model";
import type { AgentHarness } from "@/lib/agent-architecture-types";

type Props = {
  harnesses: AgentHarness[];
  selectedId: string;
  total: number;
  hasMore: boolean;
  loadingMore: boolean;
  onSelect: (id: string) => void;
  onLoadMore: () => void;
};

/** Harnesses in API order; more pages load with the API cursor rather than all at once. */
export function HarnessList({ harnesses, selectedId, total, hasMore, loadingMore, onSelect, onLoadMore }: Props) {
  return (
    <nav aria-label="Harnesses" className="flex min-h-0 flex-col gap-2">
      <p className="px-1 text-xs font-semibold uppercase tracking-wide text-ink-tertiary">Harnesses · {harnesses.length} of {total}</p>
      <ul className="grid max-h-[13.5rem] gap-2 overflow-y-auto sm:grid-cols-2 xl:grid-cols-4">
        {harnesses.map(harness => {
          const selected = harness.harness_id === selectedId;
          const findings = harness.security.findings;
          return (
            <li key={harness.harness_id}>
              <button type="button" aria-pressed={selected} onClick={() => onSelect(harness.harness_id)}
                className={`w-full rounded-xl border px-3 py-2 text-left transition-colors focus-visible:outline-2 focus-visible:outline-[color:var(--focus-ring)] ${selected ? "border-[color:var(--accent)] bg-surface-elevated" : "border-outline bg-surface hover:bg-surface-muted"}`}>
                <span className="flex items-center gap-2">
                  <span className="min-w-0 flex-1 truncate text-sm font-semibold text-foreground">{harness.label}</span>
                  {findings > 0 && (
                    <span title={`${findings} ${findings === 1 ? "finding" : "findings"}, worst ${harness.security.max_severity || "unrated"}`}
                      className="inline-flex items-center gap-0.5 rounded-full border px-1.5 text-xs font-bold tabular-nums" style={severityStyle(harness.security.max_severity)}>
                      <Bug className="h-3 w-3" aria-hidden="true" />{findings}
                    </span>
                  )}
                </span>
                <span className="block truncate text-xs text-ink-secondary">{harness.harness_kind} · {frameworkLabel(harness.framework)} · {harness.agent_count} agents · {harness.layer_count} layers</span>
                <span className="block truncate font-mono text-[11px] text-ink-tertiary">{harness.declared_in ? `${harness.declared_in.label} · ` : ""}{harness.file_path}{harness.line_number ? `:${harness.line_number}` : ""}</span>
              </button>
            </li>
          );
        })}
      </ul>
      {hasMore && (
        <button type="button" onClick={onLoadMore} disabled={loadingMore}
          aria-label={`Load more harnesses (${harnesses.length} of ${total})`}
          className="inline-flex items-center justify-center gap-2 self-start rounded-lg border border-outline px-4 py-2 text-sm font-medium text-foreground hover:bg-surface-muted disabled:opacity-60">
          {loadingMore && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}Load more
        </button>
      )}
    </nav>
  );
}
