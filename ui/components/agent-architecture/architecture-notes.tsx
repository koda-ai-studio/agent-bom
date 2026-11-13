"use client";

import { AlertTriangle, Info } from "lucide-react";

import type { ArchitectureModel } from "@/lib/agent-architecture-model";
import type { AgentHarness, HarnessCoverage } from "@/lib/agent-architecture-types";

const NOTE = "flex items-start gap-2 rounded-lg border px-3 py-2 text-sm";

/** What the read covers: an honest incomplete warning and the gaps not modelled yet. */
export function CoverageNote({ coverage }: { coverage: HarnessCoverage }) {
  return (
    <div role="status" aria-label="Coverage" className="space-y-2">
      {!coverage.complete && (
        <p className={`${NOTE} border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] text-foreground`}>
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-[color:var(--severity-medium)]" aria-hidden="true" />
          <span>Coverage is incomplete: this read reached a bound ({coverage.framework_agent_cap.toLocaleString()} framework agents, the structural edge limit or the finding overlay limit), so some agents, edges or findings may be missing.</span>
        </p>
      )}
      <details className="rounded-lg border border-outline bg-surface px-3 py-2 text-sm text-ink-secondary">
        <summary className="cursor-pointer font-medium text-foreground">Not modelled yet ({coverage.gaps.length})</summary>
        <ul className="mt-2 list-disc space-y-1 pl-5">{coverage.gaps.map(gap => <li key={gap}>{gap}</li>)}</ul>
      </details>
    </div>
  );
}

/** Per-harness bounds the API reported, so nothing reads as complete when it is not. */
export function HarnessNotes({ harness, model }: { harness: AgentHarness; model: ArchitectureModel }) {
  const notes: string[] = [];
  if (harness.truncated.agents) notes.push(`This harness has ${harness.agent_count} agents; the API returned the first ${harness.layers.reduce((sum, layer) => sum + layer.agents.length, 0)}.`);
  if (harness.truncated.flow_edges) notes.push("Flow edges were cut at the API's per-harness limit.");
  if (model.unlistedUnresolved > 0) notes.push(`${model.unlistedUnresolved} more unresolved routes were counted but not listed.`);
  if (notes.length === 0) return null;
  return (
    <ul className="space-y-1 border-b border-outline bg-surface px-3 py-2 text-xs text-ink-secondary">
      {notes.map(note => <li key={note} className="flex items-center gap-1.5"><Info className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />{note}</li>)}
    </ul>
  );
}
