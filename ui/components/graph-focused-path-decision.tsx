"use client";

import { GraphHopEvidenceInspector } from "@/components/graph-hop-evidence-inspector";
import type { AttackPath, UnifiedNode } from "@/lib/graph-schema";

export interface FocusedPathDecision {
  findingLabel: string;
  nextAction: string;
  remediationHref: string;
  directedTraversable: number | null;
  hasHopReceipts: boolean;
  sourceLabel: string;
  targetLabel: string;
}

/** The decision card above a focused attack path: endpoints, risk, evidence receipts and the next action. */
export function GraphFocusedPathDecision({ path, decision, nodeById, evidenceHopCount, snapshotCreatedAt, captureMode, onReturn }: {
  path: AttackPath;
  decision: FocusedPathDecision;
  nodeById: Map<string, UnifiedNode>;
  evidenceHopCount: number;
  snapshotCreatedAt: string | null;
  captureMode: boolean;
  onReturn: () => void;
}) {
  return (
            <section
              aria-label="Focused attack path decision"
              data-testid="focused-path-decision"
              className="mb-2 rounded-xl border border-outline bg-surface px-4 py-3"
            >
              <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                <div className="min-w-0">
                  <p className="text-xs font-semibold uppercase tracking-[0.12em] text-ink-secondary">
                    Focused attack path
                  </p>
                  <h2 className="mt-1 text-lg font-semibold text-foreground">
                    {decision.sourceLabel} → {decision.targetLabel}
                  </h2>
                  <p className="mt-1 max-w-3xl text-sm text-ink-secondary">
                    {decision.findingLabel} · Inspect the recorded relationships and their evidence.
                  </p>
                </div>
                <div className="flex shrink-0 flex-wrap items-center gap-2">
                  <span className="rounded-lg border border-red-500/35 bg-red-500/10 px-3 py-2 text-sm font-semibold text-red-700 dark:text-red-200">
                    Path risk {path.composite_risk.toFixed(1)}/100
                  </span>
                  <a
                    href={decision.remediationHref}
                    className="rounded-lg bg-[var(--accent-strong)] px-3 py-2 text-sm font-semibold text-[var(--accent-contrast)] hover:opacity-90"
                  >
                    Open remediation plan
                  </a>
                </div>
              </div>
              <details className="mt-3 rounded-lg border border-outline bg-surface/60 px-3 py-2 text-sm text-ink-secondary">
                <summary className="cursor-pointer font-medium text-foreground">Path explanation and scoring</summary>
                <p className="mt-2 leading-relaxed [overflow-wrap:anywhere]">{path.summary || "No additional path explanation recorded."}</p>
                <p className="mt-2">Path risk uses a 0–100 scale; higher means more risk. This is a composite ranking score, not a CVSS score or a probability.</p>
                <div className="mt-3">
                  <GraphHopEvidenceInspector key={path.hops.join("->")} receipts={path.hop_evidence}
                    hops={path.hops.map(id => ({ id, label: nodeById.get(id)?.label || id }))} />
                </div>
              </details>
              <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-sm text-ink-secondary">
                <span>{evidenceHopCount} evidence hops</span>
                <span>{decision.hasHopReceipts
                  ? `${decision.directedTraversable === null ? "Unavailable" : `${decision.directedTraversable}/${evidenceHopCount}`} directed traversable relationships evidenced`
                  : "Directed hop verification not recorded"}</span>
                <span>Snapshot freshness: {snapshotCreatedAt ? new Date(snapshotCreatedAt).toLocaleString() : "unavailable"}</span>
                <span className="font-medium text-foreground">Next: {decision.nextAction}</span>
                {captureMode ? <span>Demo data — sample environment</span> : null}
                <button
                  type="button"
                  onClick={onReturn}
                  className="graph-chip-orange-muted"
                >
                  Return to topology
                </button>
              </div>
            </section>
  );
}
