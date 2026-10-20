"use client";

import Link from "next/link";
import { Loader2 } from "lucide-react";

import { GraphEmptyState } from "@/components/graph-state-panels";
import { formatDate, type FixFirstGraphViewResponse, type GraphSnapshot, type PostureResponse } from "@/lib/api";
import type { investigationEstateMode } from "@/lib/investigation-estate-mode";
import { tonedChipClass } from "@/lib/toned-chip";

/** The selected scan's evidence summary and the snapshot chooser. */
export function InvestigationScanEvidence({
  selectedScanId, selectedSnapshot, posture, fixFirstView, loadingSnapshots, snapshots, currentEstateId,
  displayedSnapshots, onSelect, hiddenSnapshotCount, showAll, onToggleShowAll, estateMode,
}: {
  selectedScanId: string;
  selectedSnapshot: GraphSnapshot | null;
  posture: PostureResponse | null;
  fixFirstView: FixFirstGraphViewResponse | null;
  loadingSnapshots: boolean;
  snapshots: GraphSnapshot[];
  currentEstateId: string;
  displayedSnapshots: GraphSnapshot[];
  onSelect: (scanId: string) => void;
  hiddenSnapshotCount: number;
  showAll: boolean;
  onToggleShowAll: () => void;
  estateMode: ReturnType<typeof investigationEstateMode>;
}) {
  return (
    <>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                Current scan evidence
              </p>
              <p className="mt-1 font-mono text-sm text-[color:var(--foreground)]">
                {selectedScanId.startsWith("current-estate:") ? "Current tenant estate" : selectedSnapshot ? selectedSnapshot.scan_id : "No scan selected"}
              </p>
              {selectedSnapshot ? <p className="mt-1 text-xs text-ink-tertiary">{formatDate(selectedSnapshot.created_at)} · {selectedSnapshot.node_count} nodes · {selectedSnapshot.edge_count} edges</p> : null}
            </div>
            <div className="flex flex-wrap gap-2 text-xs">
              {posture ? <QuickStat label="Posture" value={`${posture.grade} ${posture.score}`} tone="red" /> : null}
              {fixFirstView ? (
                <>
                  <QuickStat label="Matched paths" value={String(fixFirstView.summary.matched_paths)} tone="blue" />
                  <QuickStat label="Covered findings" value={String(fixFirstView.summary.covered_findings)} tone="amber" />
                  <QuickStat label="Highest risk" value={fixFirstView.summary.highest_risk.toFixed(1)} tone="red" />
                </>
              ) : null}
            </div>
          </div>

          {loadingSnapshots ? (
            <span className="inline-flex items-center gap-2 text-xs text-sky-400">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              Loading scan evidence
            </span>
          ) : snapshots.length > 0 ? (
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                Manage snapshots
              </p>
              <div className="mt-2 flex flex-wrap gap-2">
                {currentEstateId && <button type="button" className="graph-chip-neutral" aria-pressed={selectedScanId === currentEstateId} onClick={() => onSelect(currentEstateId)}>Current tenant estate</button>}
                {displayedSnapshots.map((snapshot) => {
                  const selected = snapshot.scan_id === selectedScanId;
                  return (
                    <button
                      key={snapshot.scan_id}
                      type="button"
                      onClick={() => onSelect(snapshot.scan_id)}
                      className={`rounded-xl border px-3 py-2 text-left text-xs transition ${
                        selected
                          ? "border-emerald-700 bg-emerald-500/10 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-200"
                          : "border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] text-[color:var(--text-secondary)] hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
                      }`}
                    >
                      <span className="block font-mono">{snapshot.scan_id.slice(0, 8)}…</span>
                      <span className="mt-1 block text-[11px] opacity-80">{snapshot.node_count} nodes</span>
                    </button>
                  );
                })}
              </div>
              {hiddenSnapshotCount > 0 || showAll ? (
                <button
                  type="button"
                  onClick={() => onToggleShowAll()}
                  className="mt-3 rounded-lg border border-[color:var(--border-subtle)] px-3 py-1.5 text-xs text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
                >
                  {showAll
                    ? "Show active snapshots"
                    : `Show all ${snapshots.length} snapshots (${hiddenSnapshotCount} empty or older)`}
                </button>
              ) : null}
            </div>
          ) : (
            <GraphEmptyState
              title="No persisted graph snapshots yet"
              detail="Run a scan first so Investigation can rank paths from persisted graph evidence."
              suggestions={[
                "Run a local scan with graph output enabled.",
                "Confirm the graph persistence backend is enabled.",
              ]}
              command="agent-bom scan -p . -f graph"
              actions={[{ label: "Run a scan", href: "/scan" }]}
            />
          )}

          {selectedSnapshot && estateMode.large ? (
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[color:var(--border-subtle)] pt-3 text-xs text-[color:var(--text-secondary)]">
              <span>{estateMode.summary}. Use a focused lens before opening the full topology.</span>
              <div className="flex flex-wrap gap-3">
                <Link href={estateMode.clusteredHref} className="font-medium text-[color:var(--accent-mint)] hover:underline">
                  Explore clusters
                </Link>
                <Link href={estateMode.rawHref} className="font-medium text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)] hover:underline">
                  Open raw topology
                </Link>
              </div>
            </div>
          ) : null}
    </>
  );
}

function QuickStat({ label, value, tone = "zinc" }: { label: string; value: string; tone?: "zinc" | "red" | "amber" | "blue" }) {
  const tones = {
    zinc: "border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] text-[color:var(--foreground)]",
    red: tonedChipClass("danger"),
    amber: tonedChipClass("warn"),
    blue: tonedChipClass("low"),
  };
  return (
    <div className={`rounded-2xl border px-4 py-3 ${tones[tone]}`}>
      <div className="text-[11px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">{label}</div>
      <div className="mt-1 font-mono text-xl">{value}</div>
    </div>
  );
}
