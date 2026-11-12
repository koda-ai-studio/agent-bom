"use client";

import { X } from "lucide-react";

import type { UnifiedNode } from "@/lib/graph-schema";

const RATED = new Set(["critical", "high", "medium", "low"]);

/** The findings behind one asset's badge; each opens the finding's detail. */
export function AttackPathFindingsList({ asset, findings, onSelect, onClose }: {
  asset: string;
  findings: UnifiedNode[];
  onSelect: (findingId: string) => void;
  onClose: () => void;
}) {
  return (
    <section aria-label={`Findings on ${asset}`} className="border-t border-outline bg-surface px-3 py-2">
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-xs font-semibold text-foreground">{findings.length} findings on {asset}</h3>
        <button type="button" aria-label="Close findings" onClick={onClose} className="graph-page-action min-h-8 min-w-8 justify-center px-1">
          <X className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      </div>
      <ul className="mt-1 divide-y divide-[color:var(--border-subtle)]">
        {findings.map(finding => {
          const severity = String(finding.severity ?? "").toLowerCase();
          return (
            <li key={finding.id}>
              <button type="button" onClick={() => onSelect(finding.id)}
                className="flex w-full min-h-9 items-center gap-2 py-1.5 text-left text-sm text-foreground hover:underline">
                <span className="w-16 shrink-0 text-xs font-semibold uppercase"
                  style={{ color: RATED.has(severity) ? `var(--severity-${severity})` : "var(--text-secondary)" }}>
                  {RATED.has(severity) ? severity : "unrated"}
                </span>
                <span className="truncate font-mono text-xs">{finding.label}</span>
              </button>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
