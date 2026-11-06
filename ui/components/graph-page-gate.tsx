"use client";

import { AlertTriangle, Loader2, ShieldAlert } from "lucide-react";
import type { GraphPageModel } from "@/components/graph-page-view";

/** The states with nothing to investigate yet; null once a snapshot can be shown. */
export function graphPageGate({ loadingSnapshots, error, snapshots, selectedScanId, setSnapshotRetry, rateLimited }: GraphPageModel) {
  if (loadingSnapshots) {
    return (
      <div className="flex items-center justify-center h-[80vh] text-ink-secondary">
        <Loader2 className="w-5 h-5 animate-spin mr-2" />
        Loading persisted graph snapshots...
      </div>
    );
  }

  if (error && snapshots.length === 0 && !selectedScanId) {
    return (
      <div className="flex flex-col items-center justify-center h-[80vh] text-ink-secondary gap-3">
        <AlertTriangle className="w-8 h-8 text-amber-500" />
        <button type="button" className="graph-chip-neutral" onClick={() => setSnapshotRetry((value) => value + 1)}>Retry loading snapshots</button>
        {rateLimited ? (
          <>
            <p className="text-sm">Graph temporarily rate-limited</p>
            <p className="text-xs text-ink-tertiary">
              The API is shedding load (HTTP 429). Wait a moment and retry — your
              snapshots are still there.
            </p>
          </>
        ) : (
          <>
            <p className="text-sm">Could not load the unified graph</p>
            <p className="text-xs text-ink-tertiary">
              Run a scan first so the API can persist graph snapshots.
            </p>
          </>
        )}
      </div>
    );
  }

  if (snapshots.length === 0 && !selectedScanId) {
    return (
      <div className="flex flex-col items-center justify-center h-[80vh] text-ink-secondary gap-3">
        <ShieldAlert className="w-8 h-8 text-ink-tertiary" />
        <p className="text-sm">No graph snapshots found</p>
        <p className="text-xs text-ink-tertiary">
          Run a scan to persist the unified inventory and security graph.
        </p>
      </div>
    );
  }
  return null;
}
