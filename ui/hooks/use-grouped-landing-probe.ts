"use client";

import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import { INITIAL_CLUSTER_MAP_STATE, clusterMapHasScopeGroups, clusterMapParams } from "@/lib/graph-cluster-map";
import type { GroupedLandingProbe } from "@/lib/graph-rollup-default";

/**
 * A large estate's default landing reads the grouped map's first frame beside
 * the roll-up: it is the cheap read, so a flat estate learns it has no scope to
 * rank without waiting on the much slower roll-up.
 */
export function useGroupedLandingProbe(scanId: string | undefined, enabled: boolean): GroupedLandingProbe {
  const [result, setResult] = useState<{ scanId: string; status: GroupedLandingProbe } | null>(null);

  useEffect(() => {
    if (!enabled || !scanId) return;
    let cancelled = false;
    const settle = (status: GroupedLandingProbe) => { if (!cancelled) setResult({ scanId, status }); };
    try {
      api.getGraphClusterMap(clusterMapParams(scanId, INITIAL_CLUSTER_MAP_STATE))
        .then(view => settle(clusterMapHasScopeGroups(view) ? "scoped" : "flat"))
        .catch(() => settle("failed"));
    } catch {
      settle("failed");
    }
    return () => { cancelled = true; };
  }, [enabled, scanId]);

  if (!enabled || !scanId) return "idle";
  return result?.scanId === scanId ? result.status : "pending";
}
