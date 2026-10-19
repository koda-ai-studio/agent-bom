"use client";

import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import type { GraphEstateChangesResponse } from "@/lib/api-types";
import { estateChangesHeadline } from "@/lib/graph-estate-changes";

export interface GraphEstateChangesState {
  estateChanges: GraphEstateChangesResponse | null;
  headline: string | null;
  loading: boolean;
  error: string | null;
}

/**
 * The current estate's "what changed?" read: every source against its own
 * previous scan. It waits for the canvas (`ready`) so it never competes with
 * the first frame, and is inert for historical snapshots.
 */
export function useGraphEstateChanges({ scanId, enabled, ready }: { scanId: string; enabled: boolean; ready: boolean }): GraphEstateChangesState {
  const [estateChanges, setEstateChanges] = useState<GraphEstateChangesResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setEstateChanges(null);
    setError(null);
    if (!enabled || !ready || !scanId) {
      setLoading(false);
      return;
    }
    const controller = new AbortController();
    setLoading(true);
    api
      .getGraphEstateChanges({ signal: controller.signal })
      .then(setEstateChanges)
      .catch((cause: unknown) => {
        if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Changes could not be loaded.");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [enabled, ready, scanId]);

  return { estateChanges, headline: estateChangesHeadline(estateChanges), loading, error };
}
