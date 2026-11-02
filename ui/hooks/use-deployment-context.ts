"use client";

import { useEffect, useState } from "react";

import { api, type PostureCountsResponse } from "@/lib/api";

export interface DeploymentContextState {
  counts: PostureCountsResponse | null;
  loading: boolean;
  error: string | null;
}

/** ``enabled: false`` skips the read for a caller that already has the shell's shared counts. */
export function useDeploymentContext({ enabled = true }: { enabled?: boolean } = {}): DeploymentContextState {
  const [counts, setCounts] = useState<PostureCountsResponse | null>(null);
  const [loading, setLoading] = useState(enabled);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!enabled) return;
    let mounted = true;

    const load = () => {
      api
        .getPostureCounts()
        .then((nextCounts) => {
          if (!mounted) return;
          setCounts(nextCounts);
          setError(null);
          setLoading(false);
        })
        .catch((nextError: Error) => {
          if (!mounted) return;
          setError(nextError.message);
          setLoading(false);
        });
    };

    load();
    const interval = window.setInterval(load, 60_000);
    return () => {
      mounted = false;
      window.clearInterval(interval);
    };
  }, [enabled]);

  return { counts, loading, error };
}
