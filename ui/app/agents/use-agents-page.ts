"use client";

import { useEffect, useState } from "react";

import { api, type AgentsResponse } from "@/lib/api";
import type { AgentListParams } from "@/lib/api-inventory";

/** One server page of agents; the previous page stays on screen while the next loads. */
export function useAgentsPage(params: AgentListParams) {
  const [data, setData] = useState<AgentsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    api
      .listAgents(params, controller.signal)
      .then((response) => {
        if (controller.signal.aborted) return;
        setData(response);
        setError("");
      })
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setError(err instanceof Error ? err.message : "Failed to load agents");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [params]);

  return { data, loading, error };
}
