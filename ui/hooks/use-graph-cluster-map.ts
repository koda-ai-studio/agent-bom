"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { api } from "@/lib/api";
import {
  CLUSTER_MAP_MEMBER_LIMIT,
  INITIAL_CLUSTER_MAP_STATE,
  clusterMapParams,
  pageCluster,
  toggleClusterExpanded,
  type ClusterMapResponse,
  type ClusterMapState,
} from "@/lib/graph-cluster-map";

export type ClusterMapStatus = "loading" | "ready" | "failed";

/** One bounded read per frame; a newer request always wins over a slower older one. */
export function useGraphClusterMap(scanId: string | undefined, enabled: boolean, memberLimit = CLUSTER_MAP_MEMBER_LIMIT) {
  const [state, setState] = useState<ClusterMapState>(INITIAL_CLUSTER_MAP_STATE);
  const [view, setView] = useState<ClusterMapResponse | null>(null);
  const [status, setStatus] = useState<ClusterMapStatus>("loading");
  const request = useRef(0);

  useEffect(() => { setState(INITIAL_CLUSTER_MAP_STATE); setView(null); }, [scanId]);

  useEffect(() => {
    if (!enabled) return;
    const id = ++request.current;
    setStatus("loading");
    let pending: Promise<ClusterMapResponse>;
    try {
      pending = api.getGraphClusterMap(clusterMapParams(scanId, state, memberLimit));
    } catch {
      setStatus("failed");
      return;
    }
    pending.then(result => {
      if (id !== request.current) return;
      setView(result);
      setStatus("ready");
    }).catch(() => { if (id === request.current) setStatus("failed"); });
  }, [enabled, scanId, state, memberLimit]);

  const focusClusterId = view?.focus?.cluster_id ?? null;
  const toggle = useCallback((id: string) => setState(current => toggleClusterExpanded(current, id, focusClusterId)), [focusClusterId]);
  const page = useCallback((id: string, offset: number) => setState(current => pageCluster(current, id, offset)), []);
  const setRiskyOnly = useCallback((riskyOnly: boolean) => setState(current => ({ ...current, riskyOnly })), []);
  const focus = useCallback((nodeId: string | null) => setState(current => ({ ...current, focus: nodeId })), []);
  const reset = useCallback(() => setState(INITIAL_CLUSTER_MAP_STATE), []);

  return { state, view, status, toggle, page, setRiskyOnly, focus, reset };
}
