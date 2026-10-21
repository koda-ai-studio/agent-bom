"use client";

import { useEffect, useState } from "react";

import type { ExposurePathView } from "@/components/overview/shared";
import { api } from "@/lib/api";
import type { OverviewTopRisk } from "@/lib/api-types";
import { queueTopRisks } from "@/lib/overview-queue-risks";

const QUEUE_PAGE = 50;

export interface QueueTopRisks {
  paths: ExposurePathView[];
  total: number;
}

/** The first page of the Investigation queue, folded into overview top risks; null until it loads or when unavailable. */
export function useQueueTopRisks(enabled: boolean, topRisks: OverviewTopRisk[] | null | undefined): QueueTopRisks | null {
  const [state, setState] = useState<QueueTopRisks | null>(null);
  useEffect(() => {
    if (!enabled) {
      setState(null);
      return;
    }
    const controller = new AbortController();
    void (async () => {
      try {
        const graph = await api.getGraphAttackPaths({ offset: 0, limit: QUEUE_PAGE }, { signal: controller.signal });
        const paths = queueTopRisks(graph, topRisks);
        if (!controller.signal.aborted) setState(paths.length ? { paths, total: graph.count_metadata?.open_paths ?? graph.pagination.total } : null);
      } catch {
        if (!controller.signal.aborted) setState(null);
      }
    })();
    return () => controller.abort();
  }, [enabled, topRisks]);
  return state;
}
