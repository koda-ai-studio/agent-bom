"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { api } from "@/lib/api";
import { loadArchitecturePage, type ArchitecturePagesState } from "@/lib/agent-architecture-pages";

export const ARCHITECTURE_PAGE_SIZE = 20;

/** Harness pages for the caller's tenant; the first page loads on mount, the rest on request. */
export function useAgentArchitecture(scanId: string | undefined) {
  const [state, setState] = useState<ArchitecturePagesState | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const generation = useRef(0);
  const fetchPage = useCallback((cursor: string | undefined, options: { fresh: boolean }) =>
    api.getAgentArchitecture({ scanId, cursor, limit: ARCHITECTURE_PAGE_SIZE, fresh: options.fresh }), [scanId]);

  const restart = useCallback(() => {
    const ticket = ++generation.current;
    setState(null);
    void loadArchitecturePage(fetchPage, null, { fresh: true }).then(next => { if (generation.current === ticket) setState(next); });
  }, [fetchPage]);

  useEffect(() => {
    const ticket = ++generation.current;
    void loadArchitecturePage(fetchPage, null).then(next => { if (generation.current === ticket) setState(next); });
    return () => { generation.current += 1; };
  }, [fetchPage]);

  const loadMore = useCallback(() => {
    if (!state || loadingMore) return;
    const ticket = generation.current;
    setLoadingMore(true);
    void loadArchitecturePage(fetchPage, state).then(next => {
      if (generation.current === ticket) setState(next);
      setLoadingMore(false);
    });
  }, [fetchPage, loadingMore, state]);

  return { state, loadingMore, loadMore, restart };
}
