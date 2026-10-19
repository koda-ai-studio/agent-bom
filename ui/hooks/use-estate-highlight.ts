"use client";

import { useCallback, useEffect, useRef, useState, type Dispatch, type SetStateAction } from "react";

import { api } from "@/lib/api";
import type { GraphDiffResponse, GraphEstateChangesResponse } from "@/lib/api-types";
import { highlightPairs, mergeDriftDiffs, type SnapshotPair } from "@/lib/graph-estate-changes";

/**
 * Arms the drift lens for "what changed": the merged per-source diffs for the
 * current estate, or the existing snapshot pair for a historical view. A pair
 * opened from the changes panel is released when the selected scan changes.
 */
export function useEstateHighlight({
  scanId,
  currentEstate,
  estateChanges,
  setPair,
  setLensActive,
  setPanelOpen,
}: {
  scanId: string;
  currentEstate: boolean;
  estateChanges: GraphEstateChangesResponse | null;
  setPair: Dispatch<SetStateAction<SnapshotPair | null>>;
  setLensActive: (active: boolean) => void;
  setPanelOpen: (open: boolean) => void;
}) {
  const [diff, setDiff] = useState<GraphDiffResponse | null>(null);
  const [state, setState] = useState<{ loading: boolean; error: string | null }>({ loading: false, error: null });
  const panelPair = useRef<SnapshotPair | null>(null);

  useEffect(() => {
    setDiff(null);
    setPair(current => (current && current === panelPair.current ? null : current));
  }, [scanId, setPair]);

  const highlight = useCallback(async () => {
    if (!currentEstate || !estateChanges) {
      setLensActive(true);
      setPanelOpen(false);
      return;
    }
    setState({ loading: true, error: null });
    try {
      const diffs = await Promise.all(highlightPairs(estateChanges).map(pair => api.getGraphDiff(pair.oldScanId, pair.newScanId)));
      panelPair.current = null;
      setPair(null);
      setDiff(mergeDriftDiffs(diffs));
      setLensActive(true);
      setPanelOpen(false);
      setState({ loading: false, error: null });
    } catch (cause) {
      setState({ loading: false, error: cause instanceof Error ? cause.message : "Changes could not be highlighted." });
    }
  }, [currentEstate, estateChanges, setLensActive, setPanelOpen, setPair]);

  const openPair = useCallback((pair: SnapshotPair) => {
    panelPair.current = pair;
    setPair(pair);
  }, [setPair]);

  return { diff, clear: useCallback(() => setDiff(null), []), highlight, openPair, ...state };
}
