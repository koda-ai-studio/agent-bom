"use client";

import { useCallback, useMemo, useState } from "react";
import type { Node, NodeChange } from "@xyflow/react";

/** Keep controlled nodes measured across telemetry updates with unchanged DOM sizes. */
export function usePipelineNodeMeasurements(nodes: Node[], compact: boolean) {
  const [sizes, setSizes] = useState(new Map<string, { width: number; height: number }>());
  const onNodesChange = useCallback((changes: NodeChange[]) => {
    setSizes(previous => {
      let next = previous;
      for (const change of changes) {
        if (change.type !== "dimensions" || !change.dimensions) continue;
        const { width, height } = change.dimensions;
        if (!(width > 0 && height > 0) || !nodes.some(node => node.id === change.id)) continue;
        const key = `${compact}:${change.id}`;
        const existing = previous.get(key);
        if (existing?.width === width && existing.height === height) continue;
        if (next === previous) next = new Map(previous);
        next.set(key, { width, height });
      }
      return next;
    });
  }, [compact, nodes]);
  const measuredNodes = useMemo(() => nodes.map(node => {
    const measured = sizes.get(`${compact}:${node.id}`);
    return measured ? { ...node, measured } : node;
  }), [nodes, sizes, compact]);
  return { measuredNodes, onNodesChange };
}
