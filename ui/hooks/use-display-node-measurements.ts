"use client";
import { useCallback, useMemo, useState } from "react";
import type { Node, NodeChange } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";

/** Keep measurements for display-only nodes out of persisted asset layouts. */
export function useDisplayNodeMeasurements(nodes: Node<LineageNodeData>[], onNodesChange: (changes: NodeChange<Node<LineageNodeData>>[]) => void) {
  const [measurements, setMeasurements] = useState<Record<string, { width: number; height: number }>>({});
  const displayIds = useMemo(() => new Set(nodes.filter(n => n.data.displayOnly).map(n => n.id)), [nodes]);
  const change = useCallback((changes: NodeChange<Node<LineageNodeData>>[]) => {
    const canonical = changes.filter(c => "id" in c && !displayIds.has(c.id));
    if (canonical.length) onNodesChange(canonical);
    const dimensions = changes.filter(c => c.type === "dimensions" && displayIds.has(c.id));
    if (dimensions.length) setMeasurements(previous => {
      let next = previous;
      for (const c of dimensions) if (c.type === "dimensions" && c.dimensions
        && (previous[c.id]?.width !== c.dimensions.width || previous[c.id]?.height !== c.dimensions.height)) {
        if (next === previous) next = Object.fromEntries(Object.entries(previous).filter(([id]) => displayIds.has(id)));
        next[c.id] = c.dimensions;
      }
      return next;
    });
  }, [displayIds, onNodesChange]);
  return { nodes: useMemo(() => nodes.map(n => n.data.displayOnly && measurements[n.id]
    ? { ...n, measured: measurements[n.id]! } : n), [nodes, measurements]), onNodesChange: change };
}
