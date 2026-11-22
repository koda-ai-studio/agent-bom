"use client";
import { useCallback, useMemo, useState } from "react";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { cloudFindingDisclosure } from "@/lib/graph-finding-disclosure";

export function useCloudFindingDisclosure(nodes: Node<LineageNodeData>[], edges: Edge[], selectedId: string | null, scope: string, preservePositions = false) {
  const [state, setState] = useState<{ scope: string; ids: Set<string> }>({ scope, ids: new Set() });
  const toggle = useCallback((id: string) => setState(previous => {
    const ids = new Set(previous.scope === scope ? previous.ids : []);
    if (ids.has(id)) ids.delete(id); else ids.add(id);
    return { scope, ids };
  }), [scope]);
  return useMemo(() => {
    const expanded = new Set(state.scope === scope ? state.ids : []);
    const selectedOwner = nodes.find(n => n.id === selectedId)?.data.readingOwner;
    if (selectedOwner) expanded.add(selectedOwner);
    // The toolbar counts only findings the disclosure really folds: an owner without a backend aggregate has no group.
    const result = cloudFindingDisclosure(nodes, edges, expanded, toggle, preservePositions);
    const grouped = nodes.filter(n => result.groupedIds.has(n.id));
    const owners = [...new Set(grouped.flatMap(n => n.data.readingOwner ? [n.data.readingOwner] : []))];
    const collapsed = grouped.filter(n => !expanded.has(n.data.readingOwner!)).length;
    return { ...result, key: [...expanded].sort().join("|"), collapsed, available: owners.length > 0,
      reset: () => setState({ scope, ids: new Set() }),
      toggleAll: () => setState({ scope, ids: collapsed ? new Set(owners) : new Set() }) };

  }, [nodes, edges, state, scope, selectedId, toggle, preservePositions]);
}
