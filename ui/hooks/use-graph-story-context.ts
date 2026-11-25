"use client";
import { useMemo, useState } from "react";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { semanticGraphLayout } from "@/lib/graph-semantic-layout";
import { storyContext } from "@/lib/graph-story-context";

export function useGraphStoryContext(nodes: Node<LineageNodeData>[], edges: Edge[], enabled: boolean, scope: string, selectedId: string | null, selectedEdge: string | null, clearSelection: () => void) {
  const [expandedScope, setExpandedScope] = useState<string | null>(null);
  const folded = useMemo(() => enabled ? storyContext(nodes, edges, false) : { nodes, edges, contextIds: new Set<string>() }, [nodes, edges, enabled]);
  const selection = edges.find(edge => edge.id === selectedEdge);
  const selectedContext = [selectedId, selection?.source, selection?.target].some(id => id && folded.contextIds.has(id));
  const expanded = expandedScope === scope || selectedContext;
  const visible = useMemo(() => enabled && expanded ? storyContext(nodes, edges, true) : folded, [nodes, edges, enabled, expanded, folded]);
  const layout = useMemo(() => visible.contextIds.size ? semanticGraphLayout(visible.nodes, visible.edges) : visible, [visible]);
  return { ...visible, ...layout, expanded, available: folded.contextIds.size > 0,
    toggle: () => { if (expanded) clearSelection(); setExpandedScope(expanded ? null : scope); },
    expand: () => setExpandedScope(scope), key: `${scope}:${expanded}` };
}
