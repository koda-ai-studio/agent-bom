"use client";
import { useMemo, useState } from "react";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { semanticGraphLayout } from "@/lib/graph-semantic-layout";
import { storyContext } from "@/lib/graph-story-context";
import { scopeStories, selectScopeStory } from "@/lib/graph-scope-stories";

export function useGraphStoryContext(nodes: Node<LineageNodeData>[], edges: Edge[], enabled: boolean, scope: string, selectedId: string | null, selectedEdge: string | null, clearSelection: () => void) {
  const [expandedScope, setExpandedScope] = useState<string | null>(null);
  const [chosen, setChosen] = useState<{ scope: string; id: string } | null>(null);
  const stories = useMemo(() => enabled ? scopeStories(nodes, edges) : null, [nodes, edges, enabled]);
  const selection = edges.find(edge => edge.id === selectedEdge);
  const selectedStory = stories?.stories.find(story => [selectedId, selection?.source, selection?.target].some(id => id && story.nodeIds.has(id)));
  const storyId = selectedStory?.id ?? (chosen?.scope === scope ? chosen.id : stories?.stories[0]?.id ?? "");
  const projected = useMemo(() => stories && storyId ? selectScopeStory(nodes, edges, stories, storyId) : { nodes, edges }, [nodes, edges, stories, storyId]);
  const folded = useMemo(() => enabled ? storyContext(projected.nodes, projected.edges, false) : { ...projected, contextIds: new Set<string>() }, [projected, enabled]);
  const selectedContext = [selectedId, selection?.source, selection?.target].some(id => id && folded.contextIds.has(id));
  const expanded = expandedScope === `${scope}:${storyId}` || selectedContext;
  const visible = useMemo(() => enabled && expanded ? storyContext(projected.nodes, projected.edges, true) : folded, [projected, enabled, expanded, folded]);
  const layout = useMemo(() => visible.contextIds.size || stories && storyId ? semanticGraphLayout(visible.nodes, visible.edges) : visible, [visible, stories, storyId]);
  return { ...visible, ...layout, expanded, available: folded.contextIds.size > 0,
    stories: stories ? { value: storyId, options: stories.stories.map(story => ({ id: story.id, label: story.label })),
      onChange: (id: string) => { clearSelection(); setExpandedScope(id ? null : `${scope}:`); setChosen({ scope, id }); } } : undefined,
    focused: Boolean(stories && storyId),
    focusedCounts: stories && storyId ? { nodes: projected.nodes.filter(n => !n.hidden && !n.data.displayOnly).length, edges: projected.edges.filter(e => !e.hidden && !e.data?.displayOnly).length } : undefined,
    toggle: () => { if (expanded) clearSelection(); setExpandedScope(expanded ? null : `${scope}:${storyId}`); },
    expand: () => { clearSelection(); setChosen({ scope, id: "" }); setExpandedScope(`${scope}:`); }, key: `${scope}:${storyId}:${expanded}` };
}
