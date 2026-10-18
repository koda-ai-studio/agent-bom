"use client";

import { useMemo } from "react";
import { type Edge, type Node } from "@xyflow/react";

import { graphHierarchyLayout } from "@/lib/graph-hierarchy-layout";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { GraphLayout } from "@/lib/graph-schema";
import { type LayoutOptions } from "@/lib/dagre-layout";
import { type DagreLrOptions, useDagreLrLayout } from "@/lib/use-dagre-lr";
import { type ForceLayoutOptions, useForceLayout } from "@/lib/use-force-layout";
import { type RadialLayoutOptions, useRadialLayout } from "@/lib/use-radial-layout";
import { type SankeyLayoutOptions, useSankeyLayout } from "@/lib/use-sankey-layout";
import { useDagreLayout } from "@/lib/use-dagre-layout";

const EMPTY_NODES: Node[] = [];
const EMPTY_EDGES: Edge[] = [];

export type GraphLayoutKind =
  | GraphLayout
  | "asset-hierarchy"
  | "force"
  | "radial"
  | "dagre"
  | "sankey"
  | "dagre-lr"
  | "dagre_lr"
  | "lr"
  | "topology"
  | "spawn-tree"
  | "spawn_tree";

export type ResolvedGraphLayoutKind =
  | "asset-hierarchy"
  | "force"
  | "radial"
  | "dagre"
  | "dagre-lr"
  | "sankey";

export interface GraphLayoutOptions {
  force?: ForceLayoutOptions;
  radial?: RadialLayoutOptions;
  dagre?: LayoutOptions;
  dagreLr?: DagreLrOptions;
  sankey?: SankeyLayoutOptions;
}

export interface GraphLayoutState {
  nodes: Node[];
  edges: Edge[];
  pending: boolean;
  seed?: number;
  kind: ResolvedGraphLayoutKind;
}

export function resolveGraphLayoutKind(kind: GraphLayoutKind): ResolvedGraphLayoutKind {
  switch (kind) {
    case "asset-hierarchy":
      return "asset-hierarchy";
    case GraphLayout.FORCE:
    case "force":
      return "force";
    case GraphLayout.RADIAL:
    case "radial":
      return "radial";
    case GraphLayout.SANKEY:
    case "sankey":
      return "sankey";
    case GraphLayout.DAGRE:
    case "dagre":
    case GraphLayout.HIERARCHICAL:
    case GraphLayout.GRID:
    case "topology":
    case "spawn-tree":
    case "spawn_tree":
      return "dagre";
    case "dagre-lr":
    case "dagre_lr":
    case "lr":
      return "dagre-lr";
  }
}

export function useGraphLayout(
  kind: GraphLayoutKind,
  nodes: Node[],
  edges: Edge[],
  options: GraphLayoutOptions = {},
  enabled = true,
): GraphLayoutState {
  const resolvedKind = resolveGraphLayoutKind(kind);
  // Summary lists and WebGL own their presentation. Keep the hook order stable
  // without computing an unused layout or transferring the graph to a worker.
  const inputNodes = enabled ? nodes : EMPTY_NODES;
  const inputEdges = enabled ? edges : EMPTY_EDGES;
  const dagreOptions = useMemo<LayoutOptions>(() => {
    const requested = options.dagre ?? {};
    if (requested.direction !== undefined) return requested;
    if (kind === "spawn-tree" || kind === "spawn_tree") {
      return { ...requested, direction: "TB" };
    }
    if (kind === "topology") {
      return { ...requested, direction: "LR" };
    }
    return requested;
  }, [kind, options.dagre]);
  const force = useForceLayout(
    resolvedKind === "force" ? inputNodes : EMPTY_NODES,
    resolvedKind === "force" ? inputEdges : EMPTY_EDGES,
    options.force,
  );
  const radial = useRadialLayout(
    resolvedKind === "radial" ? inputNodes : EMPTY_NODES,
    resolvedKind === "radial" ? inputEdges : EMPTY_EDGES,
    options.radial,
  );
  const dagre = useDagreLayout(
    resolvedKind === "dagre" ? inputNodes : EMPTY_NODES,
    resolvedKind === "dagre" ? inputEdges : EMPTY_EDGES,
    dagreOptions,
  );
  const dagreLr = useDagreLrLayout(
    resolvedKind === "dagre-lr" ? inputNodes : EMPTY_NODES,
    resolvedKind === "dagre-lr" ? inputEdges : EMPTY_EDGES,
    options.dagreLr,
  );
  const sankey = useSankeyLayout(
    resolvedKind === "sankey" ? inputNodes : EMPTY_NODES,
    resolvedKind === "sankey" ? inputEdges : EMPTY_EDGES,
    options.sankey,
  );

  const hierarchyOptionsKey = JSON.stringify(options.dagreLr ?? {});
  const hierarchy = useMemo(
    () => enabled && resolvedKind === "asset-hierarchy"
      ? graphHierarchyLayout(nodes as Node<LineageNodeData>[], edges, JSON.parse(hierarchyOptionsKey) as LayoutOptions)
      : undefined,
    [enabled, resolvedKind, nodes, edges, hierarchyOptionsKey],
  );

  return useMemo(() => {
    if (!enabled) return { nodes, edges, pending: false, kind: resolvedKind };
    switch (resolvedKind) {
      case "asset-hierarchy":
        return { ...hierarchy!, pending: false, kind: resolvedKind };
      case "force":
        return { ...force, kind: resolvedKind };
      case "radial":
        return { ...radial, kind: resolvedKind };
      case "dagre":
        return { ...dagre, kind: resolvedKind };
      case "dagre-lr":
        return { ...dagreLr, kind: resolvedKind };
      case "sankey":
        return { ...sankey, kind: resolvedKind };
    }
  }, [dagre, dagreLr, force, radial, resolvedKind, sankey, enabled, nodes, edges, hierarchy]);
}
