"use client";

import { BaseEdge, type Edge, type EdgeProps } from "@xyflow/react";

import type { DisplayBundle } from "@/lib/graph-cluster-layout";
import { labelWidth, roundedPath, type BundleRoute } from "@/lib/graph-cluster-routes";

export type BundleEdgeData = { route: BundleRoute; text: string; title: string; bundle: DisplayBundle };
export type BundleEdge = Edge<BundleEdgeData, "bundle">;

/**
 * A bundled relationship drawn on its routed lane. A label that found a clear
 * place is always shown; any other (including single relationships) appears
 * only while the bundle is hovered, focused or selected.
 */
export function ClusterBundleEdge({ id, data, markerEnd, markerStart, style, interactionWidth }: EdgeProps<BundleEdge>) {
  if (!data) return null;
  const { route, text, title } = data;
  const points = route.points;
  const middle = points[Math.floor(points.length / 2)] ?? points[0]!;
  const width = labelWidth(text);
  const box = route.label ?? { x: middle.x - width / 2, y: middle.y - 8, width, height: 16, placed: false };
  return <>
    <BaseEdge id={id} path={roundedPath(points)} interactionWidth={interactionWidth ?? 14}
      {...(markerEnd ? { markerEnd } : {})} {...(markerStart ? { markerStart } : {})} {...(style ? { style } : {})} />
    <g className="cluster-edge-label" data-placed={Boolean(route.label?.placed)} aria-hidden="true">
      <title>{title}</title>
      <rect x={box.x} y={box.y} width={box.width} height={box.height} rx={4} />
      <text x={box.x + box.width / 2} y={box.y + box.height / 2} dominantBaseline="central" textAnchor="middle">{text}</text>
    </g>
  </>;
}

export const clusterEdgeTypes = { bundle: ClusterBundleEdge };
