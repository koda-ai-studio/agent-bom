"use client";

import { BaseEdge, EdgeLabelRenderer, type Edge, type EdgeProps } from "@xyflow/react";

import type { DisplayBundle } from "@/lib/graph-cluster-layout";
import { labelWidth, roundedPath, type BundleRoute } from "@/lib/graph-cluster-routes";

export type BundleEdgeData = { route: BundleRoute; text: string; title: string; bundle: DisplayBundle; hovered?: boolean };
export type BundleEdge = Edge<BundleEdgeData, "bundle">;

/**
 * A bundled relationship drawn on its routed lane. Labels sit in the label
 * layer above every line. A label that found a clear place is always shown;
 * any other (including single relationships) appears only while the bundle is
 * hovered or selected, and its counts are always in the bundle panel.
 */
export function ClusterBundleEdge({ id, data, selected, markerEnd, markerStart, style, interactionWidth }: EdgeProps<BundleEdge>) {
  if (!data) return null;
  const { route, text, title, hovered } = data;
  const points = route.points;
  const middle = points[Math.floor(points.length / 2)] ?? points[0]!;
  const width = labelWidth(text);
  const box = route.label ?? { x: middle.x - width / 2, y: middle.y - 9, width, height: 18, placed: false };
  const shown = box.placed || hovered || selected;
  return <>
    <BaseEdge id={id} path={roundedPath(points)} interactionWidth={interactionWidth ?? 14}
      {...(markerEnd ? { markerEnd } : {})} {...(markerStart ? { markerStart } : {})} {...(style ? { style } : {})} />
    {shown && <EdgeLabelRenderer>
      <div className="cluster-edge-label" data-placed={box.placed} title={title}
        style={{ transform: `translate(${box.x}px, ${box.y}px)`, width: box.width, height: box.height }}>{text}</div>
    </EdgeLabelRenderer>}
  </>;
}

export const clusterEdgeTypes = { bundle: ClusterBundleEdge };
