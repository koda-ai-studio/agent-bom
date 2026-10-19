import type { Edge } from "@xyflow/react";
import type { CSSProperties } from "react";

import { readableGraphNodeStyle } from "@/lib/graph-node-dimensions";

/** Bounds for the selected-path canvas: short paths get a short canvas. */
export const PATH_CARD_CANVAS_MIN_PX = 288;
export const PATH_CARD_CANVAS_MAX_PX = 544;
const TOOLBAR_PX = 48;
const ROW_PX = 168;
const FRAME_PX = 96;
const ROW_TOLERANCE = 40;

/** Height that fits the laid-out rows of a focused path plus its toolbar. */
export function pathCardCanvasHeight(nodes: ReadonlyArray<{ position: { y: number } }>): number {
  if (nodes.length === 0) return PATH_CARD_CANVAS_MIN_PX;
  const rows = new Set(nodes.map(node => Math.round(node.position.y / ROW_TOLERANCE))).size;
  const height = TOOLBAR_PX + FRAME_PX + rows * ROW_PX;
  return Math.min(PATH_CARD_CANVAS_MAX_PX, Math.max(PATH_CARD_CANVAS_MIN_PX, height));
}

/**
 * One-line chips and strokes of a constant on-screen weight. Flow-unit strokes
 * thin out as a short path is fitted wide, turning tier dashes into faint dots.
 */
export function pathCardEdges(edges: Edge[], zoom: number): Edge[] {
  const scale = 1 / Math.max(Number.isFinite(zoom) ? zoom : 1, 0.16);
  return edges.map(edge => {
    const dashed = Boolean(edge.style?.strokeDasharray);
    return {
      ...edge,
      data: { ...edge.data, compactEvidence: true },
      style: {
        ...edge.style,
        strokeWidth: 2 * scale,
        strokeDasharray: dashed ? `${6 * scale} ${4 * scale}` : undefined,
        opacity: Math.max(Number(edge.style?.opacity ?? 1), 0.9),
      },
    };
  });
}

/** Path nodes get room for a package name and version on one line. */
export function pathCardNodeStyle(zoom: number): CSSProperties {
  return { ...readableGraphNodeStyle(zoom), "--graph-node-card-width": "300px" } as CSSProperties;
}

/**
 * The header already states severity and the ring marks it on the node, so the
 * finding's severity chip is redundant here; a package's hover-only vulnerability
 * count renders as an unexplained dot at this zoom (the ring tooltip names it).
 */
export const PATH_CARD_CANVAS_CLASS =
  "[&_.graph-finding-metadata>span.uppercase]:hidden [&_.react-flow__node-packageNode_.graph-node-context]:hidden";
