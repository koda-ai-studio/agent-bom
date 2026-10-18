/** Shared layout footprint for circular entity glyphs and readable labels. */

import type { DagreLrOptions } from "@/lib/use-dagre-lr";
import type { MinSeparationOptions } from "@/lib/dagre-layout";
import type { CSSProperties } from "react";

/** Bounded investigations reserve more metadata space when Fit all lowers zoom. */
export function readableGraphNodeStyle(zoom: number, boundedContext = false, roomyCaptions = boundedContext): CSSProperties {
  const scale = Math.max(Number.isFinite(zoom) ? zoom : 1, 0.16);
  return {
    "--graph-node-card-width": roomyCaptions ? "clamp(220px, 30vw, 340px)" : "220px",
    "--graph-node-label-size": `${Math.min(roomyCaptions ? 36 : boundedContext ? 30 : 28, Math.max(18, 15 / scale))}px`,
    "--graph-node-glyph-size": `${Math.min(112, Math.max(72, 64 / scale))}px`,
    "--graph-node-icon-size": `${Math.min(48, Math.max(32, 28 / scale))}px`,
    "--graph-node-meta-size": `${Math.min(roomyCaptions ? 32 : boundedContext ? 28 : 24, Math.max(12, 12 / scale))}px`,
  } as CSSProperties;
}

/** Reserve label width as well as the circular glyph. */
export const LINEAGE_NODE_WIDTH = 240;
/** Reserve three label lines and evidence/finding metadata below the glyph. */
export const LINEAGE_NODE_HEIGHT = 224;
/** Minimum clear gap enforced between any two lineage cards, at any scale. */
export const GRAPH_NODE_MIN_GAP = 48;

/**
 * Width:height ratio of a graph canvas. Measured at ~1322 x 610 on `/graph` at
 * a 1440px viewport; the roll-up grid derives its column count from the same
 * assumption. Dagre knows nothing about the viewport, so without this a wide
 * fan-out becomes a portrait tower that `fitView` can only answer with an
 * unreadable zoom.
 */
export const LINEAGE_CANVAS_ASPECT = 2.2;

/** Collision footprint shared by the layout and the separation guarantee. */
export const LINEAGE_MIN_SEPARATION: MinSeparationOptions = {
  width: LINEAGE_NODE_WIDTH,
  height: LINEAGE_NODE_HEIGHT,
  gap: GRAPH_NODE_MIN_GAP,
};

/**
 * Canonical left-to-right dagre options for lineage graphs: a box that matches
 * the real card footprint, generous rank/node separation for breathing room,
 * and the min-separation guarantee wired in. Rank separation reads as the
 * blast-radius flow direction (agent → server → package → finding); node
 * separation keeps stacked siblings clearly apart.
 */
export const READABLE_LINEAGE_DAGRE_LR: DagreLrOptions = {
  nodeWidth: LINEAGE_NODE_WIDTH,
  nodeHeight: LINEAGE_NODE_HEIGHT,
  rankSep: 112,
  nodeSep: 56,
  minSeparation: LINEAGE_MIN_SEPARATION,
  fitAspect: LINEAGE_CANVAS_ASPECT,
};

/**
 * Merge caller overrides onto the readable defaults while always preserving the
 * separation guarantee. Callers can tighten/loosen rank + node separation (e.g.
 * a focused single-agent view) without ever reintroducing overlapping cards.
 */
export function readableLineageDagreLr(
  overrides: Partial<DagreLrOptions> = {},
): DagreLrOptions {
  return {
    ...READABLE_LINEAGE_DAGRE_LR,
    ...overrides,
    minSeparation: overrides.minSeparation ?? LINEAGE_MIN_SEPARATION,
    fitAspect: overrides.fitAspect ?? LINEAGE_CANVAS_ASPECT,
  };
}

export const COMPACT_GRAPH_MIN_ZOOM = 0.75;

/** A bounded selected context keeps full labels and card-sized layout boxes. */
export function compactInvestigationLayout(explicitContext: boolean, nodeCount: number, boundedCaptions = false): DagreLrOptions | undefined {
  if (!explicitContext || nodeCount < 1 || nodeCount > 16) return undefined;
  const width = boundedCaptions ? 360 : LINEAGE_NODE_WIDTH;
  const height = boundedCaptions ? 260 : LINEAGE_NODE_HEIGHT;
  return readableLineageDagreLr({
    nodeWidth: width,
    nodeHeight: height,
    rankSep: 128,
    nodeSep: 32,
    minSeparation: { width, height, gap: 24 },
  });
}
