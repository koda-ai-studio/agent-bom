/** Shared layout footprint for circular entity glyphs and readable labels. */

import { PREVIEW_CARD_MAX_WIDTH } from "@/lib/graph-preview-layout";
import type { DagreLrOptions } from "@/lib/use-dagre-lr";
import type { MinSeparationOptions } from "@/lib/dagre-layout";
import type { CSSProperties } from "react";

/** On-screen card sizes. Each token is divided by zoom, so cards read the same at any fit. */
const DRAWN = { glyph: 52, icon: 28, label: 14, meta: 12 } as const;
/**
 * A graph this small has room for a glyph at the readability floor (66px on screen, icon 32px);
 * larger graphs draw the compact 52px glyph so many nodes fit. Both stay far below the
 * 115px circles a nine-node graph used to draw.
 */
export const SMALL_GRAPH_NODES = 12;
const SMALL_DRAWN = { glyph: 66, icon: 32 } as const;
/** Layout-unit ceilings; past these a fully fitted overview keeps its cards inside their layout boxes. */
const CEILING = { glyph: 128, icon: 56, label: 30, roomyLabel: 36, meta: 30, roomyMeta: 32 } as const;

/** Bounded investigations reserve more metadata space when Fit all lowers zoom. */
export function readableGraphNodeStyle(zoom: number, boundedContext = false, roomyCaptions = boundedContext, nodeCount = Number.POSITIVE_INFINITY): CSSProperties {
  const scale = Math.max(Number.isFinite(zoom) ? zoom : 1, 0.16);
  const units = (drawn: number, ceiling: number) => `${Math.min(ceiling, drawn / scale)}px`;
  const shape = nodeCount <= SMALL_GRAPH_NODES ? SMALL_DRAWN : DRAWN;
  return {
    "--graph-node-card-width": roomyCaptions ? `clamp(220px, 30vw, ${PREVIEW_CARD_MAX_WIDTH}px)` : "220px",
    "--graph-node-label-size": units(DRAWN.label, roomyCaptions ? CEILING.roomyLabel : CEILING.label),
    "--graph-node-glyph-size": units(shape.glyph, CEILING.glyph),
    "--graph-node-icon-size": units(shape.icon, CEILING.icon),
    "--graph-node-meta-size": units(DRAWN.meta, roomyCaptions ? CEILING.roomyMeta : CEILING.meta),
    "--graph-group-label-size": `${Math.min(75, Math.max(18, 12 / scale))}px`,
  } as CSSProperties;
}

/** The glyph a flow draws when finding groups are disclosed, on the same on-screen scale as every card. */
export function disclosedGlyphSize(zoom: number, nodeCount = Number.POSITIVE_INFINITY): string {
  return `${Math.min(156, (nodeCount <= SMALL_GRAPH_NODES ? SMALL_DRAWN : DRAWN).glyph / Math.max(zoom, 0.1))}px`;
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
  // Agent kind can wrap on phones; the host row remains visible at overview zoom.
  const height = boundedCaptions ? 360 : LINEAGE_NODE_HEIGHT;
  return readableLineageDagreLr({
    nodeWidth: width,
    nodeHeight: height,
    rankSep: 128,
    nodeSep: 32,
    minSeparation: { width, height, gap: 24 },
  });
}
