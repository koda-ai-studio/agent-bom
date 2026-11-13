import type { WrapOptions } from "@/lib/graph-wrapped-ranks";

/** The widest caption a roomy card draws, in layout units. Columns are spaced wider than this. */
export const PREVIEW_CARD_MAX_WIDTH = 300;

/** A preview shows few cards, so it can give them room; the columns wrap to two rows. */
export const PREVIEW_LAYOUT: WrapOptions = { maxRows: 2, columnGap: PREVIEW_CARD_MAX_WIDTH + 60, rowGap: 380, respace: true };
