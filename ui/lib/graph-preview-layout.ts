/** The widest caption a roomy card draws, in layout units. Columns are spaced wider than this. */
export const PREVIEW_CARD_MAX_WIDTH = 300;

/** A preview shows few cards, so it gives them room: one column per hop from the start node. */
export const PREVIEW_LAYOUT = { columnGap: PREVIEW_CARD_MAX_WIDTH + 60, rowGap: 380 } as const;
