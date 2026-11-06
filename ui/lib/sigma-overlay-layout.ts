export interface OverlayBox { left: number; top: number; right: number; bottom: number }

const overlaps = (a: OverlayBox, b: OverlayBox) => a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top;

/** The first candidate clear of everything already placed and inside the stage; placing it reserves its box. */
export function placeOverlay(candidates: OverlayBox[], placed: OverlayBox[], stage: { width: number; height: number; top: number }) {
  const box = candidates.find(item => item.left >= 0 && item.right <= stage.width && item.top >= stage.top && item.bottom <= stage.height && !placed.some(other => overlaps(item, other)));
  if (box) placed.push(box);
  return box ?? null;
}
