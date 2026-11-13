const FINDING_TYPES = new Set(["vulnerability", "misconfiguration", "finding"]);
/** Three lines of a card caption at the on-screen label size. */
const MAX_CAPTION = 60;
const PATH_SUFFIX = /^(.{8,}?):\s+\S.*\s(?:→|->)\s/;

/**
 * A short name for a finding card. A path finding's title restates the chain the canvas already
 * draws, so its rule names it; any other long title ends on a word boundary. The full title stays
 * in the card's tooltip and accessible name.
 */
export function canvasCaption(title: string, nodeType: string | undefined): { text: string; shortened: boolean } {
  const whole = title.trim();
  if (!FINDING_TYPES.has(nodeType ?? "")) return { text: whole, shortened: false };
  const rule = PATH_SUFFIX.exec(whole)?.[1]?.trim();
  const text = rule ?? whole;
  if (text.length <= MAX_CAPTION) return { text, shortened: text !== whole };
  const space = text.lastIndexOf(" ", MAX_CAPTION - 1);
  return { text: `${text.slice(0, space > 0 ? space : MAX_CAPTION - 1)}…`, shortened: true };
}
