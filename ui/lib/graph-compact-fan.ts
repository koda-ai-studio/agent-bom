type Point = { x: number; y: number };
type FanLink = { id: string; source: string; target: string; hidden?: boolean | undefined };

/** Layout units between neighbouring link ends on one side of a glyph, and the most a side's ends may spread. */
const FAN_STEP = 7, FAN_SPAN = 24;

/** Where several forward links meet one side of a glyph, their ends spread a few units along the rim, ordered by
 * the row of the card at the far end. Two relationships then never share the last stretch into a card, and each
 * arrowhead stays distinct. Links drawn through side handles (back links, same-rank links) are left alone. */
export function linkEndFans(links: readonly FanLink[], positions: ReadonlyMap<string, Point>): Map<string, { sourceFan?: number; targetFan?: number }> {
  const forward = links.filter(link => !link.hidden && link.source !== link.target && positions.has(link.source) && positions.has(link.target)
    && positions.get(link.source)!.x < positions.get(link.target)!.x);
  const out = new Map<string, { sourceFan?: number; targetFan?: number }>();
  const spread = (end: "source" | "target") => {
    const far = end === "source" ? "target" : "source";
    const groups = new Map<string, FanLink[]>();
    for (const link of forward) groups.set(link[end], [...(groups.get(link[end]) ?? []), link]);
    for (const group of groups.values()) {
      if (group.length < 2) continue;
      const step = Math.min(FAN_STEP, FAN_SPAN / (group.length - 1));
      group.sort((a, b) => positions.get(a[far])!.y - positions.get(b[far])!.y || positions.get(a[far])!.x - positions.get(b[far])!.x || a.id.localeCompare(b.id))
        .forEach((link, index) => out.set(link.id, { ...out.get(link.id), [`${end}Fan`]: (index - (group.length - 1) / 2) * step }));
    }
  };
  spread("source");
  spread("target");
  return out;
}
