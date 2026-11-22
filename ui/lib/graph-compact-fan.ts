type Point = { x: number; y: number };
type FanLink = { id: string; source: string; target: string; hidden?: boolean | undefined };

/** Layout units between neighbouring link ends on one side of a glyph, and the most a side's ends may spread. */
const FAN_STEP = 7, FAN_SPAN = 24;

/** The side of each end's card a link attaches to, as the compact canvas draws it: a forward link leaves the right and
 * enters the left; a back link uses the context handles (leaves the left, enters the right); a same-rank link
 * leaves and enters on the right. */
function sides(from: Point, to: Point): { source: "left" | "right"; target: "left" | "right" } {
  if (from.x < to.x) return { source: "right", target: "left" };
  if (from.x > to.x) return { source: "left", target: "right" };
  return { source: "right", target: "right" };
}

/** Where several links meet one side of a glyph, their ends spread a few units along the rim, ordered by the row of
 * the card at the far end. Two relationships then never share the last stretch into or out of a card (a back link
 * entering where a forward link leaves included), and each arrowhead stays distinct. */
export function linkEndFans(links: readonly FanLink[], positions: ReadonlyMap<string, Point>): Map<string, { sourceFan?: number; targetFan?: number }> {
  const drawn = links.filter(link => !link.hidden && link.source !== link.target && positions.has(link.source) && positions.has(link.target));
  const groups = new Map<string, { link: FanLink; end: "source" | "target" }[]>();
  for (const link of drawn) {
    const side = sides(positions.get(link.source)!, positions.get(link.target)!);
    for (const end of ["source", "target"] as const) {
      const key = `${link[end]}\u0000${side[end]}`;
      groups.set(key, [...(groups.get(key) ?? []), { link, end }]);
    }
  }
  const out = new Map<string, { sourceFan?: number; targetFan?: number }>();
  for (const group of groups.values()) {
    if (group.length < 2) continue;
    const step = Math.min(FAN_STEP, FAN_SPAN / (group.length - 1));
    const far = ({ link, end }: { link: FanLink; end: "source" | "target" }) => positions.get(end === "source" ? link.target : link.source)!;
    group.sort((a, b) => far(a).y - far(b).y || far(a).x - far(b).x || a.link.id.localeCompare(b.link.id) || a.end.localeCompare(b.end))
      .forEach((item, index) => out.set(item.link.id, { ...out.get(item.link.id), [`${item.end}Fan`]: (index - (group.length - 1) / 2) * step }));
  }
  return out;
}
