type Point = { x: number; y: number };
type Link = { source: string; target: string };

/** Coordinated rank sweeps keep branches with a shared destination together.
 * Local swaps alone cannot move a directory and its file past another chain.
 * Only row slots change; recorded links and the pinned path stay untouched. */
export function orderedRankStarts(positions: ReadonlyMap<string, Point>, links: readonly Link[], fixed: ReadonlySet<string>) {
  const map = new Map(positions);
  const ranks = new Map<number, string[]>();
  for (const [id, point] of map) ranks.set(point.x, [...(ranks.get(point.x) ?? []), id]);
  const starts: Map<string, Point>[] = [];
  for (const reverse of [true, false, true, false]) {
    for (const x of [...ranks.keys()].sort((a, b) => reverse ? b - a : a - b)) {
      const ids = ranks.get(x)!.filter(id => !fixed.has(id));
      const slots = ids.map(id => map.get(id)!.y).sort((a, b) => a - b);
      const center = (id: string) => {
        const neighbors = links.flatMap(link => {
          const other = link.source === id ? link.target : link.target === id ? link.source : null;
          const at = other ? map.get(other) : undefined;
          return at && (reverse ? at.x > x : at.x < x) ? [at.y] : [];
        });
        return neighbors.length ? neighbors.reduce((a, b) => a + b, 0) / neighbors.length : map.get(id)!.y;
      };
      ids.sort((a, b) => center(a) - center(b) || map.get(a)!.y - map.get(b)!.y || a.localeCompare(b));
      ids.forEach((id, index) => map.set(id, { x, y: slots[index]! }));
    }
    starts.push(new Map(map));
  }
  return starts;
}
