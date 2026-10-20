const TAIL = 9;

/**
 * A snapshot id short enough for a chip or option. Short names stay whole;
 * a long id keeps its leading words and its distinguishing tail, because two
 * snapshots of one source usually share a prefix. Pair with `title={id}`.
 */
export function snapshotLabel(id: string, max = 28): string {
  if (id.length <= max) return id;
  return `${id.slice(0, max - TAIL - 1)}…${id.slice(-TAIL)}`;
}
