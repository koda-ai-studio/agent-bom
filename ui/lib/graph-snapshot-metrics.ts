export type GraphAttackPathCounts = { retained_count: number; assessed_count: number; basis: string };

export function readAttackPathCounts(value: unknown): GraphAttackPathCounts | null {
  if (!value || typeof value !== "object") return null;
  const { retained_count, assessed_count, basis } = value as Record<string, unknown>;
  if (typeof retained_count !== "number" || !Number.isSafeInteger(retained_count) || retained_count < 0
    || typeof assessed_count !== "number" || !Number.isSafeInteger(assessed_count) || assessed_count < retained_count
    || typeof basis !== "string" || !basis.trim()) return null;
  return { retained_count, assessed_count, basis };
}

/** One snapshot-wide contract; bounded pages and legacy scalars are not substitutes. */
export function resolveSnapshotAttackPathCount(attackPaths: unknown): number | null {
  return readAttackPathCounts(attackPaths)?.retained_count ?? null;
}
