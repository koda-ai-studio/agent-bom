/**
 * Read a name list that the contract types as `string[]`, tolerating producers
 * that send `{ name }` or `{ id }` objects. Blank and non-string entries are dropped.
 */
export function entityNames(values: unknown): string[] {
  if (!Array.isArray(values)) return [];
  const names: string[] = [];
  for (const value of values) {
    let candidate: unknown = value;
    if (candidate && typeof candidate === "object") {
      const record = candidate as { name?: unknown; id?: unknown };
      candidate = typeof record.name === "string" && record.name.trim() ? record.name : record.id;
    }
    if (typeof candidate === "string" && candidate.trim()) names.push(candidate.trim());
  }
  return names;
}
