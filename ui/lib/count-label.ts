/** "1 agent" / "3 agents": a count with a noun that agrees with it. */
export function countLabel(count: number, singular: string, plural = `${singular}s`): string {
  return `${count.toLocaleString("en-US")} ${count === 1 ? singular : plural}`;
}

/** A count with thousands separators (fixed locale so server and client render alike); strings pass through. */
export function formatCount<T>(value: T): T | string {
  return typeof value === "number" && Number.isFinite(value) ? value.toLocaleString("en-US") : value;
}
