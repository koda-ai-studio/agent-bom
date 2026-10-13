/** "1 agent" / "3 agents": a count with a noun that agrees with it. */
export function countLabel(count: number, singular: string, plural = `${singular}s`): string {
  return `${count.toLocaleString("en-US")} ${count === 1 ? singular : plural}`;
}
