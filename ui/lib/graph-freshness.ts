/** A previous graph generation's recorded time for display; null when absent or unparseable. */
export function recordedAt(iso: string | null | undefined): string | null {
  if (!iso?.trim()) return null;
  const parsed = new Date(iso);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toLocaleString();
}
