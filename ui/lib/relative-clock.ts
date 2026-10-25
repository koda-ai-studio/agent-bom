/**
 * The one clock for relative times (ages, "x ago", SLA due/overdue, freshness
 * windows). In the static demo every record is dated at the sample snapshot,
 * so ages are measured from that snapshot instead of the visitor's wall clock.
 * Everywhere else this is the wall clock.
 */
let demoSnapshotAt: number | null = null;

/** Set by the static demo manifest loader once `snapshot_at` is known. */
export function setDemoSnapshotAt(value: number | null): void {
  demoSnapshotAt = value;
}

export function nowForRelativeTime(): number {
  return process.env.NEXT_PUBLIC_STATIC_DEMO === "1" && demoSnapshotAt !== null ? demoSnapshotAt : Date.now();
}
