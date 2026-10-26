/** Header label for the runtime proxy feed: a loaded snapshot with no socket is not "Disconnected" data. */
export function proxyConnectionLabel({ connected, liveTransport, hasSnapshot }: { connected: boolean; liveTransport: boolean; hasSnapshot: boolean }): string {
  if (connected) return liveTransport ? "Live transport" : "Connected";
  return hasSnapshot ? "Snapshot (not live)" : "Disconnected";
}

/**
 * Block-reason slices that sum to the Blocked tile: blocks the producer did
 * not attribute to a reason become an explicit "unattributed" slice.
 */
export function blockedBreakdown(byReason: Record<string, number>, totalBlocked: number): { name: string; value: number }[] {
  const slices = Object.entries(byReason)
    .filter(([, count]) => count > 0)
    .map(([name, value]) => ({ name, value }));
  const attributed = slices.reduce((sum, slice) => sum + slice.value, 0);
  if (totalBlocked > attributed) slices.push({ name: "unattributed", value: totalBlocked - attributed });
  return slices;
}
