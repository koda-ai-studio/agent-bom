/** Quarantined agents the "All" list actually leaves out; 0 when the list already includes them. */
export function hiddenQuarantinedCount(
  stateFilter: string,
  search: string,
  quarantined: number,
  statsTotal: number,
  listTotal: number,
): number {
  if (stateFilter !== "all" || search.trim() !== "") return 0;
  return Math.max(0, Math.min(quarantined, statsTotal - listTotal));
}
