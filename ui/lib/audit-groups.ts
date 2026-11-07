import type { AuditEntry } from "@/lib/api";

/** Collapse consecutive identical campaign details within one fetched page. */
export function groupAuditEntries(entries: AuditEntry[]): AuditEntry[][] {
  const groups: AuditEntry[][] = [];
  let previousKey: string | null = null;
  for (const entry of entries) {
    const key = entry.action.startsWith("risk_campaign.")
      ? JSON.stringify([entry.action, entry.actor, entry.resource, entry.details, Boolean(entry.hmac_signature)])
      : null;
    if (key !== null && key === previousKey) groups[groups.length - 1]!.push(entry);
    else groups.push([entry]);
    previousKey = key;
  }
  return groups;
}
