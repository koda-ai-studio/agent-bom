/** Presentation of saved setup, not a claim that remote clients installed it. */
export function profileSetup(value: unknown, tenant: string | undefined, now: number): string {
  const rows = (value as { assignments?: unknown } | null)?.assignments;
  if (!tenant || !Array.isArray(rows) || rows.length > 1000 || rows.some(row => !row || row.tenant_id !== tenant ||
    typeof row.config_id !== "string" || !["active", "disabled", "revoked"].includes(row.status) || typeof row.revoked !== "boolean" ||
    typeof row.expires_at !== "string" || (row.expires_at && !Number.isFinite(Date.parse(row.expires_at))))) return "Profile setup unavailable";
  if (new Set(rows.map(row => row.config_id)).size !== rows.length) return "Profile setup unavailable";
  const count = rows.filter(row => row.status === "active" && !row.revoked && (!row.expires_at || Date.parse(row.expires_at) > now)).length;
  return `${count} active ${count === 1 ? "profile" : "profiles"}${rows.length === 1000 ? " in first 1,000 records" : ""}`;
}

export function policySetup(value: unknown): string {
  const runtime = (value as { policy_runtime?: { source_kind?: string; rollout_mode?: string } } | null)?.policy_runtime;
  if (runtime?.source_kind !== "policy_store") return "Policy setup unavailable";
  const labels: Record<string, string> = { disabled: "Gateway policies disabled", advisory_only: "Advisory policies configured", mixed: "Mixed policies configured", default_deny: "Default deny configured", blocking: "Blocking configured" };
  const mode = runtime.rollout_mode;
  return typeof mode === "string" && Object.hasOwn(labels, mode) ? labels[mode]! : "Policy setup unavailable";
}

export function receiptStatus(timestamp: string | undefined, now: number): string {
  if (!timestamp) return "No receipts in this window";
  const age = now - Date.parse(timestamp);
  if (!Number.isFinite(age) || age < 0) return "Receipt time unverified";
  return age <= 120000 ? "Received within 2 minutes" : "Receipt older than 2 minutes";
}
