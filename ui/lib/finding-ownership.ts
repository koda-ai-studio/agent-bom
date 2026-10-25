import { nowForRelativeTime } from "@/lib/relative-clock";

/** Owner and remediation-SLA facts recorded on a finding occurrence. */
export interface OwnershipFields {
  owner?: string | null | undefined;
  sla_due_at?: string | null | undefined;
  sla_due_at_source?: string | null | undefined;
}

export interface OwnershipSummary {
  owner: string | null;
  ownerLabel: string;
  dueDate: string | null;
  slaLabel: string;
  slaState: "overdue" | "due" | "none";
  basis: string | null;
}

const DAY_MS = 86_400_000;
const BASIS: Record<string, string> = {
  "severity-kev/v1": "Severity and KEV policy",
  explicit: "Explicit due date",
};

const plural = (count: number, unit: string) => `${count} ${unit}${count === 1 ? "" : "s"}`;

export function ownershipSummary(fields: OwnershipFields, now = nowForRelativeTime()): OwnershipSummary {
  const owner = fields.owner?.trim() || null;
  const due = fields.sla_due_at ? Date.parse(fields.sla_due_at) : Number.NaN;
  const basis = fields.sla_due_at_source ? BASIS[fields.sla_due_at_source] ?? null : null;
  if (!Number.isFinite(due)) {
    return { owner, ownerLabel: owner ?? "Unassigned", dueDate: null, slaLabel: "No SLA recorded", slaState: "none", basis: null };
  }
  const days = Math.round((due - now) / DAY_MS);
  const overdue = due < now;
  return {
    owner,
    ownerLabel: owner ?? "Unassigned",
    dueDate: fields.sla_due_at!,
    slaLabel: overdue ? `Overdue by ${plural(Math.max(1, -days), "day")}` : days === 0 ? "Due today" : `Due in ${plural(days, "day")}`,
    slaState: overdue ? "overdue" : "due",
    basis,
  };
}

/** The occurrence this path runs through: its node on the path, else the same package. */
export function pathLeadFinding<T extends { node_id?: string | null | undefined; package?: string | null | undefined }>(
  rows: T[],
  hops: string[],
  packageLabel: string | undefined,
): T | null {
  const onPath = new Set(hops);
  return rows.find((row) => row.node_id && onPath.has(row.node_id))
    ?? (packageLabel ? rows.find((row) => row.package === packageLabel) : undefined)
    ?? null;
}
