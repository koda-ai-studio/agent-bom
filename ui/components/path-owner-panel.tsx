"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import { formatDate } from "@/lib/api";
import { ownershipSummary, pathLeadFinding, type OwnershipFields } from "@/lib/finding-ownership";

type Row = OwnershipFields & { finding_id?: string; id?: string; node_id?: string | null; package?: string | null };

/** Owner/team and remediation SLA of the finding occurrence this path runs through. */
export function PathOwnerPanel({ cve, hops, packageLabel, scanId }: {
  cve: string; hops: string[]; packageLabel: string | undefined; scanId: string;
}) {
  const scope = JSON.stringify([cve, scanId]);
  const [state, setState] = useState<{ scope: string; rows?: Row[]; error?: boolean } | null>(null);
  useEffect(() => {
    let cancelled = false;
    const historical = scanId && !scanId.startsWith("current-estate:") ? { scanId } : {};
    api.listFindings({ query: cve, limit: 100, ...historical })
      .then((page) => { if (!cancelled) setState({ scope, rows: (page.findings ?? []) as Row[] }); })
      .catch(() => { if (!cancelled) setState({ scope, error: true }); });
    return () => { cancelled = true; };
  }, [cve, scanId, scope]);
  const current = state?.scope === scope ? state : null;
  const lead = current?.rows ? pathLeadFinding(current.rows, hops, packageLabel) : null;
  const summary = lead ? ownershipSummary(lead) : null;
  const findingId = lead?.finding_id ?? lead?.id;
  const slaTone = summary?.slaState === "overdue" ? "text-red-700 dark:text-red-300" : "text-foreground";
  return (
    <section aria-label="Path owner" className="rounded-xl border border-outline bg-surface p-4 text-sm text-foreground">
      <h3 className="font-semibold">Owner and SLA · {cve}</h3>
      {!current ? <p role="status" className="mt-2 text-ink-secondary">Reading ownership…</p> : null}
      {current?.error ? <p role="alert" className="mt-2 text-ink-secondary">Ownership is unavailable. Open the finding to review it.</p> : null}
      {current?.rows && !summary ? <p className="mt-2 text-ink-secondary">No finding record for this path carries ownership in this scope.</p> : null}
      {summary ? (
        <div className="mt-3 space-y-3">
          <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-[auto_1fr]">
            <dt className="text-ink-secondary">Owner / team</dt>
            <dd className={summary.owner ? "font-medium" : "font-medium text-amber-800 dark:text-amber-300"}>{summary.ownerLabel}</dd>
            <dt className="text-ink-secondary">Remediation SLA</dt>
            <dd className={slaTone}>
              <span className="font-medium">{summary.slaLabel}</span>
              {summary.dueDate ? <span className="text-ink-secondary"> · {formatDate(summary.dueDate)}</span> : null}
              {summary.basis ? <span className="block text-xs text-ink-secondary">{summary.basis}</span> : null}
            </dd>
          </dl>
          {findingId ? (
            <Link href={`/findings?${new URLSearchParams({ finding: findingId })}`} className="inline-flex rounded-lg border border-outline bg-surface px-3 py-2 text-xs font-medium hover:bg-surface-muted">
              {summary.owner ? "Review ownership in triage" : "Assign owner in triage"}
            </Link>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
