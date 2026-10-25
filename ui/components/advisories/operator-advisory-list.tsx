"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { ShieldAlert } from "lucide-react";

import { SeverityBadge } from "@/components/severity-badge";
import { PageEmptyState, PageErrorState, PageLoadingState } from "@/components/states/page-state";
import { ApiForbiddenError } from "@/lib/api-errors";
import { operatorAdvisoryApi, type OperatorAdvisoryListResponse, type OperatorAdvisoryRecord } from "@/lib/operator-advisories";

import { secondaryButtonClass } from "./advisory-form-fields";
import { formatUtc } from "./advisory-format";

function productLabel(advisory: OperatorAdvisoryRecord): string {
  const names = advisory.affected.map(item => item.cpe_product ?? (item.name ? `${item.ecosystem ?? ""}/${item.name}` : "")).filter(Boolean);
  return names.length > 2 ? `${names.slice(0, 2).join(", ")} +${names.length - 2}` : names.join(", ");
}

function RetireControl({ id, onRetire, busy }: { id: string; onRetire: () => void; busy: boolean }) {
  const [confirming, setConfirming] = useState(false);
  if (!confirming) {
    return <button type="button" className={secondaryButtonClass} aria-label={`Retire ${id}`} onClick={() => setConfirming(true)}>Retire</button>;
  }
  return (
    <span className="inline-flex flex-wrap gap-1.5">
      <button type="button" disabled={busy} aria-label={`Confirm retire ${id}`} onClick={onRetire}
        className={`${secondaryButtonClass} border-[color:var(--status-danger-border)] text-[color:var(--status-danger)]`}>Confirm</button>
      <button type="button" className={secondaryButtonClass} aria-label={`Keep ${id}`} onClick={() => setConfirming(false)}>Cancel</button>
    </span>
  );
}

/** Declared emergency advisories (`GET /v1/intel/operator-advisories`), each linking to its affected assets. */
export function OperatorAdvisoryList({ refreshKey }: { refreshKey: number }) {
  const [data, setData] = useState<OperatorAdvisoryListResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [retiring, setRetiring] = useState<string | null>(null);
  const [retireError, setRetireError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setData(await operatorAdvisoryApi.list());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Advisories could not be loaded");
    }
  }, []);

  useEffect(() => { void load(); }, [load, refreshKey]);

  async function retire(id: string) {
    setRetiring(id);
    setRetireError(null);
    try {
      await operatorAdvisoryApi.retire(id);
      await load();
    } catch (err) {
      setRetireError(err instanceof ApiForbiddenError ? "Retiring an advisory needs the admin role." : `Could not retire ${id}: ${err instanceof Error ? err.message : "request failed"}`);
    } finally {
      setRetiring(null);
    }
  }

  if (error) return <PageErrorState compact title="Declared advisories unavailable" detail={error} action={{ label: "Retry", onClick: () => void load() }} />;
  if (!data) return <PageLoadingState compact title="Loading declared advisories" detail="Reading this tenant's emergency advisories." />;
  if (!data.advisories.length) {
    return <PageEmptyState compact icon={ShieldAlert} title="No emergency advisories declared" detail="Declare one to match a disclosure against stored scans before any feed publishes it." />;
  }
  return (
    <div className="min-w-0 space-y-2">
      {retireError ? <p role="alert" className="text-sm text-[color:var(--status-danger)]">{retireError}</p> : null}
      <ul aria-label="Declared emergency advisories" className="divide-y divide-outline rounded-xl border border-outline bg-surface">
        {data.advisories.map(advisory => (
          <li key={advisory.id} aria-label={advisory.id} className="space-y-1.5 px-3 py-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs font-semibold text-foreground">{advisory.id}</span>
              <SeverityBadge severity={advisory.severity} />
              <span className="min-w-0 truncate font-mono text-[11px] text-ink-tertiary">{productLabel(advisory)}</span>
            </div>
            <p className="line-clamp-2 text-xs text-ink-secondary" title={advisory.summary}>{advisory.summary}</p>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-[11px] text-ink-tertiary">Updated {formatUtc(advisory.updated_at)}</span>
              <div className="flex flex-wrap gap-1.5">
                <Link href={`/advisories?id=${encodeURIComponent(advisory.id)}`} aria-label={`Affected assets for ${advisory.id}`} className={secondaryButtonClass}>Affected assets</Link>
                <RetireControl id={advisory.id} busy={retiring === advisory.id} onRetire={() => void retire(advisory.id)} />
              </div>
            </div>
          </li>
        ))}
      </ul>
      {data.rematch?.last_run ? <p className="text-xs text-ink-tertiary">Last re-match against stored scans · {formatUtc(data.rematch.last_run)}</p> : null}
    </div>
  );
}
