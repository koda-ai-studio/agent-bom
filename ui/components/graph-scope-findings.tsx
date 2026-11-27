"use client";

import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";

type Page = Awaited<ReturnType<typeof api.getGraphScopeFindings>>;

export function GraphScopeFindings({ scanId, nodeId, label, expected, onClose, onInspect }: {
  scanId: string; nodeId: string; label: string; expected?: number | undefined;
  onClose: () => void; onInspect: (id: string, label: string) => void;
}) {
  const panel = useRef<HTMLElement>(null);
  useEffect(() => {
    const previous = document.activeElement;
    const positions: {element: HTMLElement; top: number}[] = [];
    for (let element = panel.current?.parentElement; element; element = element.parentElement) positions.push({element, top: element.scrollTop});
    const top = window.scrollY;
    panel.current?.focus();
    return () => {
      for (const item of positions) item.element.scrollTop = item.top;
      window.scrollTo({top});
      if ((previous instanceof HTMLElement || previous instanceof SVGElement) && previous.isConnected) previous.focus({preventScroll: true});
    };
  }, []);
  const [page, setPage] = useState<Page>();
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState(false);
  const [loading, setLoading] = useState(true);
  const [retry, setRetry] = useState(0);
  const generation = page?.snapshot_generation;
  const revision = page?.finding_revision;
  useEffect(() => {
    let active = true;
    setLoading(true); setError(false);
    api.getGraphScopeFindings(scanId, nodeId, offset, offset ? generation : undefined, offset ? revision : undefined).then(result => {
      if (active) { if (result.node_id !== nodeId || result.scan_id !== scanId) throw new Error("Scope response mismatch"); setPage(result); }
    }).catch(() => { if (active) setError(true); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [scanId, nodeId, offset, generation, revision, retry]);
  return <section ref={panel} tabIndex={-1} aria-label={`Findings for ${label}`} className="border-t border-outline p-4 text-sm">
    <div className="flex items-center justify-between gap-3"><h3 className="font-semibold">Findings · {label}</h3><button className="graph-page-action" onClick={onClose}>Close findings</button></div>
    <p className="my-2 text-xs text-ink-secondary">Distinct open issues in this asset’s containment scope. Shared occurrences of the same advisory and package count once.</p>
    {loading ? <p role="status">Loading scope findings…</p> : error ? <div role="alert">Findings could not be loaded. This is not a clean result. <button className="underline" onClick={() => { setOffset(0); setRetry(n => n + 1); }}>Retry findings</button></div> : page && <>
      {expected !== undefined && expected !== page.total && <p role="status">The current issue count is {page.total}; the earlier badge showed {expected}. Refresh the scope to reconcile revisions.</p>}
      <p>{page.total} open {page.total === 1 ? "issue" : "issues"}</p>
      <ul className="my-2 divide-y divide-outline">{page.findings.map(finding => <li key={finding.issue_key} className="flex flex-wrap items-center gap-3 py-2">
        <span className="w-16 text-xs">{finding.severity}</span><span className="min-w-0 flex-1 break-words">{finding.label}</span>
        {finding.node_ids.map((id, index) => <button key={id} className="text-xs underline" onClick={() => onInspect(id, finding.label)}>Inspect evidence{finding.node_ids.length > 1 ? ` ${index + 1}` : ""}</button>)}
      </li>)}</ul>
      <nav aria-label="Finding pages" className="flex items-center gap-3 text-xs"><button disabled={!offset} onClick={() => setOffset(Math.max(0, offset - 20))}>Previous</button><span>Page {Math.floor(offset / 20) + 1} of {Math.max(1, Math.ceil(page.total / 20))} · 20 per page</span><button disabled={offset + 20 >= page.total} onClick={() => setOffset(offset + 20)}>Next</button></nav>
    </>}
  </section>;
}
