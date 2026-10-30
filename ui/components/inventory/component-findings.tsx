"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowRight, Download, Network, Package, ShieldCheck } from "lucide-react";
import { useAuthState } from "@/components/auth-provider";
import { SeverityBadge } from "@/components/severity-badge";
import { useIncidentNeighborhood } from "@/hooks/use-incident-neighborhood";
import { FINDING_ENTITY_TYPES, type UnifiedEdge, type UnifiedNode } from "@/lib/graph-schema";
import { buildGraphInvestigationBundle, downloadGraphInvestigation } from "@/lib/graph-investigation-bundle";
import { plainRelationshipSummary } from "@/lib/graph-relationship-plain";
import { formatFindingTimestamp } from "@/lib/findings-view";
import { humanizeEnum } from "@/lib/enum-labels";

const actionClass = "inline-flex items-center justify-center gap-2 rounded-lg border border-outline px-3 py-2 text-sm font-medium hover:bg-surface-muted";
const graphHref = (node: string, scan: string) => `/security-graph?${new URLSearchParams({ lens: "estate", node, scan })}`;
const recordedText = (value: unknown) => typeof value === "string" && value.trim() ? value.trim() : null;
const isFinding = (node: UnifiedNode) => [...FINDING_ENTITY_TYPES].some(type => type === node.entity_type);

/** Explicit component scope never falls back to the tenant-wide finding queue. */
export function ComponentFindings({ assetId, scanId }: { assetId: string; scanId: string }) {
  const { session, loading } = useAuthState();
  if (!assetId || !scanId) return <p role="alert" className="p-6">Choose a component and a retained scan snapshot from inventory to inspect its finding evidence.</p>;
  if (loading || !session) return <p role="status" className="p-6">Resolving access to component findings…</p>;
  const owner = JSON.stringify(session);
  return <ComponentFindingEvidence key={JSON.stringify([owner, assetId, scanId])} assetId={assetId} scanId={scanId} owner={owner} />;
}

function FindingCard({ finding, component, edges, scanId }: { finding: UnifiedNode; component: UnifiedNode | undefined; edges: UnifiedEdge[]; scanId: string }) {
  const summary = recordedText(finding.attributes?.summary) ?? recordedText(finding.attributes?.description);
  const fixed = recordedText(finding.attributes?.fixed_version);
  const nodeLabel = (id: string) => id === finding.id ? finding.label || id : component?.label || id;
  return <li className="min-w-0 space-y-4 rounded-xl border border-outline bg-surface p-4 sm:p-5">
    <div className="flex items-start justify-between gap-3">
      <Link href={graphHref(finding.id, scanId)} className="break-words text-base font-semibold underline decoration-dotted underline-offset-4">{finding.label || finding.id}</Link>
      <SeverityBadge severity={finding.severity || "unknown"} />
    </div>
    {summary && <p className="text-sm leading-relaxed text-ink-secondary">{summary}</p>}
    <div className="space-y-2 border-l-2 border-[color:var(--accent)] pl-3">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-secondary">Why this is linked</h3>
      {edges.map(edge => <p key={JSON.stringify([edge.source, edge.target, edge.relationship])} className="text-sm">
        {plainRelationshipSummary(edge, nodeLabel(edge.source), nodeLabel(edge.target)).why}
      </p>)}
    </div>
    <dl className="grid gap-3 text-sm sm:grid-cols-2">
      <div><dt className="text-xs text-ink-secondary">Recorded fixed version</dt><dd className="mt-1 font-mono">{fixed || "Not recorded in this snapshot"}</dd></div>
      <div><dt className="text-xs text-ink-secondary">Last seen</dt><dd className="mt-1">{finding.last_seen ? formatFindingTimestamp(finding.last_seen) : "Not recorded"}</dd></div>
      <div className="sm:col-span-2"><dt className="text-xs text-ink-secondary">Evidence sources</dt><dd className="mt-1 break-words">{finding.data_sources?.map(humanizeEnum).join(" · ") || "Not recorded"}</dd></div>
    </dl>
    <details className="border-t border-outline pt-3 text-xs text-ink-secondary"><summary className="cursor-pointer">Recorded association</summary>
      <p className="mt-2 break-all">Finding node: {finding.id}</p>
      {edges.map(edge => <p key={JSON.stringify([edge.source, edge.target, edge.relationship])} className="mt-1 break-all">{edge.source} → {edge.relationship} → {edge.target}</p>)}
    </details>
  </li>;
}

function ComponentFindingEvidence({ assetId, scanId, owner }: { assetId: string; scanId: string; owner: string }) {
  const graph = useIncidentNeighborhood(scanId, assetId, "both", owner);
  const [exportError, setExportError] = useState(false);
  const component = graph.nodes.find(node => node.id === assetId);
  const adjacent = new Set(graph.edges.flatMap(edge => edge.source === assetId ? [edge.target] : edge.target === assetId ? [edge.source] : []));
  const neighbors = graph.nodes.filter(node => node.id !== assetId && adjacent.has(node.id));
  const findings = neighbors.filter(isFinding);
  const context = neighbors.filter(node => !isFinding(node));
  const last = graph.pages.at(-1);
  const hasGaps = graph.pages.some(page => (page.completeness.missing_endpoint_count ?? 0) > 0);
  return <div className="mx-auto max-w-6xl space-y-5 px-4 py-5 sm:p-6">
    <header className="space-y-3 border-b border-outline pb-5">
      <Link href="/findings" className="text-xs text-ink-secondary underline underline-offset-4">All findings</Link>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex min-w-0 items-start gap-3">
          <span className="rounded-xl border border-outline bg-surface p-3"><Package className="h-6 w-6 text-[color:var(--accent)]" aria-hidden="true" /></span>
          <div className="min-w-0"><p className="text-xs uppercase tracking-wide text-ink-secondary">Component finding evidence</p>
            <h1 className="mt-1 break-words text-2xl font-semibold">{component?.label || assetId}</h1>
            <p className="mt-1 text-sm text-ink-secondary">What is linked to this component, why it matters, and where to investigate next.</p>
          </div>
        </div>
        <Link className={`${actionClass} bg-[color:var(--accent)]/10`} href={graphHref(assetId, scanId)}><Network className="h-4 w-4" aria-hidden="true" />Investigate the component chain<ArrowRight className="h-4 w-4" aria-hidden="true" /></Link>
      </div>
    </header>
    <div className="grid items-start gap-5 lg:grid-cols-[minmax(0,1fr)_20rem]">
      <section className="min-w-0 space-y-3" aria-label="Linked findings">
        <div className="flex flex-wrap items-baseline justify-between gap-2"><h2 className="font-semibold">Linked findings</h2>
          <p role="status" className="text-xs text-ink-secondary">{graph.busy && !last ? "Loading component evidence…" : `${findings.length} linked finding records in ${graph.edges.length} loaded relationships`}</p>
        </div>
        {graph.error && <div role="alert" className="space-y-2 rounded-lg border border-outline p-4">
          <p>{graph.error}</p>
          <button type="button" className={actionClass} disabled={graph.busy} onClick={() => graph.stale ? graph.restart() : void graph.load(assetId, last?.next_cursor ?? undefined)}>Retry component evidence</button>
        </div>}
        {hasGaps && <p className="text-sm text-ink-secondary">Some relationship endpoints are missing. Finding coverage is incomplete.</p>}
        <ul aria-label="Component finding records" className="space-y-3">
          {findings.map(finding => <FindingCard key={finding.id} finding={finding} component={component} scanId={scanId}
            edges={graph.edges.filter(edge => (edge.source === assetId && edge.target === finding.id) || (edge.target === assetId && edge.source === finding.id))} />)}
        </ul>
        {last && !graph.error && findings.length === 0 && <p className="rounded-xl border border-outline p-4 text-sm">No finding records are linked in the loaded pages. This does not establish a clean component.</p>}
        {last?.next_cursor && !graph.error && <button type="button" className={`${actionClass} disabled:opacity-50`} disabled={graph.busy || graph.capped}
          onClick={() => void graph.load(assetId, last.next_cursor!)}>{graph.busy ? "Loading…" : "Load more component relationships"}</button>}
        {graph.capped && last?.next_cursor && <p className="text-sm">Display limit reached. Continue in the component chain to inspect connected entities.</p>}
      </section>
      <aside aria-label="Component context and next steps" className="min-w-0 space-y-4 rounded-xl border border-outline bg-surface p-4">
        <section className="space-y-2"><h2 className="font-semibold">Next steps</h2>
          <Link className={`${actionClass} w-full justify-start`} href={`/remediation?${new URLSearchParams({ scan: scanId })}`}><ArrowRight className="h-4 w-4" aria-hidden="true" />Review snapshot remediation</Link>
          <Link className={`${actionClass} w-full justify-start`} href={`/compliance?${new URLSearchParams({ asset: assetId, scan: scanId })}`}><ShieldCheck className="h-4 w-4" aria-hidden="true" />Inspect control evidence</Link>
        </section>
        <section className="space-y-2 border-t border-outline pt-4"><h2 className="text-sm font-semibold">Connected context</h2>
          <p className="text-xs text-ink-secondary">Direct neighbors in the loaded evidence. Explore the chain for wider reach.</p>
          {context.length ? <ul className="space-y-2">{context.slice(0, 6).map(node => <li key={node.id} className="flex flex-wrap items-center justify-between gap-1 text-sm"><Link href={graphHref(node.id, scanId)} className="break-words underline underline-offset-4">{node.label || node.id}</Link><span className="text-xs text-ink-secondary">{humanizeEnum(node.entity_type)}</span></li>)}</ul>
            : <p className="text-xs text-ink-secondary">No other connected components in the loaded pages.</p>}
          {context.length > 6 && <Link href={graphHref(assetId, scanId)} className="text-xs underline">Explore all {context.length} loaded neighbors</Link>}
        </section>
        <section className="space-y-2 border-t border-outline pt-4"><h2 className="text-sm font-semibold">Evidence scope</h2>
          <dl className="space-y-2 text-xs"><div><dt className="text-ink-secondary">Component</dt><dd className="break-all font-mono">{assetId}</dd></div><div><dt className="text-ink-secondary">Snapshot</dt><dd className="break-all">{scanId.startsWith("current-estate:") ? "Current tenant estate" : scanId}</dd></div></dl>
          <p className="text-xs leading-relaxed text-ink-secondary">Only findings directly linked to this component are listed. Recorded associations do not establish runtime exploitation.</p>
          {last && !last.next_cursor && !graph.error && <p className="text-xs text-ink-secondary">End of recorded relationship pages. Source collection coverage remains unknown.</p>}
        </section>
        <details className="border-t border-outline pt-4 text-sm"><summary className="cursor-pointer font-medium">Export component evidence</summary>
          <p className="my-2 text-xs text-ink-secondary">An unsigned local bundle of loaded relationships, finding nodes, source metadata, snapshot generation and completeness receipts.</p>
          <button type="button" className={`${actionClass} disabled:opacity-50`} disabled={!last || graph.busy || Boolean(graph.error)} onClick={() => {
            setExportError(false);
            try { downloadGraphInvestigation(buildGraphInvestigationBundle(scanId, assetId, graph.pages, window.location.href)); }
            catch { setExportError(true); }
          }}><Download className="h-4 w-4" aria-hidden="true" />Download component evidence</button>
          {exportError && <p role="alert">Unable to export evidence. Reload the component and retry.</p>}
        </details>
      </aside>
    </div>
  </div>;
}
