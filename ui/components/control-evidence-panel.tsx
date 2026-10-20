"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ExternalLink, Network, Route } from "lucide-react";

import { PaginationBar } from "@/components/pagination-bar";
import { SeverityBadge } from "@/components/severity-badge";
import { api } from "@/lib/api";
import type { ComplianceControl, UnifiedFinding } from "@/lib/api";
import type { GraphAttackPath } from "@/lib/api-types";
import { userFacingApiErrorMessage } from "@/lib/api-errors";
import { assetIcon, assetKindLabel } from "@/lib/asset-icon-registry";
import { attackPathKey } from "@/lib/attack-paths";
import { assetTypeLabel, controlGraphHref, controlTagFor, pathSupportReason } from "@/lib/control-evidence";
import { buildFindingInvestigationHref } from "@/lib/finding-investigation-href";

const FINDINGS_PAGE = 10;
const PATHS_PAGE = 5;

type View = "findings" | "paths";
interface Page<T> { rows: T[]; total: number | null; hasMore: boolean }
interface Load<T> { page: Page<T> | null; error: string | null; loading: boolean }
const idle = { page: null, error: null, loading: true };

function packageName(finding: UnifiedFinding): string[] {
  const value = finding.package?.trim();
  return value ? [value.replace(/@[^@]*$/, "") || value] : [];
}

function findingGraphHref(finding: UnifiedFinding, scanId: string | undefined): string {
  return buildFindingInvestigationHref({
    id: finding.cve_id || finding.finding_id || finding.id || "",
    node_id: finding.node_id ?? undefined,
    finding_node_id: finding.finding_node_id ?? undefined,
    entity_type: finding.entity_type ?? undefined,
    packages: packageName(finding),
    agents: finding.affected_agents ?? [],
    finding_id: finding.finding_id ?? finding.id,
    scan_id: finding.scan_id,
  }, { scanId });
}

/** Where an occurrence sits when its node id records it: a package copy inside a container image. */
function occurrenceLocation(nodeId: string | null | undefined): string | null {
  const image = /:image:([0-9a-f]{6,})$/i.exec(nodeId ?? "")?.[1];
  return image ? `in image ${image}` : null;
}

function findingHref(findingId: string, frameworkId: string, control: string): string {
  return `/findings?${new URLSearchParams({ finding: findingId, framework: frameworkId, control })}`;
}

function pathHref(path: GraphAttackPath, frameworkId: string, control: string, scanId: string | undefined): string {
  const params = new URL(controlGraphHref({ frameworkId, control, scanId }), "http://local").searchParams;
  const findingId = path.finding_ids?.[0];
  if (findingId) params.set("finding", findingId);
  params.set("selected_path", attackPathKey(path));
  return `/security-graph?${params}`;
}

function FindingRow({ finding, frameworkId, control, scanId }: { finding: UnifiedFinding; frameworkId: string; control: string; scanId?: string | undefined }) {
  const assetName = finding.asset?.name || finding.affected_servers?.[0] || finding.package || "Unattributed asset";
  const kindInput = { entityType: finding.entity_type ?? undefined, attributes: { resource_type: finding.asset?.asset_type } };
  const Icon = assetIcon(kindInput);
  const kind = assetTypeLabel(finding.asset?.asset_type) ?? assetKindLabel(kindInput);
  const findingId = finding.finding_id ?? finding.id;
  const label = finding.cve_id || finding.title || findingId;
  const location = occurrenceLocation(finding.node_id);
  return (
    <li className="flex flex-wrap items-start gap-x-3 gap-y-1.5 py-2.5">
      <SeverityBadge severity={finding.severity} className="mt-0.5 shrink-0" />
      <div className="min-w-[min(100%,12rem)] flex-1">
        <div className="flex min-w-0 items-center gap-1.5">
          <span data-testid="asset-kind" title={kind} className="inline-flex shrink-0 text-[color:var(--text-tertiary)]">
            <Icon className="h-3.5 w-3.5" />
          </span>
          <span className="truncate text-sm font-medium text-[color:var(--foreground)]" title={assetName}>{assetName}</span>
          <span className="shrink-0 text-xs text-[color:var(--text-tertiary)]">{kind}</span>
        </div>
        <p className="mt-0.5 truncate text-xs text-[color:var(--text-secondary)]" title={finding.title}>
          {finding.title ?? label}
          {location ? <span className="font-mono text-[color:var(--text-tertiary)]"> · {location}</span> : null}
        </p>
      </div>
      <div className="ml-auto flex shrink-0 items-center gap-1">
        <Link
          href={findingGraphHref(finding, scanId)}
          aria-label={`Open ${assetName} in the graph`}
          title="Open in the security graph"
          className="inline-flex items-center gap-1 rounded-md border border-[color:var(--border-subtle)] px-2 py-1 text-xs text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
        >
          <Network className="h-3.5 w-3.5" />Graph
        </Link>
        {findingId ? (
          <Link
            href={findingHref(findingId, frameworkId, control)}
            aria-label={`Open finding ${label}`}
            title="Open the finding"
            className="inline-flex items-center gap-1 rounded-md border border-[color:var(--border-subtle)] px-2 py-1 text-xs text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
          >
            <ExternalLink className="h-3.5 w-3.5" />Finding
          </Link>
        ) : null}
      </div>
    </li>
  );
}

function PathRow({ path, labels, reason, href }: { path: GraphAttackPath; labels: Map<string, string>; reason: string; href: string }) {
  const source = labels.get(path.source) ?? path.source;
  const target = labels.get(path.target) ?? path.target;
  return (
    <li className="flex flex-wrap items-start gap-x-3 gap-y-1.5 py-2.5">
      <span className="mt-0.5 w-12 shrink-0 text-right font-mono text-sm font-semibold text-[color:var(--foreground)]" title="Composite risk">
        {path.composite_risk.toFixed(1)}
      </span>
      <div className="min-w-[min(100%,12rem)] flex-1">
        <p className="truncate text-sm text-[color:var(--foreground)]" title={`${source} → ${target}`}>
          <span className="font-medium">{source}</span>
          <span className="text-[color:var(--text-tertiary)]"> → </span>
          {target}
        </p>
        <p className="mt-0.5 text-xs text-[color:var(--text-secondary)]">
          {path.hops.length - 1} hop{path.hops.length === 2 ? "" : "s"}
          {path.reachability ? ` · reachability ${path.reachability}` : ""}
        </p>
        <p className="mt-0.5 text-xs text-[color:var(--text-secondary)]" data-testid="path-support-reason">{reason}</p>
      </div>
      <Link
        href={href}
        className="ml-auto inline-flex shrink-0 items-center gap-1 rounded-md border border-[color:var(--border-subtle)] px-2 py-1 text-xs text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
      >
        <Route className="h-3.5 w-3.5" />Open path
      </Link>
    </li>
  );
}

function usePagedLoad<T>(load: (offset: number) => Promise<Page<T>>, offset: number, deps: unknown[]): Load<T> {
  const [state, setState] = useState<Load<T>>(idle);
  useEffect(() => {
    let cancelled = false;
    setState((current) => ({ ...current, loading: true, error: null }));
    load(offset)
      .then((page) => { if (!cancelled) setState({ page, error: null, loading: false }); })
      .catch((error: unknown) => {
        if (!cancelled) setState({ page: null, error: userFacingApiErrorMessage(error, "Could not load this control's evidence."), loading: false });
      });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [offset, ...deps]);
  return state;
}

/**
 * A control's evidence is the finding set that carries its tag, and the attack
 * paths that end on those findings. Both lists page on the server.
 */
export function ControlEvidencePanel({ control, frameworkId, scanId }: { control: ComplianceControl; frameworkId: string; scanId?: string | undefined }) {
  const [view, setView] = useState<View>("findings");
  const [findingOffset, setFindingOffset] = useState(0);
  const [pathOffset, setPathOffset] = useState(0);
  const [pathLabels, setPathLabels] = useState<Map<string, string>>(new Map());
  const code = control.code;

  const findings = usePagedLoad<UnifiedFinding>(async (offset) => {
    const response = await api.listFindings({ framework: frameworkId, control: code, ...(scanId ? { scanId } : {}), limit: FINDINGS_PAGE, offset });
    return { rows: response.findings ?? [], total: typeof response.total === "number" ? response.total : null, hasMore: Boolean(response.has_more) };
  }, findingOffset, [frameworkId, code, scanId]);

  const paths = usePagedLoad<GraphAttackPath>(async (offset) => {
    const response = await api.getGraphAttackPaths({ framework: frameworkId, control: code, scanId, limit: PATHS_PAGE, offset });
    setPathLabels(new Map((response.nodes ?? []).map((node) => [node.id, node.label || node.id])));
    const total = response.pagination?.total;
    return { rows: response.attack_paths ?? [], total: typeof total === "number" ? total : null, hasMore: Boolean(response.pagination?.has_more) };
  }, pathOffset, [frameworkId, code, scanId]);

  const sampleTag = (findings.page?.rows ?? []).map((row) => controlTagFor(row.framework_tags, code)).find(Boolean) ?? null;
  const pathTotal = paths.page?.total;
  const listedTotal = findings.page?.total;

  const tab = (key: View, label: string, count: number | null | undefined) => (
    <button
      type="button"
      onClick={() => setView(key)}
      aria-pressed={view === key}
      className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
        view === key ? "bg-[color:var(--surface-elevated)] text-[color:var(--foreground)]" : "text-[color:var(--text-tertiary)] hover:text-[color:var(--text-secondary)]"
      }`}
    >
      {label}{typeof count === "number" ? ` ${count.toLocaleString()}` : ""}
    </button>
  );

  return (
    <div>
      <div data-testid="control-evidence-summary" className="mb-3 space-y-0.5 text-sm text-[color:var(--text-secondary)]">
        {typeof pathTotal === "number" ? (
          <p>
            <span className="font-semibold text-[color:var(--foreground)]">{pathTotal.toLocaleString()}</span> attack path{pathTotal === 1 ? "" : "s"} support this control
          </p>
        ) : null}
        <p className="text-xs text-[color:var(--text-tertiary)]">
          Counted by control-tag evidence: {control.findings.toLocaleString()} finding{control.findings === 1 ? "" : "s"} carry {sampleTag ? <code className="font-mono">{sampleTag}</code> : `the ${code} tag`}; a path counts when it ends on one of them. Ranked by effective reach.
          {typeof listedTotal === "number" && listedTotal !== control.findings ? ` ${listedTotal.toLocaleString()} of them are open in the current findings window.` : ""}
        </p>
      </div>

      <div className="mb-2 inline-flex items-center gap-1 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-0.5" role="group" aria-label="Evidence view">
        {tab("findings", "Findings & assets", listedTotal)}
        {tab("paths", "Attack paths", pathTotal)}
      </div>

      {view === "findings" ? (
        <EvidenceList
          state={findings}
          empty="No current findings carry this control's tag."
          ariaLabel={`Findings mapped to ${code}`}
          page={Math.floor(findingOffset / FINDINGS_PAGE) + 1}
          pageSize={FINDINGS_PAGE}
          itemLabel="findings"
          onPage={(delta) => setFindingOffset((value) => Math.max(0, value + delta * FINDINGS_PAGE))}
          render={(row) => <FindingRow key={row.finding_id ?? row.id} finding={row} frameworkId={frameworkId} control={code} scanId={scanId} />}
        />
      ) : (
        <EvidenceList
          state={paths}
          empty="No attack path ends on a finding mapped to this control."
          ariaLabel={`Attack paths supporting ${code}`}
          page={Math.floor(pathOffset / PATHS_PAGE) + 1}
          pageSize={PATHS_PAGE}
          itemLabel="paths"
          onPage={(delta) => setPathOffset((value) => Math.max(0, value + delta * PATHS_PAGE))}
          render={(row) => (
            <PathRow
              key={attackPathKey(row)}
              path={row}
              labels={pathLabels}
              reason={pathSupportReason(row, code, sampleTag)}
              href={pathHref(row, frameworkId, code, scanId)}
            />
          )}
        />
      )}
    </div>
  );
}

function EvidenceList<T>({ state, empty, ariaLabel, page, pageSize, itemLabel, onPage, render }: {
  state: Load<T>; empty: string; ariaLabel: string; page: number; pageSize: number; itemLabel: string;
  onPage: (delta: number) => void; render: (row: T) => React.ReactNode;
}) {
  if (state.error) return <p role="alert" className="py-3 text-sm text-[color:var(--text-secondary)]">{state.error}</p>;
  if (!state.page) return <p className="py-3 text-sm text-[color:var(--text-tertiary)]" aria-busy="true">Loading evidence…</p>;
  if (state.page.rows.length === 0 && page === 1) return <p className="py-3 text-sm text-[color:var(--text-secondary)]">{empty}</p>;
  const total = state.page.total;
  return (
    <div aria-busy={state.loading}>
      <ul aria-label={ariaLabel} className="divide-y divide-[color:var(--border-subtle)]">
        {state.page.rows.map(render)}
      </ul>
      <PaginationBar
        className="mt-2"
        page={page}
        totalPages={total == null ? null : Math.max(1, Math.ceil(total / pageSize))}
        totalItems={total}
        hasMore={state.page.hasMore}
        itemLabel={itemLabel}
        onPrevious={() => onPage(-1)}
        onNext={() => onPage(1)}
      />
    </div>
  );
}
