"use client";

import {
type CloudConnectionRecord,
type SourceRecord
} from "@/lib/api";
import { REPO_SCAN_SURFACES,repoScanLanguageSummary } from "@/lib/repo-scan-surfaces";
import {
isScannableConnection,
providerDisplayName,
type AdhocScanTarget,
type ScanMode,
type ScanScopeChip
} from "@/lib/scan-scope";
import {
ArrowRight,
ChevronDown,
Plus,
ShieldCheck,
X
} from "lucide-react";
import Link from "next/link";



/** Scan sources shown in the top tablist. Extends the job-queue ``ScanMode``
 * with the synchronous AI/ML supply-chain surface, which renders its results
 * inline rather than routing to a job. */
export type FormMode = ScanMode | "aiml";



export function scanPlanCopy(mode: FormMode, target: AdhocScanTarget, enrich: boolean) {
  if (mode === "connected") return "Provider inventory → CIS posture → identity context → findings, graph, and compliance evidence.";
  if (mode === "scheduled") return "Connector health → source collection → normalized evidence → findings and audit trail.";
  if (target === "repository") return `Agent and MCP discovery → dependencies, SBOM, secrets, IaC, and SAST → ${enrich ? "CVSS, EPSS, and KEV" : "local correlation"}.`;
  if (target === "containers") return `Image manifest → package inventory → vulnerability matching → ${enrich ? "threat enrichment" : "local correlation"}.`;
  if (target === "kubernetes") return "Workload discovery → Kubernetes posture → image evidence → graph correlation.";
  return `Mounted project discovery → agents, MCP, packages, and secret indicators → ${enrich ? "threat enrichment" : "local correlation"} → prioritized findings.`;
}



export function boundaryCopy(mode: FormMode, target: AdhocScanTarget): string {
  if (mode === "connected") return "Read-only provider APIs. Agent BOM does not mutate cloud resources.";
  if (mode === "scheduled") return "Runs the registered connector within its configured credential and tenant boundary.";
  if (target === "repository") return "Shallow read-only clone and static parsing. Repository code is not executed.";
  if (target === "kubernetes") return "Reads the selected kube context and namespace scope; it does not change workloads.";
  return "Discovery and scanning are read-only. Runtime policy enforcement is a separate operating mode.";
}



export function ScanAccessNotice({
  authLoading,
  managedTrialSession,
  roleCanRunScans,
}: {
  authLoading: boolean;
  managedTrialSession: boolean;
  roleCanRunScans: boolean;
}) {
  if (authLoading) {
    return (
      <p role="status" className="mb-3 text-xs text-[color:var(--text-tertiary)]">
        Checking scan permissions…
      </p>
    );
  }
  if (!roleCanRunScans) {
    return (
      <div
        role="note"
        className="mb-3 rounded-lg border border-amber-500/25 bg-amber-500/10 px-3 py-2 text-xs leading-5 text-amber-900 dark:text-amber-100"
      >
        Scans require the Contributor role or higher. Ask an administrator to grant scan access.
      </div>
    );
  }
  if (managedTrialSession) {
    return (
      <div
        role="note"
        className="mb-3 rounded-lg border border-amber-500/25 bg-amber-500/10 px-3 py-2 text-xs leading-5 text-amber-900 dark:text-amber-100"
      >
        Managed trial scans run from a verified AWS connection. Ad-hoc, data-source, and AI / ML execution stay unavailable in this environment.
      </div>
    );
  }
  return null;
}



export function ScanWorkspacePanel({
  chips,
  mode,
  target,
  enrich,
}: {
  chips: ScanScopeChip[];
  mode: FormMode;
  target: AdhocScanTarget;
  enrich: boolean;
}) {
  const plan = scanPlanCopy(mode, target, enrich);
  const visibleChips = chips.slice(0, 4);
  const extraChips = chips.slice(4);

  return (
    <div className="space-y-5">

      <section aria-labelledby="scan-scope-heading">
        <div className="flex items-center justify-between gap-3">
          <h2 id="scan-scope-heading" className="text-xs font-semibold uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
            Scope now
          </h2>
          {mode === "adhoc" ? (
            <span className="text-[10px] text-[color:var(--text-tertiary)]">{enrich ? "Enrichment on" : "Local evidence only"}</span>
          ) : null}
        </div>
        <dl className="mt-2 divide-y divide-[color:var(--border-subtle)] rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3">
          {visibleChips.map((chip) => (
            <div key={`${chip.label}-${chip.value}`} className="grid grid-cols-[92px_minmax(0,1fr)] gap-2 py-2.5 text-[11px] leading-4">
              <dt className="text-[color:var(--text-tertiary)]">{chip.label}</dt>
              <dd className="break-words text-right text-[color:var(--foreground)]">{chip.value}</dd>
            </div>
          ))}
        </dl>
        {extraChips.length > 0 ? (
          <details className="group mt-1.5 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)]">
            <summary className="flex cursor-pointer list-none items-center justify-between px-3 py-2 text-[10px] text-[color:var(--text-tertiary)] [&::-webkit-details-marker]:hidden">
              {extraChips.length} more scope detail{extraChips.length === 1 ? "" : "s"}
              <ChevronDown className="h-3 w-3 transition-transform group-open:rotate-180" />
            </summary>
            <dl className="divide-y divide-[color:var(--border-subtle)] border-t border-[color:var(--border-subtle)] px-3">
              {extraChips.map((chip) => (
                <div key={`${chip.label}-${chip.value}`} className="grid grid-cols-[92px_minmax(0,1fr)] gap-2 py-2.5 text-[11px] leading-4">
                  <dt className="text-[color:var(--text-tertiary)]">{chip.label}</dt>
                  <dd className="break-words text-right text-[color:var(--foreground)]">{chip.value}</dd>
                </div>
              ))}
            </dl>
          </details>
        ) : null}
      </section>

      <section className="rounded-xl border border-emerald-700/30 bg-emerald-500/[0.06] p-3" aria-label="Read-only boundary">
        <div className="flex items-center gap-2 text-xs font-medium text-[color:var(--foreground)]">
          <ShieldCheck className="h-4 w-4 text-emerald-800 dark:text-emerald-400" />
          Read-only boundary
        </div>
        <p className="mt-1.5 text-[11px] leading-4 text-[color:var(--text-secondary)]">{boundaryCopy(mode, target)}</p>
      </section>

      <details className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-2.5">
        <summary className="cursor-pointer text-xs font-semibold text-[color:var(--foreground)]">
          What this scan collects and produces
        </summary>
        <p className="mt-2 text-[11px] leading-5 text-[color:var(--text-secondary)]">{plan}</p>
      </details>

    </div>
  );
}



export function ConnectedAccountPanel({
  connections,
  connectionsLoading,
  connectionsError,
  selectedConnectionId,
  onSelectConnection,
  selectedConnection,
}: {
  connections: CloudConnectionRecord[];
  connectionsLoading: boolean;
  connectionsError: string;
  selectedConnectionId: string;
  onSelectConnection: (id: string) => void;
  selectedConnection: CloudConnectionRecord | null;
}) {
  if (connectionsLoading) return <p className="text-sm text-[color:var(--text-secondary)]">Loading…</p>;
  if (connectionsError) return <p className="text-sm text-red-400">{connectionsError}</p>;
  if (connections.length === 0) {
    return (
      <div className="space-y-3">
        <p className="text-sm text-[color:var(--text-secondary)]">No accounts connected.</p>
        <Link href="/connections" className="inline-flex items-center gap-1.5 text-sm text-emerald-800 dark:text-emerald-400 hover:text-emerald-900 dark:hover:text-emerald-300">
          Connect account <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>
    );
  }
  return (
    <div className="space-y-2">
      <select
        id="connection-picker"
        aria-label="Account"
        value={selectedConnectionId}
        onChange={(event) => onSelectConnection(event.target.value)}
        className="w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2.5 text-sm text-[color:var(--foreground)] focus:border-emerald-600 focus:outline-none"
      >
        {connections.map((connection) => (
          <option key={connection.id} value={connection.id}>
            {providerDisplayName(connection.provider)} · {connection.display_name}
          </option>
        ))}
      </select>
      {selectedConnection && !isScannableConnection(selectedConnection) ? (
        <p className="text-xs text-amber-300">Provider not scannable yet.</p>
      ) : null}
      {selectedConnection && isScannableConnection(selectedConnection) && selectedConnection.status !== "active" ? (
        <p className="text-xs text-amber-300">Verify this connection before running its first scan.</p>
      ) : null}
    </div>
  );
}



export function ScheduledSourcePanel({
  sources,
  sourcesLoading,
  sourcesUnavailable,
  selectedSourceId,
  onSelectSource,
}: {
  sources: SourceRecord[];
  sourcesLoading: boolean;
  sourcesUnavailable: boolean;
  selectedSourceId: string;
  onSelectSource: (id: string) => void;
}) {
  if (sourcesLoading) return <p className="text-sm text-[color:var(--text-secondary)]">Loading…</p>;
  if (sourcesUnavailable) {
    return <p className="text-sm text-[color:var(--text-secondary)]">Data sources are unavailable for this session.</p>;
  }
  if (sources.length === 0) {
    return (
      <Link href="/sources" className="inline-flex items-center gap-1.5 text-sm text-emerald-800 dark:text-emerald-400 hover:text-emerald-900 dark:hover:text-emerald-300">
        Register data source <ArrowRight className="h-3.5 w-3.5" />
      </Link>
    );
  }
  return (
    <select
      id="source-picker"
      aria-label="Source"
      value={selectedSourceId}
      onChange={(event) => onSelectSource(event.target.value)}
      className="w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2.5 text-sm focus:border-emerald-600 focus:outline-none"
    >
      {sources.map((source) => (
        <option key={source.source_id} value={source.source_id}>
          {source.display_name} · {source.kind}
        </option>
      ))}
    </select>
  );
}



export function RepoSurfaceCatalog() {
  return (
    <details className="group rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)]">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-3 py-2.5 text-xs text-[color:var(--text-secondary)] [&::-webkit-details-marker]:hidden">
        <span>
          {REPO_SCAN_SURFACES.length} surfaces auto-detected · {repoScanLanguageSummary()}
        </span>
        <ChevronDown className="h-3.5 w-3.5 shrink-0 transition-transform group-open:rotate-180" />
      </summary>
      <div className="border-t border-[color:var(--border-subtle)] px-3 py-3">
        <div className="flex flex-wrap gap-1.5">
          {REPO_SCAN_SURFACES.map((surface) => (
            <span
              key={surface.id}
              title={surface.detail}
              className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 py-0.5 text-[10px] text-[color:var(--text-secondary)]"
            >
              {surface.label}
            </span>
          ))}
        </div>
        <p className="mt-2 text-[10px] text-[color:var(--text-tertiary)]">
          Shallow read-only clone. Optional Semgrep SAST reports findings, clean, skipped, or failed explicitly. SaaS connectors use{" "}
          <Link href="/sources" className="text-emerald-800 dark:text-emerald-400 hover:text-emerald-900 dark:hover:text-emerald-300">Data Sources</Link>, not git URLs.
        </p>
      </div>
    </details>
  );
}



export function ContainerTargetPanel({
  imageInput,
  setImageInput,
  onAdd,
  queuedImages,
  onRemove,
  showBulkImages,
  setShowBulkImages,
  bulkText,
  setBulkText,
  applyBulk,
  parseBulkImages,
  fileInputRef,
  handleFileUpload,
}: {
  imageInput: string;
  setImageInput: (value: string) => void;
  onAdd: () => void;
  queuedImages: string[];
  onRemove: (index: number) => void;
  showBulkImages: boolean;
  setShowBulkImages: (value: boolean | ((current: boolean) => boolean)) => void;
  bulkText: string;
  setBulkText: (value: string) => void;
  applyBulk: () => void;
  parseBulkImages: (text: string) => string[];
  fileInputRef: React.RefObject<HTMLInputElement | null>;
  handleFileUpload: (e: React.ChangeEvent<HTMLInputElement>) => void;
}) {
  return (
    <div className="space-y-3">
      <ListInput
        placeholder="nginx:1.25 or ghcr.io/org/app:v1"
        value={imageInput}
        onChange={setImageInput}
        onAdd={onAdd}
        items={[]}
        onRemove={() => {}}
      />
      <button
        type="button"
        onClick={() => setShowBulkImages((current) => !current)}
        className="text-xs text-[color:var(--text-tertiary)] hover:text-[color:var(--foreground)]"
      >
        {showBulkImages ? "Hide bulk add" : "Bulk add images"}
      </button>
      {showBulkImages ? (
        <textarea
          placeholder={"# one image per line"}
          value={bulkText}
          onChange={(e) => setBulkText(e.target.value)}
          rows={3}
          className="w-full resize-y rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 font-mono text-xs"
        />
      ) : null}
      {showBulkImages ? (
        <div className="flex gap-2">
          <button type="button" onClick={applyBulk} disabled={!bulkText.trim()} className="rounded-lg bg-emerald-700 px-3 py-1.5 text-xs text-white disabled:opacity-40">
            Add {parseBulkImages(bulkText).length || 0}
          </button>
          <input ref={fileInputRef} type="file" accept=".txt,.csv,.list" onChange={handleFileUpload} className="hidden" />
          <button type="button" onClick={() => fileInputRef.current?.click()} className="rounded-lg border border-[color:var(--border-subtle)] px-3 py-1.5 text-xs">
            Import file
          </button>
        </div>
      ) : null}
      {queuedImages.length > 0 ? (
        <div className="flex flex-wrap gap-1.5">
          {queuedImages.map((item, i) => (
            <span key={i} className="flex items-center gap-1 rounded-md border border-[color:var(--border-subtle)] px-2 py-0.5 font-mono text-[10px]">
              {item}
              <button type="button" onClick={() => onRemove(i)} aria-label={`Remove ${item}`}>
                <X className="h-3 w-3" />
              </button>
            </span>
          ))}
        </div>
      ) : null}
    </div>
  );
}



export function RelatedLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <Link href={href} className="text-[color:var(--text-secondary)] transition-colors hover:text-emerald-400">
      {children}
    </Link>
  );
}



export function ListInput({
  placeholder, value, onChange, onAdd, items, onRemove,
}: {
  placeholder: string;
  value: string;
  onChange: (v: string) => void;
  onAdd: () => void;
  items: string[];
  onRemove: (i: number) => void;
}) {
  return (
    <div className="space-y-2">
      <div className="flex gap-2">
        <input
          type="text"
          placeholder={placeholder}
          className="flex-1 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-sm text-[color:var(--foreground)] focus:border-emerald-600 focus:outline-none"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); onAdd(); } }}
        />
        <button
          type="button"
          onClick={onAdd}
          className="flex items-center gap-1 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-xs text-[color:var(--foreground)] transition-colors hover:border-[color:var(--border-strong)]"
        >
          <Plus className="h-3.5 w-3.5" />
          Add
        </button>
      </div>
      {items.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {items.map((item, i) => (
            <span key={i} className="flex items-center gap-1.5 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-1 font-mono text-xs text-[color:var(--foreground)]">
              {item}
              <button type="button" onClick={() => onRemove(i)}>
                <X className="h-3 w-3 text-[color:var(--text-tertiary)] hover:text-[color:var(--foreground)]" />
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
