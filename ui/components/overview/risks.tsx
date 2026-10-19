"use client";

import { Drawer } from "@/components/drawer";
import { sbomSourceName } from "@/lib/findings-view";
import { ArrowRight } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { ExposurePathView, ReportEvidenceLink } from "./shared";

export function TopRisksPanel({
  localReport = false,
  loading,
  unavailable,
  scans,
  topPath,
  exposurePaths,
  agentMeshHref = null,
}: {
  localReport?: boolean | undefined;
  loading: boolean;
  unavailable: boolean;
  scans: number | null;
  topPath: ExposurePathView | null;
  exposurePaths: ExposurePathView[];
  agentMeshHref?: string | null;
}) {
  const allPaths = exposurePaths.length > 0 ? exposurePaths : topPath ? [topPath] : [];
  const ranked = [...allPaths].sort((a, b) => b.riskScore - a.riskScore);
  const shown = ranked.slice(0, 5);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [wide, setWide] = useState(false);
  const container = useRef<HTMLElement>(null);
  useEffect(() => {
    if (!container.current || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(([entry]) => {
      const sideBySide = (entry?.contentRect.width ?? 0) >= 960;
      setWide(sideBySide);
      if (sideBySide) setDrawerOpen(false);
    });
    observer.observe(container.current);
    return () => observer.disconnect();
  }, []);
  const selected = shown.find((path) => path.key === selectedKey) ?? shown[0];
  const detail = selected ? <RiskChainRow localReport={localReport} path={selected} rank={shown.indexOf(selected) + 1} /> : null;
  return (
    <section ref={container} aria-label="Prioritized findings" className="@container">
      <p className="mb-3 text-xs text-ink-secondary">Review these findings first · {ranked.length} prioritized risks</p>
      {loading ? <p role="status" className="text-sm text-ink-secondary">Loading prioritized findings…</p>
        : shown.length > 0 ? <div className="grid items-start gap-4 @min-[960px]:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
          <div role="group" aria-label="Select a risk" className="divide-y divide-outline">
            {shown.map((path, index) => {
              const workload = path.affectedWorkloads?.[0] ?? path.nodes.find((node) => node.type === "agent" || node.type === "server")?.label;
              const finding = path.nodes.find((node) => node.type === "cve");
              return <button key={path.key} type="button" aria-pressed={selected?.key === path.key}
                onClick={() => { setSelectedKey(path.key); if (!wide) setDrawerOpen(true); }}
                className={`flex w-full items-start gap-2 rounded-md px-2 py-3 text-left ${selected?.key === path.key ? "bg-emerald-500/10" : "hover:bg-surface-muted"}`}>
                <span className="text-xs tabular-nums text-ink-secondary">{index + 1}</span>
                <span className="min-w-0 flex-1"><span className="block break-words text-sm font-semibold">{workload ? (sbomSourceName(workload) ? `SBOM source: ${sbomSourceName(workload)}` : workload) : "Workload not identified"}</span>
                  <span className="block break-words text-xs text-ink-secondary">{finding?.label ?? "Finding"} · {finding?.severity ?? "Severity unavailable"}</span></span>
                <ArrowRight className="mt-1 h-4 w-4 shrink-0 text-ink-secondary" aria-hidden="true" />
              </button>;
            })}
          </div>
          {wide ? <div role="region" aria-label="Selected risk" className="min-w-0 max-h-[28rem] overflow-y-auto rounded-lg border border-outline p-3">{detail}</div> : null}
          <Drawer open={!wide && drawerOpen} onClose={() => setDrawerOpen(false)} title="Selected risk" ariaLabel="Selected risk" size="lg">{detail}</Drawer>
        </div>
        : <p className="text-sm text-ink-secondary">{unavailable ? "Prioritized findings unavailable." : scans === 0 ? "No completed scans. Run a scan to assess findings." : "No prioritized findings in the current overview."}</p>}
      {!localReport && <div className="mt-3 flex flex-wrap gap-3 text-sm">
        <ReportEvidenceLink localReport={localReport} href="/security-graph" className="text-emerald-700 dark:text-emerald-300">Open investigation →</ReportEvidenceLink>
        {agentMeshHref ? <ReportEvidenceLink localReport={localReport} href={agentMeshHref} className="text-ink-secondary">Agent mesh</ReportEvidenceLink> : null}
      </div>}
    </section>
  );
}

export function RiskChainRow({ path, rank, localReport = false }: { path: ExposurePathView; rank: number; localReport?: boolean }) {
  const finding = path.nodes.find((node) => node.type === "cve");
  const workload = path.nodes.find((node) => node.type === "agent") ?? path.nodes.find((node) => node.type === "server");
  const sbomSource = workload ? sbomSourceName(workload.label) : null;
  const workloads = [...new Set(path.affectedWorkloads?.length ? path.affectedWorkloads : workload ? [workload.label] : [])];
  const impact = {
    "code-execution": "Could allow attacker-controlled code to run if the vulnerable feature processes untrusted input.",
    "credential-access": "Could allow unauthorized access if the affected authentication feature is exposed.",
    "file-access": "Could expose files if an attacker can reach the vulnerable feature.",
    injection: "Could let untrusted input alter commands or data operations.",
    ssrf: "Could let an attacker make requests to services reachable by this workload.",
    "data-leak": "Could disclose sensitive information through the affected feature.",
    availability: "Could interrupt service when the vulnerable feature handles malicious input.",
    "client-side": "Could affect users of the application through a vulnerable browser-facing feature.",
  }[path.impactCategory ?? ""];
  const subject = sbomSource ? `SBOM source: ${sbomSource}` : workloads.length
    ? `Affected workload: ${workloads[0]}${workloads.length > 1 ? ` and ${workloads.length - 1} more` : ""}`
    : "Affected workload not identified";
  const severity = finding?.severity?.toLowerCase();
  const knownSeverity = severity && ["critical", "high", "medium", "low"].includes(severity) ? severity : null;

  const severityTone = knownSeverity === "critical"
    ? "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300"
    : knownSeverity === "high"
      ? "border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300"
      : "border-outline bg-surface-muted text-ink-secondary";

  return (
    <article className="@container border-b border-outline py-1 last:border-b-0">
      <ReportEvidenceLink localReport={localReport} href={path.href} className="group block rounded-md px-1 py-3 transition hover:bg-surface-muted">
        <div className="flex items-start gap-2">
          <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md border border-outline font-mono text-xs text-ink-secondary">{rank}</span>
          <div className="grid min-w-0 flex-1 gap-x-4 @min-[42rem]:grid-cols-[minmax(0,1fr)_auto]">
            <p className="text-base font-semibold leading-snug text-foreground [overflow-wrap:anywhere]">
              {subject}
            </p>
            <p className="mt-1 text-xs text-ink-secondary [overflow-wrap:anywhere] @min-[42rem]:col-start-1">
              {impact ?? "A vulnerable dependency was found. Its effect on this workload needs review."}
            </p>
            <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-ink-secondary @min-[42rem]:col-start-2 @min-[42rem]:row-start-1 @min-[42rem]:row-span-2 @min-[42rem]:mt-0">
              <span className={`rounded-md border px-2 py-0.5 font-semibold capitalize ${severityTone}`}>{knownSeverity ? `${knownSeverity} severity` : "Severity unavailable"}</span>
              <span className="inline-flex items-center gap-1 font-medium text-emerald-600 dark:text-emerald-400">Review impact <ArrowRight className="h-3 w-3" aria-hidden="true" /></span>
            </div>
          </div>
        </div>
      </ReportEvidenceLink>
      <details className="pb-3 pl-9 text-xs">
        <summary className="cursor-pointer text-ink-secondary">Technical details</summary>
        <p className="mt-2 text-ink-secondary">Dependency evidence; exploitation of this workload is not established.</p>
        <dl className="mt-2 space-y-2">
          <div><dt className="text-ink-secondary">Path priority</dt><dd>{Number.isFinite(path.riskScore) ? path.riskScore.toFixed(1) : "Unavailable"}</dd></div>
          {path.fixedVersion ? <div><dt className="text-ink-secondary">Advisory fix version</dt><dd>{path.fixedVersion}</dd></div> : null}
          {workloads.length > 1 ? <div><dt className="text-ink-secondary">Affected workloads</dt><dd>{workloads.join(", ")}</dd></div> : null}
          {path.affectedServices?.length ? <div><dt className="text-ink-secondary">Affected services</dt><dd>{path.affectedServices.join(", ")}</dd></div> : null}
          {path.nodes.map((node, index) => (
            <div key={`${node.type}-${index}`} className="grid grid-cols-[5rem_minmax(0,1fr)] gap-2">
              <dt className="capitalize text-ink-secondary">{node.type === "cve" ? "Finding" : (node.type === "agent" || node.type === "server") && sbomSourceName(node.label) !== null ? "SBOM source" : node.type}</dt>
              <dd className="text-ink-secondary [overflow-wrap:anywhere]">{node.label}</dd>
            </div>
          ))}
        </dl>
      </details>
    </article>
  );
}
