"use client";

import Link from "next/link";
import { FolderSearch, Network, Upload } from "lucide-react";
import type { ScanResult } from "@/lib/api";
import { useAuthState } from "@/components/auth-provider";
import { LocalReportImport } from "@/components/local-report-import";
import { CopyTextButton } from "@/components/connections/wizard-controls";

const PROJECT_COMMAND = 'agent-bom scan . --no-discover --context-graph -f json -o report.json --push-url "${AGENT_BOM_PUSH_URL:?Set the control-plane ingestion URL}"';
const FIRST_RUN = "https://koda-ai-studio.github.io/agent-bom/getting-started/quickstart/";
const INVESTIGATION = [
  { title: "Review inventory", detail: "Confirm the source, assets and collection gaps. Keep the scan ID as your evidence scope." },
  { title: "Understand impact", detail: "Open a finding in Investigation. Follow its component, workflow and conditional reach; check what remains unverified." },
  { title: "Fix and verify", detail: "Review the proposed change, rescan the same target and compare evidence before calling it fixed." },
];

export function FirstScanGuide({ onImport }: { onImport: (data: ScanResult) => void }) {
  const { loading, hasCapability } = useAuthState();
  return (
    <section aria-labelledby="first-scan-title" className="rounded-xl border border-outline bg-surface p-4 sm:p-6">
      <p className="text-xs font-medium uppercase tracking-wider text-emerald-800 dark:text-emerald-300">Your first source → your first investigation</p>
      <h2 id="first-scan-title" className="mt-2 text-2xl font-semibold tracking-tight">Start with evidence</h2>
      <p className="mt-2 max-w-3xl text-sm leading-6 text-ink-secondary">Bring one project or connected source. See what was discovered, investigate a finding and decide what to fix next.</p>
      <p className="mt-2 text-sm text-ink-secondary">
        No scans or findings are recorded in the current overview window. This is not a clean security verdict.
      </p>
      <div className="mt-5 grid gap-4 xl:grid-cols-3">
        <div className="min-w-0 space-y-3 rounded-lg border border-outline p-4">
          <FolderSearch className="h-5 w-5 text-emerald-700 dark:text-emerald-300" aria-hidden="true" />
          <h3 className="font-medium">Scan in this control plane</h3>
          <p className="text-sm leading-6 text-ink-secondary">Choose a repository, image or mounted project in the scan form. The browser does not scan your workstation automatically.</p>
          {loading ? <p role="status" className="text-sm text-ink-secondary">Checking scan access…</p> : hasCapability("scan.run") ? (
            <Link href="/scan" className="inline-flex rounded-lg bg-emerald-700 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-600">Choose a scan target</Link>
          ) : <p className="text-sm text-ink-secondary">Ask an administrator for scan access, or preview a saved report below.</p>}
          <p className="text-xs leading-5 text-ink-secondary">Result: a retained scan with findings and graph evidence where collected. Check coverage before interpreting counts.</p>
        </div>
        <div className="min-w-0 space-y-3 rounded-lg border border-outline p-4">
          <Network className="h-5 w-5 text-emerald-700 dark:text-emerald-300" aria-hidden="true" />
          <h3 className="font-medium">Connect cloud and AI infrastructure</h3>
          <p className="text-sm leading-6 text-ink-secondary">Choose a supported provider, review the read-only permissions and verify access before starting collection.</p>
          <Link href="/connections?tab=connect" className="inline-flex rounded-lg border border-outline px-4 py-2 text-sm font-medium hover:bg-surface-muted">Connect a source</Link>
          <p className="text-xs leading-5 text-ink-secondary">Result: inventory and posture evidence for the selected scope. Verification alone does not collect assets; run the first scan.</p>
          <Link href="/connections?tab=sources" className="inline-block text-sm text-emerald-800 dark:text-emerald-300">Review connected sources →</Link>
        </div>
        <div className="min-w-0 space-y-3 rounded-lg border border-outline p-4">
          <Upload className="h-5 w-5 text-emerald-700 dark:text-emerald-300" aria-hidden="true" />
          <h3 className="font-medium">Send a local project</h3>
          <p className="text-sm leading-6 text-ink-secondary">Run from your repository with the installed CLI. Only the selected project is discovered; advisory lookup uses the network.</p>
          <details className="rounded-lg border border-outline p-3">
            <summary className="cursor-pointer text-sm font-medium">Show project command</summary>
            <div className="mt-3 space-y-3">
              <p className="text-xs leading-5 text-ink-secondary">Set AGENT_BOM_PUSH_URL to this deployment’s /v1/results/push endpoint, including any deployment prefix. Supply AGENT_BOM_PUSH_API_KEY through your secret manager with permission to push results.</p>
              <code className="block whitespace-pre-wrap break-words rounded-lg bg-surface-muted p-3 text-xs leading-5 [overflow-wrap:anywhere]">{PROJECT_COMMAND}</code>
              <CopyTextButton text={PROJECT_COMMAND} label="Copy project command" />
            </div>
          </details>
          <p className="text-xs leading-5 text-ink-secondary">Result: report.json locally and retained evidence after a successful push. Confirm the push succeeded, then inspect the stored scan in Findings. A failed push is not activation.</p>
        </div>
      </div>
      <ol aria-label="Your first investigation" className="mt-5 grid gap-4 rounded-lg bg-surface-muted p-4 md:grid-cols-3">
        {INVESTIGATION.map((step, index) => <li key={step.title} className="min-w-0">
          <h3 className="text-sm font-medium"><span className="mr-2 text-emerald-800 dark:text-emerald-300">0{index + 1}</span>{step.title}</h3>
          <p className="mt-2 text-xs leading-5 text-ink-secondary">{step.detail}</p>
        </li>)}
      </ol>
      <p className="mt-4 text-sm text-ink-secondary">Trying Agent-Bom before connecting a source? Preview a saved or sample report below. <a href={FIRST_RUN} target="_blank" rel="noreferrer" className="font-medium underline">Installation and first-run guide</a></p>
      <details className="mt-3 rounded-lg border border-outline p-3">
        <summary className="cursor-pointer text-sm font-medium">Preview a saved or sample report</summary>
        <LocalReportImport onImport={onImport} />
      </details>
    </section>
  );
}
