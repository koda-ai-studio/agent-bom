"use client";

import { CopyTextButton } from "@/components/connections/wizard-controls";

const LOCAL_COMMAND = "uvx agent-bom scan . --no-discover --context-graph -f json -o report.json";

export function PersonalScanStart({ onPreview }: { onPreview: () => void }) {
  return <div className="mt-5 space-y-3 rounded-lg border border-outline bg-surface-muted p-4">
    <h3 className="font-medium">Scan a project on your machine</h3>
    <p className="max-w-3xl text-sm leading-6 text-ink-secondary">With uv installed, run this from your project. No account, shared database or compliance setup is required. Advisory lookups use the network; use the first-run guide for offline scans.</p>
    <code aria-label="Local scan command" className="block whitespace-pre-wrap break-words rounded-lg bg-surface p-3 text-xs leading-5 [overflow-wrap:anywhere]">{LOCAL_COMMAND}</code>
    <div className="flex flex-wrap gap-2">
      <CopyTextButton text={LOCAL_COMMAND} label="Copy local scan command" />
      <button type="button" onClick={onPreview} className="rounded-lg bg-[color:var(--accent)] px-4 py-2 text-sm font-medium text-[color:var(--accent-contrast)] hover:bg-[color:var(--accent-strong)]">Open a report</button>
    </div>
    <p className="text-sm leading-6 text-ink-secondary">Result: report.json on your machine. Preview it below, review coverage, investigate a finding, then fix and rescan the same project. Previewing does not upload the report to the control plane.</p>
  </div>;
}
