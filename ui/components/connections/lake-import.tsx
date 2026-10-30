"use client";

import Link from "next/link";
import { useState } from "react";
import { ArrowRight, Database, FileCheck2, Network } from "lucide-react";
import { Card } from "@/components/card";
import { CopyTextButton } from "@/components/connections/wizard-controls";

const GUIDE = "https://koda-ai-studio.github.io/agent-bom/deployment/lake-evidence-ingestion/";
const DEPLOY = "https://koda-ai-studio.github.io/agent-bom/deployment/docker/";

function Command({ title, text }: { title: string; text: string }) {
  return <div className="min-w-0 rounded-lg border border-outline bg-surface-muted p-3">
    <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
      <span className="text-xs font-medium">{title}</span><CopyTextButton text={text} label={`Copy ${title.toLowerCase()}`} />
    </div>
    <pre className="overflow-x-auto whitespace-pre-wrap break-words text-xs leading-6"><code>{text}</code></pre>
  </div>;
}

export function LakeImportWorkflow() {
  const [sample, setSample] = useState(true);
  const source = sample ? "lake-pilot/findings.json" : "findings.json";
  const mapping = sample ? "lake-pilot/mapping.json" : "mapping.json";
  const preview = `agent-bom ingest lake ${source} --mapping ${mapping} -o ${sample ? "lake-pilot/" : ""}preview-report.json`;
  const push = `agent-bom ingest lake ${source} --mapping ${mapping} -o ${sample ? "lake-pilot/" : ""}pushed-report.json --push "$AGENT_BOM_CONTROL_PLANE_URL"`;

  return <section className="space-y-5" aria-labelledby="lake-import-title">
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div className="max-w-3xl">
        <p className="text-xs font-medium uppercase tracking-wider text-ink-tertiary">Existing evidence · Customer-controlled import</p>
        <h2 id="lake-import-title" className="mt-2 text-2xl font-semibold">From lake export to an investigation</h2>
        <p className="mt-2 text-sm leading-6 text-ink-secondary">Bring selected finding observations into your control plane. Keep account, region, observation time and source receipts alongside the findings and graph.</p>
      </div>
      <a href={GUIDE} className="text-sm font-medium underline" target="_blank" rel="noreferrer">Mapping and S3 guide</a>
    </div>

    <div className="flex flex-wrap gap-2" role="group" aria-label="Import starting point">
      <button type="button" aria-pressed={sample} onClick={() => setSample(true)} className={`rounded-lg border px-4 py-2 text-sm ${sample ? "border-emerald-500 bg-emerald-500/10" : "border-outline"}`}>Try a sample</button>
      <button type="button" aria-pressed={!sample} onClick={() => setSample(false)} className={`rounded-lg border px-4 py-2 text-sm ${!sample ? "border-emerald-500 bg-emerald-500/10" : "border-outline"}`}>Use your export</button>
    </div>

    {sample ? <p className="rounded-lg border border-amber-500/40 bg-amber-500/5 p-3 text-sm text-amber-900 dark:text-amber-200">Synthetic sample for an isolated pilot. Its two labelled findings demonstrate a shared asset; they do not describe a real cloud account.</p> : <p className="text-sm leading-6 text-ink-secondary">Export 1–1,000 selected finding records as JSON or NDJSON. Select the intended account and resource occurrences in your query, then map the columns. Provider labels record provenance; they do not run warehouse queries.</p>}

    <ol className="grid gap-4 lg:grid-cols-3" aria-label="Lake activation steps">
      <Card as="li" className="min-w-0 space-y-4">
        <Database className="h-5 w-5 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
        <h3 className="font-semibold">1. Prepare a snapshot</h3>
        <p className="text-sm leading-6 text-ink-secondary">{sample ? "Create a private sample directory from the installed CLI. No repository checkout or cloud credentials are needed." : "Keep your export and mapping on the machine running the CLI. Unmapped fields are omitted; numeric severity values need an explicit mapping."}</p>
        {sample ? <Command title="Sample setup" text="agent-bom ingest lake-sample --directory lake-pilot" /> : <a href={GUIDE + "#existing-columns-or-explicit-normalization"} className="inline-flex text-sm underline" target="_blank" rel="noreferrer">Review required fields and mapping example</a>}
      </Card>
      <Card as="li" className="min-w-0 space-y-4">
        <FileCheck2 className="h-5 w-5 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
        <h3 className="font-semibold">2. Inspect the local report</h3>
        <p className="text-sm leading-6 text-ink-secondary">Validate the full snapshot before sending it. Inspect findings, lake_receipt and coverage_warnings in the saved report. Existing files are never overwritten.</p>
        <Command title="Local preview" text={preview} />
      </Card>
      <Card as="li" className="min-w-0 space-y-4">
        <Network className="h-5 w-5 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
        <h3 className="font-semibold">3. Import and investigate</h3>
        <p className="text-sm leading-6 text-ink-secondary">Set AGENT_BOM_CONTROL_PLANE_URL to your API endpoint, including any deployment prefix. Supply AGENT_BOM_PUSH_API_KEY through your secret manager with permission to push scan results.</p>
        <Command title="Authenticated import" text={push} />
        <p className="text-xs leading-5 text-ink-secondary">Use a new output path on retry. An identical snapshot keeps the same replay key. A failed push retains the report.</p>
      </Card>
    </ol>

    <Card className="space-y-3">
      <h3 className="font-semibold">What successful activation looks like</h3>
      <p className="text-sm leading-6 text-ink-secondary">The CLI prints the retained report, stored scan ID and server-recorded graph counts. Follow its scoped Findings and Investigation links, then check the account, region and observation time on the imported asset. A missing graph receipt stays unconfirmed.</p>
      <p className="text-sm leading-6 text-ink-secondary">Imported records do not establish collection completeness, current configuration, execution, exploitability or control attestation. Add direct collection when those questions need current evidence.</p>
      <div className="flex flex-wrap gap-4 text-sm">
        <Link href="/findings" className="inline-flex items-center gap-1 underline">Open findings <ArrowRight className="h-3 w-3" /></Link>
        <a href={DEPLOY} target="_blank" rel="noreferrer" className="underline">Set up a self-hosted control plane</a>
      </div>
    </Card>
  </section>;
}
