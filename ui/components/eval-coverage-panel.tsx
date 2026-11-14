"use client";

import { EVAL_PURPOSE_LABEL, evalResultSummary, type EvalCoverageEvidence, type EvalSuiteRef } from "@/lib/eval-coverage";

const CHIP = "rounded-md border border-outline bg-surface-elevated px-2 py-0.5 font-mono text-[12px] text-foreground";

function PurposeBadge({ purpose }: { purpose: EvalSuiteRef["purpose"] }) {
  const tone = purpose === "safety" ? "text-accent-mint border-outline-strong" : "text-ink-secondary border-outline";
  return <span className={`rounded-full border px-2 py-0.5 text-[11px] font-semibold ${tone}`}>{EVAL_PURPOSE_LABEL[purpose]}</span>;
}

/** One eval suite: what it is, where it lives, and any results it recorded with their source and date. */
export function EvalSuiteRow({ suite }: { suite: EvalSuiteRef }) {
  return (
    <li className="space-y-1 px-3 py-2 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <PurposeBadge purpose={suite.purpose} />
        <span className="font-medium text-foreground">{suite.name || suite.file_path}</span>
        <span className="text-xs text-ink-tertiary">{suite.harness}</span>
      </div>
      <p className="font-mono text-[12px] text-ink-secondary">{suite.file_path}</p>
      {suite.results.map((result) => (
        <p key={`${result.source_file}:${result.recorded_at}`} className="text-xs text-ink-secondary">
          {evalResultSummary(result)} · {result.source}: <span className="font-mono">{result.source_file}</span>
          {result.recorded_at ? ` · recorded ${result.recorded_at}` : " · no run date recorded"}
        </p>
      ))}
    </li>
  );
}

export function EvalSuiteList({ suites, empty }: { suites: EvalSuiteRef[]; empty: string }) {
  if (suites.length === 0) return <p className="text-sm text-ink-secondary">{empty}</p>;
  return <ul className="divide-y divide-[color:var(--border-subtle)] rounded-lg border border-outline">{suites.map((suite) => <EvalSuiteRow key={`${suite.file_path}:${suite.name}`} suite={suite} />)}</ul>;
}

function Chips({ label, values }: { label: string; values: string[] }) {
  if (values.length === 0) return null;
  return (
    <div className="space-y-1">
      <div className="text-[11px] font-medium uppercase tracking-wide text-ink-tertiary">{label}</div>
      <ul className="flex flex-wrap gap-1.5">{values.map((value) => <li key={value} className={CHIP}>{value}</li>)}</ul>
    </div>
  );
}

/** Evidence for a safety-eval coverage finding: why the agent is high-risk and what was searched. */
export function EvalCoverageEvidencePanel({ evidence }: { evidence: EvalCoverageEvidence }) {
  const { riskSignals, searched } = evidence;
  return (
    <div className="space-y-3" data-testid="eval-coverage-evidence">
      <p className="text-sm text-ink-secondary">
        Searched scope <span className="font-mono text-foreground">{searched.scope || "unknown"}</span> ({searched.filesExamined} candidate eval {searched.filesExamined === 1 ? "file" : "files"} read): {searched.statement}.
      </p>
      <Chips label="Write / exec tools" values={riskSignals.writeExecTools} />
      <Chips label="Credentials" values={riskSignals.credentials} />
      <Chips label="Data access" values={riskSignals.dataAccess} />
      <div className="space-y-1">
        <div className="text-[11px] font-medium uppercase tracking-wide text-ink-tertiary">Evals linked to this agent</div>
        <EvalSuiteList suites={evidence.linked} empty="No eval in the scanned files targets this agent." />
      </div>
      {evidence.modelLevelSafety.length > 0 ? (
        <div className="space-y-1">
          <div className="text-[11px] font-medium uppercase tracking-wide text-ink-tertiary">Safety evals on this agent&apos;s model (do not exercise its tools)</div>
          <EvalSuiteList suites={evidence.modelLevelSafety} empty="" />
        </div>
      ) : null}
      {evidence.unlinkedSafety.length > 0 ? (
        <div className="space-y-1">
          <div className="text-[11px] font-medium uppercase tracking-wide text-ink-tertiary">Safety evals that could not be linked to an agent</div>
          <EvalSuiteList suites={evidence.unlinkedSafety} empty="" />
        </div>
      ) : null}
    </div>
  );
}
