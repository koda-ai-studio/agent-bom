"use client";

import type { ReactNode } from "react";
import { Sparkles } from "lucide-react";

import type { components } from "@/lib/api-schema.generated";

type Schemas = components["schemas"];

/** Everything here is advisory. It sits beside scanner severity and never replaces it. */
export type AIAssessment = Pick<Schemas["AIAssessmentRow"], "finding_id" | "verdict" | "confidence" | "rationale" | "advisory"> & {
  guard_applied?: boolean | null | undefined;
  protected_reasons?: string[] | null | undefined;
  scan_id?: string | null | undefined;
  advice_covers_occurrences?: number | null | undefined;
  group_occurrences?: number | null | undefined;
  provenance: Pick<Schemas["AIAssessmentProvenance"], "model"> & {
    model_digest?: string | null | undefined;
    prompt_version?: string | null | undefined;
    dataset_version?: string | null | undefined;
    generated_at?: string | null | undefined;
  };
};

export type AIStatus = Pick<Schemas["AIStatusResponse"], "state" | "reason" | "advisory_only"> & {
  schema_version?: string;
  last_run?: (Pick<Schemas["AITriageRun"], "scan_id" | "created_at" | "status"> & Partial<Pick<Schemas["AITriageRun"], "reason" | "model" | "triage_scope">>) | null | undefined;
};

const VERDICTS: Record<string, string> = {
  likely_false_positive: "Likely false positive",
  confirmed: "Confirmed",
  needs_review: "Needs review",
};
const PROTECTED: Record<string, string> = {
  kev: "known-exploited (KEV)",
  malicious_package: "a malicious package",
  reachable_critical: "reachable and critical",
};

export function aiVerdictLabel(verdict: string): string {
  return VERDICTS[verdict] ?? "Needs review";
}

function titleCase(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function shortDate(value: string | null | undefined): string | null {
  return value ? value.slice(0, 10) : null;
}

export function AIAdviceBadge({ assessment }: { assessment: AIAssessment | null | undefined }) {
  if (!assessment) return null;
  const label = aiVerdictLabel(assessment.verdict);
  return (
    <span
      aria-label={`AI advice: ${label}, ${assessment.confidence} confidence`}
      title={`AI advice: ${label}.${assessment.group_occurrences ? ` Covers one of ${assessment.group_occurrences} occurrences.` : ""} Scanner severity is unchanged.`}
      className="inline-flex shrink-0 items-center gap-1 rounded border border-dashed border-outline px-1.5 py-0.5 text-[11px] leading-4 text-ink-secondary"
    >
      <Sparkles aria-hidden="true" className="h-3 w-3" />
      AI: {label}{assessment.group_occurrences ? ` (1 of ${assessment.group_occurrences})` : ""}
    </span>
  );
}

function SectionShell({ label, children, note }: { label: string; children: ReactNode; note: string }) {
  return (
    <section aria-label={label} className="rounded-lg border border-dashed border-outline bg-surface-muted p-3">
      <h4 className="flex items-center gap-1.5 text-xs font-medium uppercase tracking-wide text-ink-secondary">
        <Sparkles aria-hidden="true" className="h-3.5 w-3.5" />
        AI advice
      </h4>
      <div className="mt-2 space-y-2 text-sm text-foreground">{children}</div>
      <p className="mt-2 text-xs text-ink-tertiary">{note}</p>
    </section>
  );
}

export function AIAdviceSection({ assessment }: { assessment: AIAssessment | null | undefined }) {
  if (!assessment) return null;
  const { provenance } = assessment;
  const reasons = (assessment.protected_reasons ?? []).map((reason) => PROTECTED[reason] ?? reason).join(", ");
  const facts = [provenance.model, shortDate(provenance.generated_at), provenance.prompt_version].filter(Boolean).join(" · ");
  return (
    <SectionShell label="AI advice" note="A model's opinion for a person to weigh. It does not change scanner severity, status or gates.">
      <p className="font-medium">
        {aiVerdictLabel(assessment.verdict)}
        <span className="ml-2 font-normal text-ink-secondary">{titleCase(assessment.confidence)} confidence</span>
      </p>
      <p className="max-w-prose whitespace-pre-wrap break-words leading-6 text-ink-secondary">{assessment.rationale}</p>
      {assessment.group_occurrences ? <p className="text-xs text-ink-secondary">This advice covers one of {assessment.group_occurrences} occurrences. Open an occurrence to check the others.</p> : null}
      {assessment.guard_applied && reasons ? <p className="text-xs text-ink-secondary">This finding is {reasons}, so a model cannot dismiss it.</p> : null}
      <p className="break-words text-xs text-ink-tertiary" title={provenance.model_digest ?? undefined}>{facts}</p>
    </SectionShell>
  );
}

function statusSentence(status: AIStatus): string {
  const run = status.last_run;
  if (status.state === "off") return status.reason || "AI advice is off.";
  if (run && ["failed", "unavailable", "blocked"].includes(run.status)) {
    return `The last AI run failed${run.reason ? `: ${run.reason}` : ""}. Scanner findings are unaffected.`;
  }
  if (!run) return "AI advice is on. No scan has requested it yet.";
  const scope = (run.triage_scope ?? {}) as { findings_total?: number; findings_offered?: number };
  const coverage = scope.findings_offered !== undefined && scope.findings_total !== undefined ? ` It assessed the riskiest ${scope.findings_offered} of ${scope.findings_total} findings.` : "";
  const partial = run.status === "partial" ? ` Some assessments are missing${run.reason ? `: ${run.reason}` : ""}.` : "";
  return `AI advice is on${run.model ? ` (${run.model})` : ""}.${coverage}${partial} Advice never changes scanner severity.`;
}

export function AIStatusNotice({ status }: { status: AIStatus | null | undefined }) {
  if (!status) return null;
  return (
    <p role="status" className="flex items-start gap-1.5 text-xs text-ink-secondary">
      <Sparkles aria-hidden="true" className="mt-0.5 h-3 w-3 shrink-0" />
      <span className="break-words">{statusSentence(status)}</span>
    </p>
  );
}
