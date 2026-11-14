/**
 * Safety-eval coverage evidence read from an EVAL_COVERAGE_GAP finding.
 *
 * The scanner records what it searched; the UI repeats that wording and never
 * turns "no safety eval found in the scanned files" into "never evaluated".
 */

export const EVAL_COVERAGE_GAP = "EVAL_COVERAGE_GAP";

export type EvalPurpose = "safety" | "quality" | "unknown";

export interface EvalResultEvidence {
  source: string;
  source_file: string;
  recorded_at: string;
  passed: number;
  failed: number;
  errors: number;
  pass_rate: number | null;
}

export interface EvalSuiteRef {
  harness: string;
  name: string;
  file_path: string;
  purpose: EvalPurpose;
  results: EvalResultEvidence[];
}

export interface EvalCoverageEvidence {
  riskSignals: { writeExecTools: string[]; credentials: string[]; dataAccess: string[] };
  searched: { scope: string; filesExamined: number; statement: string };
  linked: EvalSuiteRef[];
  modelLevelSafety: EvalSuiteRef[];
  unlinkedSafety: EvalSuiteRef[];
}

type Rec = Record<string, unknown>;

const isRec = (value: unknown): value is Rec => typeof value === "object" && value !== null && !Array.isArray(value);
const str = (value: unknown): string => (typeof value === "string" ? value : "");
const num = (value: unknown): number => (typeof value === "number" && Number.isFinite(value) ? value : 0);
const strings = (value: unknown): string[] => (Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item !== "") : []);

function purpose(value: unknown): EvalPurpose {
  return value === "safety" || value === "quality" ? value : "unknown";
}

export function parseEvalResult(raw: unknown): EvalResultEvidence | null {
  if (!isRec(raw)) return null;
  const rate = raw.pass_rate;
  return {
    source: str(raw.source),
    source_file: str(raw.source_file),
    recorded_at: str(raw.recorded_at),
    passed: num(raw.passed),
    failed: num(raw.failed),
    errors: num(raw.errors),
    pass_rate: typeof rate === "number" && Number.isFinite(rate) ? rate : null,
  };
}

export function parseEvalSuite(raw: unknown): EvalSuiteRef | null {
  if (!isRec(raw)) return null;
  const results = Array.isArray(raw.results) ? raw.results.map(parseEvalResult).filter((item): item is EvalResultEvidence => item !== null) : [];
  return { harness: str(raw.harness), name: str(raw.name), file_path: str(raw.file_path), purpose: purpose(raw.purpose), results };
}

function suites(value: unknown): EvalSuiteRef[] {
  return Array.isArray(value) ? value.map(parseEvalSuite).filter((item): item is EvalSuiteRef => item !== null) : [];
}

/** Parse the evidence block of an EVAL_COVERAGE_GAP finding; null for any other finding. */
export function parseEvalCoverageEvidence(findingType: string | undefined, evidence: unknown): EvalCoverageEvidence | null {
  if (findingType !== EVAL_COVERAGE_GAP || !isRec(evidence)) return null;
  const signals = isRec(evidence.risk_signals) ? evidence.risk_signals : {};
  const searched = isRec(evidence.searched) ? evidence.searched : {};
  return {
    riskSignals: {
      writeExecTools: strings(signals.write_exec_tools),
      credentials: strings(signals.credentials),
      dataAccess: strings(signals.data_access),
    },
    searched: {
      scope: str(searched.scope),
      filesExamined: num(searched.files_examined),
      statement: str(searched.statement) || "no safety eval found in the scanned project files",
    },
    linked: suites(evidence.linked_evals),
    modelLevelSafety: suites(evidence.model_level_safety_evals),
    unlinkedSafety: suites(evidence.unlinked_safety_evals),
  };
}

/** "46 of 50 passed (92%)", or a plain count when no rate could be computed. */
export function evalResultSummary(result: EvalResultEvidence): string {
  const total = result.passed + result.failed + result.errors;
  if (total === 0 || result.pass_rate === null) return "No test outcomes recorded";
  return `${result.passed} of ${total} passed (${Math.round(result.pass_rate * 100)}%)`;
}

export const EVAL_PURPOSE_LABEL: Record<EvalPurpose, string> = {
  safety: "Safety / red team",
  quality: "Quality",
  unknown: "Purpose unknown",
};
