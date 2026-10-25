import { ApiError } from "./api-errors";
import { del, get, post } from "./api-transport";

export type AdvisorySeverity = "critical" | "high" | "medium" | "low";
export const ADVISORY_SEVERITIES: readonly AdvisorySeverity[] = ["critical", "high", "medium", "low"];

export interface AdvisoryRange {
  introduced?: string | undefined;
  fixed?: string | undefined;
  last_affected?: string | undefined;
}

export interface AdvisoryAffectedProduct {
  ecosystem?: string | undefined;
  name?: string | undefined;
  cpe_product?: string | undefined;
  ranges: AdvisoryRange[];
  versions: string[];
}

/** Request body for `POST /v1/intel/operator-advisories` (OperatorAdvisory, extra fields forbidden). */
export interface OperatorAdvisoryInput {
  id: string;
  aliases: string[];
  summary: string;
  severity: AdvisorySeverity;
  published_at?: string | undefined;
  references: string[];
  affected: AdvisoryAffectedProduct[];
}

export interface OperatorAdvisoryRecord extends OperatorAdvisoryInput {
  updated_at?: string | null | undefined;
}

export interface OperatorAdvisoryListResponse {
  advisories: OperatorAdvisoryRecord[];
  provenance: string;
  rematch: { last_run?: string | null; recent_findings?: unknown } | null;
}

const BASE = "/v1/intel/operator-advisories";

export const operatorAdvisoryApi = {
  list: () => get<OperatorAdvisoryListResponse>(BASE, { ttlMs: 0 }),
  declare: (body: OperatorAdvisoryInput) => post<OperatorAdvisoryRecord>(BASE, body),
  retire: (advisoryId: string) => del(`${BASE}/${encodeURIComponent(advisoryId)}`),
};

// ── Draft form state and client-side validation (mirrors OperatorAdvisory) ──

export interface RangeDraft { introduced: string; bound: "fixed" | "last_affected"; boundValue: string }
export interface ProductDraft { identity: "package" | "cpe"; ecosystem: string; name: string; cpe_product: string; ranges: RangeDraft[]; versions: string }
export interface AdvisoryDraft {
  id: string;
  aliases: string;
  summary: string;
  severity: AdvisorySeverity;
  published_at: string;
  references: string;
  affected: ProductDraft[];
}

export const emptyRange = (): RangeDraft => ({ introduced: "", bound: "fixed", boundValue: "" });
export const emptyProduct = (): ProductDraft => ({ identity: "package", ecosystem: "", name: "", cpe_product: "", ranges: [emptyRange()], versions: "" });
export const emptyDraft = (): AdvisoryDraft => ({ id: "", aliases: "", summary: "", severity: "high", published_at: "", references: "", affected: [emptyProduct()] });

const ADVISORY_ID = /^[A-Z][A-Z0-9]{1,15}-[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const CPE_PRODUCT = /^[a-z0-9_.\-~%]{1,64}:[a-z0-9_.\-~%]{1,64}$/;
const VERSION = /^[0-9A-Za-z][0-9A-Za-z.+~_:-]{0,63}$/;
const NAME = /^[A-Za-z0-9@/._+:-]{1,214}$/;

const splitList = (value: string) => value.split(/[\n,]/).map(item => item.trim()).filter(Boolean);

/** Field errors keyed by the request-body path (`affected.0.ranges.1.fixed`), the same keys a 422 maps to. */
export type FieldErrors = Record<string, string>;

function validateProduct(product: ProductDraft, index: number, errors: FieldErrors) {
  const at = `affected.${index}`;
  if (product.identity === "cpe") {
    if (!CPE_PRODUCT.test(product.cpe_product.trim().toLowerCase())) errors[`${at}.cpe_product`] = "cpe_product must be vendor:product, e.g. php:php";
  } else {
    if (!product.ecosystem.trim()) errors[`${at}.ecosystem`] = "Ecosystem is required with a package name";
    else if (product.ecosystem.trim().length > 32) errors[`${at}.ecosystem`] = "Ecosystem must be at most 32 characters";
    if (!NAME.test(product.name.trim())) errors[`${at}.name`] = "Enter a package name (letters, digits, @ / . _ + : -)";
  }
  const versions = splitList(product.versions);
  const bad = versions.find(version => !VERSION.test(version));
  if (bad) errors[`${at}.versions`] = `"${bad}" is not a plain version string`;
  const ranges = product.ranges.filter(range => range.introduced.trim() || range.boundValue.trim());
  product.ranges.forEach((range, rangeIndex) => {
    if (range.introduced.trim() && !VERSION.test(range.introduced.trim())) errors[`${at}.ranges.${rangeIndex}.introduced`] = "Use a plain version string";
    if (range.boundValue.trim() && !VERSION.test(range.boundValue.trim())) errors[`${at}.ranges.${rangeIndex}.${range.bound}`] = "Use a plain version string";
  });
  if (!ranges.length && !versions.length) errors[at] = "Add at least one version range or an exact affected version";
}

export function validateAdvisoryDraft(draft: AdvisoryDraft): FieldErrors {
  const errors: FieldErrors = {};
  if (!ADVISORY_ID.test(draft.id.trim())) errors.id = "Use an id like CVE-2026-12345 or PREFIX-ID (uppercase prefix, a dash, then the id)";
  const aliases = splitList(draft.aliases);
  const badAlias = aliases.find(alias => !ADVISORY_ID.test(alias));
  if (badAlias) errors.aliases = `"${badAlias}" is not an advisory id`;
  else if (aliases.length > 16) errors.aliases = "At most 16 aliases";
  const summary = draft.summary.trim();
  if (!summary) errors.summary = "Summary is required";
  else if (summary.length > 1000) errors.summary = "Summary must be at most 1,000 characters";
  if (!ADVISORY_SEVERITIES.includes(draft.severity)) errors.severity = "Choose a severity";
  if (draft.published_at && Number.isNaN(new Date(draft.published_at).getTime())) errors.published_at = "Enter a valid date and time";
  const references = splitList(draft.references);
  if (references.some(ref => !ref.startsWith("https://") || ref.length > 512)) errors.references = "References must be https:// URLs";
  else if (references.length > 16) errors.references = "At most 16 references";
  if (!draft.affected.length) errors.affected = "Add at least one affected product";
  draft.affected.forEach((product, index) => validateProduct(product, index, errors));
  return errors;
}

function rangeBody(range: RangeDraft): AdvisoryRange | null {
  const introduced = range.introduced.trim();
  const bound = range.boundValue.trim();
  if (!introduced && !bound) return null;
  return { ...(introduced ? { introduced } : {}), ...(bound ? { [range.bound]: bound } : {}) };
}

/** Build the exact request body; empty optional fields are omitted because the model forbids unknown keys only. */
export function draftToAdvisory(draft: AdvisoryDraft): OperatorAdvisoryInput {
  return {
    id: draft.id.trim(),
    aliases: splitList(draft.aliases),
    summary: draft.summary.trim(),
    severity: draft.severity,
    ...(draft.published_at ? { published_at: new Date(draft.published_at).toISOString() } : {}),
    references: splitList(draft.references),
    affected: draft.affected.map(product => ({
      ...(product.identity === "cpe"
        ? { cpe_product: product.cpe_product.trim().toLowerCase() }
        : { ecosystem: product.ecosystem.trim(), name: product.name.trim() }),
      ranges: product.ranges.map(rangeBody).filter((range): range is AdvisoryRange => range !== null),
      versions: splitList(product.versions),
    })),
  };
}

interface ValidationIssue { loc?: unknown; msg?: unknown }

/** One server-reported validation problem, keyed like {@link FieldErrors}. */
export interface ServerFieldError { field: string; message: string }

/** Read FastAPI's 422 `detail` (list of {loc,msg,type}) into body-path keyed messages. */
export function serverFieldErrors(error: unknown): ServerFieldError[] {
  if (!(error instanceof ApiError) || error.status !== 422) return [];
  const body = error.body as { detail?: unknown; error?: { details?: unknown } } | undefined;
  const detail = body?.detail ?? body?.error?.details;
  if (typeof detail === "string") return [{ field: "", message: detail }];
  if (!Array.isArray(detail)) return [{ field: "", message: error.message }];
  return (detail as ValidationIssue[]).map(issue => {
    const loc = Array.isArray(issue.loc) ? issue.loc.map(String) : [];
    const path = loc[0] === "body" ? loc.slice(1) : loc;
    const message = typeof issue.msg === "string" ? issue.msg.replace(/^Value error, /, "") : "Invalid value";
    return { field: path.join("."), message };
  });
}

/** A readable label for a body path, for the error summary list. */
export function fieldLabel(field: string): string {
  if (!field) return "Advisory";
  const parts = field.split(".");
  const labels: string[] = [];
  for (let i = 0; i < parts.length; i += 1) {
    const part = parts[i]!;
    const next = parts[i + 1];
    if (part === "affected" && next !== undefined && /^\d+$/.test(next)) { labels.push(`Affected product ${Number(next) + 1}`); i += 1; continue; }
    if (part === "ranges" && next !== undefined && /^\d+$/.test(next)) { labels.push(`range ${Number(next) + 1}`); i += 1; continue; }
    labels.push(part.replaceAll("_", " "));
  }
  const text = labels.join(" · ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}
