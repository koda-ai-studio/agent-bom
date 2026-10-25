"use client";

import Link from "next/link";
import { useState, type FormEvent } from "react";
import { Loader2, Plus } from "lucide-react";

import { ApiForbiddenError } from "@/lib/api-errors";
import {
  ADVISORY_SEVERITIES,
  draftToAdvisory,
  emptyDraft,
  emptyProduct,
  fieldLabel,
  operatorAdvisoryApi,
  serverFieldErrors,
  validateAdvisoryDraft,
  type AdvisoryDraft,
  type AdvisorySeverity,
  type FieldErrors,
  type ServerFieldError,
} from "@/lib/operator-advisories";

import { AffectedProductFields } from "./affected-product-fields";
import { Field, inputClass, primaryButtonClass, secondaryButtonClass } from "./advisory-form-fields";

function failureMessage(error: unknown): string {
  if (error instanceof ApiForbiddenError) return "Declaring an advisory needs the admin role.";
  return error instanceof Error && error.message ? error.message : "The advisory could not be declared.";
}

/** Declare an advisory ahead of feed publication (`POST /v1/intel/operator-advisories`). */
export function AdvisoryDeclareForm({ onDeclared }: { onDeclared?: ((advisoryId: string) => void) | undefined }) {
  const [draft, setDraft] = useState<AdvisoryDraft>(emptyDraft);
  const [clientErrors, setClientErrors] = useState<FieldErrors>({});
  const [serverErrors, setServerErrors] = useState<ServerFieldError[]>([]);
  const [failure, setFailure] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [declaredId, setDeclaredId] = useState<string | null>(null);

  const errorFor = (field: string) => clientErrors[field] ?? serverErrors.find(item => item.field === field)?.message;
  const set = (patch: Partial<AdvisoryDraft>) => setDraft(current => ({ ...current, ...patch }));

  async function submit(event: FormEvent) {
    event.preventDefault();
    setServerErrors([]);
    setFailure(null);
    setDeclaredId(null);
    const errors = validateAdvisoryDraft(draft);
    setClientErrors(errors);
    if (Object.keys(errors).length) return;
    setSubmitting(true);
    try {
      const body = draftToAdvisory(draft);
      await operatorAdvisoryApi.declare(body);
      setDeclaredId(body.id);
      setDraft(emptyDraft());
      onDeclared?.(body.id);
    } catch (error) {
      const fields = serverFieldErrors(error);
      if (fields.length) setServerErrors(fields);
      else setFailure(failureMessage(error));
    } finally {
      setSubmitting(false);
    }
  }

  const clientErrorCount = Object.keys(clientErrors).length;
  return (
    <form onSubmit={submit} noValidate aria-label="Declare an emergency advisory" className="min-w-0 space-y-4">
      {serverErrors.length ? (
        <div role="alert" aria-label="The server rejected this advisory" className="rounded-xl border border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] p-3 text-sm">
          <p className="font-medium text-foreground">The server rejected this advisory</p>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-ink-secondary">
            {serverErrors.map((item, index) => <li key={`${item.field}-${index}`}>{`${fieldLabel(item.field)}: ${item.message}`}</li>)}
          </ul>
        </div>
      ) : null}
      {failure ? <p role="alert" className="rounded-xl border border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] p-3 text-sm text-foreground">{failure}</p> : null}
      {clientErrorCount ? <p role="status" className="text-sm text-[color:var(--status-danger)]">{clientErrorCount === 1 ? "Fix 1 field before declaring." : `Fix ${clientErrorCount} fields before declaring.`}</p> : null}
      {declaredId ? (
        <p role="status" className="rounded-xl border border-[color:var(--status-success-border)] bg-[color:var(--status-success-bg)] p-3 text-sm text-foreground">
          Declared {declaredId}. It is matched against stored scans; nothing is rescanned.{" "}
          <Link className="font-medium text-[color:var(--accent)] underline-offset-2 hover:underline" href={`/advisories?id=${encodeURIComponent(declaredId)}`}>See affected assets</Link>
        </p>
      ) : null}

      <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_10rem]">
        <Field id="advisory-id" label="Advisory ID" hint="CVE-2026-12345, GHSA-…, or your own PREFIX-ID." error={errorFor("id")}>
          {props => <input {...props} className={inputClass} value={draft.id} onChange={e => set({ id: e.target.value })} placeholder="CVE-2026-12345" autoComplete="off" />}
        </Field>
        <Field id="advisory-severity" label="Severity" error={errorFor("severity")}>
          {props => (
            <select {...props} className={inputClass} value={draft.severity} onChange={e => set({ severity: e.target.value as AdvisorySeverity })}>
              {ADVISORY_SEVERITIES.map(severity => <option key={severity} value={severity}>{severity}</option>)}
            </select>
          )}
        </Field>
      </div>
      <Field id="advisory-summary" label="Summary" error={errorFor("summary")}>
        {props => <textarea {...props} rows={2} maxLength={1000} className={inputClass} value={draft.summary} onChange={e => set({ summary: e.target.value })} placeholder="What is affected and why it matters" />}
      </Field>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field id="advisory-aliases" label="Aliases" hint="Optional. Comma-separated advisory ids." error={errorFor("aliases")}>
          {props => <input {...props} className={inputClass} value={draft.aliases} onChange={e => set({ aliases: e.target.value })} placeholder="GHSA-xxxx-xxxx-xxxx" autoComplete="off" />}
        </Field>
        <Field id="advisory-published" label="Published at" hint="Optional. Your local time; sent as UTC." error={errorFor("published_at")}>
          {props => <input {...props} type="datetime-local" className={inputClass} value={draft.published_at} onChange={e => set({ published_at: e.target.value })} />}
        </Field>
      </div>
      <Field id="advisory-references" label="References" hint="Optional. One https:// URL per line." error={errorFor("references")}>
        {props => <textarea {...props} rows={2} className={inputClass} value={draft.references} onChange={e => set({ references: e.target.value })} placeholder="https://vendor.example/security/advisory" />}
      </Field>

      <div className="space-y-3">
        {draft.affected.map((product, index) => (
          <AffectedProductFields
            key={index}
            index={index}
            product={product}
            errorFor={errorFor}
            onChange={next => set({ affected: draft.affected.map((item, i) => (i === index ? next : item)) })}
            onRemove={draft.affected.length > 1 ? () => set({ affected: draft.affected.filter((_, i) => i !== index) }) : undefined}
          />
        ))}
        {errorFor("affected") ? <p className="text-xs text-[color:var(--status-danger)]">{errorFor("affected")}</p> : null}
        <button type="button" className={secondaryButtonClass} disabled={draft.affected.length >= 64} onClick={() => set({ affected: [...draft.affected, emptyProduct()] })}>
          <Plus className="h-3.5 w-3.5" aria-hidden /> Add affected product
        </button>
      </div>

      <div className="flex flex-wrap items-center gap-3 border-t border-outline pt-4">
        <button type="submit" className={primaryButtonClass} disabled={submitting}>
          {submitting ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : null}
          Declare advisory
        </button>
        <p className="text-xs text-ink-tertiary">Admin only. Declaring the same id again replaces it.</p>
      </div>
    </form>
  );
}
