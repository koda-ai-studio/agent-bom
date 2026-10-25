"use client";

import type { ReactNode } from "react";

export const inputClass =
  "w-full min-w-0 rounded-lg border border-outline bg-surface-muted px-3 py-2 text-sm text-foreground placeholder:text-ink-tertiary focus:border-[color:var(--accent-border)] focus:outline-none aria-[invalid=true]:border-[color:var(--status-danger-border)]";

export const secondaryButtonClass =
  "inline-flex items-center justify-center gap-1.5 rounded-lg border border-outline bg-surface-muted px-3 py-1.5 text-xs font-medium text-ink-secondary transition hover:border-outline-strong hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50";

export const primaryButtonClass =
  "inline-flex items-center justify-center gap-2 rounded-lg border border-[color:var(--accent-border)] bg-[color:var(--accent-soft)] px-4 py-2 text-sm font-medium text-[color:var(--accent)] transition hover:bg-[color:var(--accent-soft-hover)] disabled:cursor-not-allowed disabled:opacity-50";

export function FieldError({ id, message }: { id: string; message: string | undefined }) {
  if (!message) return null;
  return <p id={id} className="mt-1 text-xs text-[color:var(--status-danger)]">{message}</p>;
}

/** A labelled control with its hint and the client or server error for the same body path. */
export function Field({
  id,
  label,
  hint,
  error,
  children,
  className = "",
}: {
  id: string;
  label: string;
  hint?: string | undefined;
  error?: string | undefined;
  children: (props: { id: string; "aria-invalid": boolean; "aria-describedby": string | undefined }) => ReactNode;
  className?: string;
}) {
  const describedBy = [hint ? `${id}-hint` : "", error ? `${id}-error` : ""].filter(Boolean).join(" ") || undefined;
  return (
    <div className={`min-w-0 ${className}`}>
      <label htmlFor={id} className="mb-1 block text-xs font-medium text-ink-secondary">{label}</label>
      {children({ id, "aria-invalid": Boolean(error), "aria-describedby": describedBy })}
      {hint ? <p id={`${id}-hint`} className="mt-1 text-[11px] text-ink-tertiary">{hint}</p> : null}
      <FieldError id={`${id}-error`} message={error} />
    </div>
  );
}
