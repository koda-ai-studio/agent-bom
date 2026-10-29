"use client";

import {
formatDate,
type ApiKeyRecord,
type AuthPolicyResponse
} from "@/lib/api";



export function formatSeconds(value: number): string {
  if (value < 60) return `${value}s`;
  if (value < 3600) return `${Math.floor(value / 60)}m`;
  if (value < 86400) return `${Math.floor(value / 3600)}h`;
  return `${Math.floor(value / 86400)}d`;
}



export function toIsoOrNull(value: string): string | null {
  if (!value.trim()) return null;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw new Error("Expiration must be a valid date/time");
  }
  return parsed.toISOString();
}



export function keyStateTone(state: ApiKeyRecord["state"]): string {
  switch (state) {
    case "active":
      return "border-emerald-500/30 dark:border-emerald-900/60 bg-emerald-500/10 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-300";
    case "rotation_overlap":
      return "border-sky-500/30 dark:border-sky-900/60 bg-sky-500/10 dark:bg-sky-950/30 text-sky-700 dark:text-sky-300";
    case "rotated":
      return "border-amber-500/30 dark:border-amber-900/60 bg-amber-500/10 dark:bg-amber-950/30 text-amber-700 dark:text-amber-300";
    case "revoked":
      return "border-red-500/30 dark:border-red-900/60 bg-red-500/10 dark:bg-red-950/30 text-red-700 dark:text-red-300";
    case "expired":
    default:
      return "border-[var(--border-subtle)] bg-[var(--surface)] text-[var(--text-secondary)]";
  }
}



export function stateLabel(state: ApiKeyRecord["state"]): string {
  switch (state) {
    case "rotation_overlap":
      return "Rotation overlap";
    default:
      return state.charAt(0).toUpperCase() + state.slice(1);
  }
}



export type TenantQuotaUsageEntry =
  AuthPolicyResponse["tenant_quota_runtime"]["usage"][keyof AuthPolicyResponse["tenant_quota_runtime"]["usage"]];


export type QuotaKey = keyof AuthPolicyResponse["tenant_quota_runtime"]["usage"];


export type QuotaCard = {
  field: QuotaKey;
  label: string;
  value: TenantQuotaUsageEntry;
};


export type QuotaForm = Record<QuotaKey, string>;



export function isSessionKey(key: ApiKeyRecord): boolean {
  return key.name.startsWith("saml:") || key.scopes.includes("saml-session");
}



export function formatModeLabel(value: string): string {
  const acronyms: Record<string, string> = {
    oidc: "OIDC",
    api: "API",
    ui: "UI",
    saml: "SAML",
    sso: "SSO",
  };
  return value
    .split("_")
    .filter(Boolean)
    .map((segment) => acronyms[segment] ?? (segment.charAt(0).toUpperCase() + segment.slice(1)))
    .join(" ");
}



export function modeTone(value: string): string {
  switch (value) {
    case "reverse_proxy_oidc":
    case "trusted_proxy":
      return "border-emerald-500/30 dark:border-emerald-900/60 bg-emerald-500/10 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-300";
    case "oidc_bearer":
    case "saml_sso":
      return "border-sky-500/30 dark:border-sky-900/60 bg-sky-500/10 dark:bg-sky-950/30 text-sky-700 dark:text-sky-300";
    case "session_api_key":
    case "api_key":
      return "border-amber-500/30 dark:border-amber-900/60 bg-amber-500/10 dark:bg-amber-950/30 text-amber-700 dark:text-amber-300";
    case "no_auth":
    default:
      return "border-[var(--border-subtle)] bg-[var(--surface)] text-[var(--text-secondary)]";
  }
}



export function quotaInputValue(value: number | null | undefined): string {
  return value == null ? "" : String(value);
}



export function quotaStatusTone(status: string): string {
  switch (status) {
    case "ok":
      return "border-emerald-500/30 dark:border-emerald-900/60 bg-emerald-500/10 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-300";
    case "near_limit":
      return "border-amber-500/30 dark:border-amber-900/60 bg-amber-500/10 dark:bg-amber-950/30 text-amber-700 dark:text-amber-300";
    case "at_limit":
      return "border-red-500/30 dark:border-red-900/60 bg-red-500/10 dark:bg-red-950/30 text-red-700 dark:text-red-300";
    case "unlimited":
    default:
      return "border-[var(--border-subtle)] bg-[var(--surface)] text-[var(--text-secondary)]";
  }
}



export function quotaStatusLabel(status: string): string {
  return status.replaceAll("_", " ");
}



export function formatStatusLabel(value: string): string {
  return value.replaceAll("_", " ");
}



export function formatBoundaryList(values: string[]): string {
  return values.map(formatStatusLabel).join(" · ");
}



export function formatCadence(rotationDays: number | null, maxAgeDays: number | null): string | null {
  const parts = [];
  if (rotationDays != null) parts.push(`rotate ${rotationDays}d`);
  if (maxAgeDays != null) parts.push(`max ${maxAgeDays}d`);
  return parts.length ? parts.join(" · ") : null;
}



export function formatRotationDetail(posture: {
  rotation_status: string;
  rotation_method: string;
  last_rotated: string | null;
  age_days: number | null;
  rotation_days: number | null;
  max_age_days: number | null;
}): string {
  return [
    formatStatusLabel(posture.rotation_status),
    posture.last_rotated ? `rotated ${formatDate(posture.last_rotated)}` : "timestamp unset",
    posture.age_days != null ? `${posture.age_days}d old` : null,
    formatCadence(posture.rotation_days, posture.max_age_days),
    posture.rotation_method.replaceAll("_", " "),
  ]
    .filter(Boolean)
    .join(" · ");
}



export function formatRateLimitRotationDetail(rateLimit: AuthPolicyResponse["rate_limit_key"]): string {
  return [
    formatStatusLabel(rateLimit.status),
    rateLimit.last_rotated ? `rotated ${formatDate(rateLimit.last_rotated)}` : "timestamp unset",
    rateLimit.age_days != null ? `${rateLimit.age_days}d old` : null,
    formatCadence(rateLimit.rotation_days ?? null, rateLimit.max_age_days ?? null),
    rateLimit.fallback_source ? `fallback ${rateLimit.fallback_source}` : null,
  ]
    .filter(Boolean)
    .join(" · ");
}
