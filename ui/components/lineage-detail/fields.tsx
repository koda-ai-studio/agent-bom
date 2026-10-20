import type { ReactNode } from "react";
import Link from "next/link";

export function GenericAssetSection({
  description,
  version,
  attributes,
}: {
  description?: string | undefined;
  version?: string | undefined;
  attributes?: Record<string, unknown> | undefined;
}) {
  return (
    <div className="space-y-3">
      {description && (
        <div className="text-xs text-ink-secondary">{description}</div>
      )}
      {version && <Row label="Version / hash" value={version} />}
      {typeof attributes?.verified === "boolean" && (
        <Row label="Verified" value={attributes.verified ? "yes" : "no"} />
      )}
    </div>
  );
}

export function TagList({
  label,
  tags,
  tone = "zinc",
  linkBuilder,
}: {
  label: string;
  tags: string[];
  tone?: "zinc" | "blue" | undefined;
  linkBuilder?: (tag: string) => string | undefined;
}) {
  const toneClass =
    tone === "blue"
      ? "bg-blue-950 text-blue-300 border-blue-800"
      : "bg-surface-elevated text-ink-secondary border-outline";
  return (
    <div>
      <Label>{label}</Label>
      <div className="flex flex-wrap gap-1 mt-1">
        {tags.map((tag) =>
          linkBuilder ? (
            <Link
              key={tag}
              href={linkBuilder(tag) ?? "#"}
              className={`text-[10px] px-1.5 py-0.5 rounded border transition-colors hover:brightness-110 ${toneClass}`}
            >
              {tag}
            </Link>
          ) : (
            <span
              key={tag}
              className={`text-[10px] px-1.5 py-0.5 rounded border ${toneClass}`}
            >
              {tag}
            </span>
          ),
        )}
      </div>
    </div>
  );
}

export function CodeBlock({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <Label>{label}</Label>
      <div className="text-xs font-mono text-ink-secondary bg-surface rounded px-2 py-1 break-all">
        {value}
      </div>
    </div>
  );
}

export function Label({ children }: { children: ReactNode }) {
  return (
    <div className="text-[10px] uppercase tracking-wider text-ink-tertiary mb-0.5">
      {children}
    </div>
  );
}

export function Row({
  label,
  value,
  className = "",
}: {
  label: string;
  value: string | number;
  className?: string | undefined;
}) {
  return (
    <div className="flex items-center justify-between gap-4 text-xs">
      <span className="text-ink-tertiary">{label}</span>
      <span
        className={`text-ink-secondary font-mono text-right break-all ${className}`}
      >
        {value}
      </span>
    </div>
  );
}

export function shortDate(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

export function formatValue(value: unknown): string {
  if (value == null) return "—";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean")
    return String(value);
  if (Array.isArray(value))
    return value
      .slice(0, 4)
      .map((item) => String(item))
      .join(", ");
  return JSON.stringify(value);
}

export function prettifyKey(value: string): string {
  return value
    .replace(/_/g, " ")
    .replace(/\b\w/g, (match) => match.toUpperCase());
}

