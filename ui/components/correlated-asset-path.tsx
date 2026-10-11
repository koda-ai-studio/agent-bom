"use client";

import Link from "next/link";
import { useState } from "react";
import { ArrowUpRight } from "lucide-react";
import { buildGraphInvestigationHref } from "@/lib/attack-paths";

/** Select a recorded incident asset, never an unrelated finding or inferred identity. */
export function incidentAssetRoot(
  assets: readonly string[],
  correlationId: string,
  findings: readonly { correlation_id: string; asset_id: string }[],
): string | null {
  return findings.find((finding) => finding.correlation_id === correlationId && assets.includes(finding.asset_id))?.asset_id
    ?? assets[0] ?? null;
}

const PROVIDERS: Record<string, string> = { github: "GitHub", aws: "AWS", azure: "Azure", gcp: "GCP", kubernetes: "Kubernetes", mcp: "MCP", snowflake: "Snowflake", openai: "OpenAI" };

function displayIdentifier(identifier: string): { label: string; kind: string } {
  const parts = identifier.split(":");
  // Presentation only: the complete recorded identifier remains the query key.
  const resource = identifier.includes("@sha256:") ? identifier.split("@sha256:")[0]! : parts.at(-1)!;
  return {
    label: resource.split("/").at(-1) || identifier,
    kind: parts[0] === "cloud_resource"
      ? `${PROVIDERS[parts[1]!] ?? parts[1]} · ${parts[2]?.toUpperCase() ?? "asset"}`
      : parts[0] === "model" ? `${PROVIDERS[parts[1]!] ?? parts[1]} · model`
      : parts.length > 2 ? `${PROVIDERS[parts[0]!] ?? parts[0]} · ${parts[1]}` : PROVIDERS[parts[0]!] ?? parts[0] ?? "Asset",
  };
}

export function CorrelatedAssetPath({ assets, scanId }: { assets: readonly string[]; scanId: string | null }) {
  const [expanded, setExpanded] = useState(false);
  const visible = expanded ? assets : assets.slice(0, 4);
  return (
    <div className="mt-5" aria-label="Correlated asset path">
      <p className="mb-3 text-xs text-[color:var(--text-secondary)]">
        {assets.length} assets in recorded correlation order; this does not establish permissions or exploitation.
      </p>
      <ol className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {visible.map((asset, index) => {
          const { label, kind } = displayIdentifier(asset);
          return (
            <li key={`${index}:${asset}`} className="min-w-0 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-3">
              <div className="mb-2 flex items-center gap-2 text-xs text-[color:var(--text-secondary)]">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-[color:var(--border-subtle)] font-mono">{index + 1}</span>
                <span className="truncate">{kind}</span>
              </div>
              {scanId ? (
                <Link href={buildGraphInvestigationHref({ scanId, rootId: asset })} aria-label={`Inspect ${label} in graph`} title={asset}
                  className="flex items-start gap-2 break-words text-sm font-semibold text-[color:var(--foreground)] hover:underline">
                  <span className="min-w-0 break-all">{label}</span><ArrowUpRight className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
                </Link>
              ) : <span className="break-all text-sm font-semibold text-[color:var(--foreground)]">{label}</span>}
              <details className="mt-3 text-xs text-[color:var(--text-secondary)]">
                <summary className="cursor-pointer">Exact identifier</summary>
                <code className="mt-2 block break-all text-[11px]">{asset}</code>
              </details>
            </li>
          );
        })}
      </ol>
      {assets.length > 4 ? <button type="button" onClick={() => setExpanded((value) => !value)} aria-expanded={expanded}
        className="mt-3 rounded-lg border border-[color:var(--border-subtle)] px-3 py-2 text-xs text-[color:var(--text-secondary)] hover:bg-[color:var(--surface-elevated)]">
        {expanded ? "Show first 4 assets" : `Show all ${assets.length} assets`}
      </button> : null}
    </div>
  );
}
