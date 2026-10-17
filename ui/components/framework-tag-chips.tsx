"use client";

import { useState } from "react";

import type { AtlasMappingReceipt } from "@/lib/api-types";

/** Keep historical tag lists inspectable and qualify source-backed associations. */
const DEFAULT_VISIBLE = 6;

/**
 * Tones are spelled out as whole class strings on purpose. The previous
 * `bg-${color}-950` form in a graph renderer cannot be seen by Tailwind's
 * static extractor, so those classes were never generated and the chips
 * rendered with no background or border at all.
 */
type Tone = "owasp" | "mcp" | "atlas";

const TONE_CLASS: Record<Tone, string> = {
  owasp: "bg-purple-50 border-purple-300 text-purple-800 dark:bg-purple-950 dark:border-purple-800 dark:text-purple-300",
  mcp: "bg-[color:var(--severity-medium-bg)] border-[color:var(--severity-medium-border)] text-[color:var(--severity-medium)]",
  atlas: "bg-cyan-50 border-cyan-300 text-cyan-800 dark:bg-cyan-950 dark:border-cyan-800 dark:text-cyan-300",
};

const TONE_NAME_CLASS: Record<Tone, string> = {
  owasp: "text-purple-800 dark:text-purple-300",
  mcp: "text-amber-600",
  atlas: "text-cyan-800 dark:text-cyan-300",
};

export function FrameworkTagChips({
  tags,
  catalog,
  tone,
  showNames = false,
  visible = DEFAULT_VISIBLE,
  mappingEvidence,
}: {
  tags: string[] | undefined;
  catalog: Record<string, string>;
  tone: Tone;
  /** Render the technique name beside its id. Off in dense rows. */
  showNames?: boolean;
  visible?: number;
  mappingEvidence?: Record<string, AtlasMappingReceipt> | undefined;
}) {
  const [expanded, setExpanded] = useState(false);
  const all = [...new Set(tags ?? [])];
  if (all.length === 0) return null;

  const shown = expanded ? all : all.slice(0, visible);
  const hidden = all.length - shown.length;
  const receipts = tone === "atlas" ? all.flatMap((tag) => {
    const receipt = mappingEvidence?.[tag];
    return receipt?.basis === "catalog_weakness_association" && receipt.execution_proven === false
      && Array.isArray(receipt.cwe_ids) ? [{ tag, receipt }] : [];
  }) : [];

  return (
    <>
      {tone === "atlas" ? <span className="w-full text-xs text-ink-secondary">ATLAS associations · execution not established</span> : null}
      {shown.map((tag) => (
        <span
          key={tag}
          data-testid="framework-tag-chip"
          title={catalog[tag] ?? tag}
          className={`text-xs font-mono ${TONE_CLASS[tone]} border rounded px-1.5 py-0.5 cursor-help`}
        >
          {tag}
          {showNames && catalog[tag] ? (
            <span className={`ml-1 ${TONE_NAME_CLASS[tone]} font-sans`}>{catalog[tag]}</span>
          ) : null}
        </span>
      ))}
      {hidden > 0 || expanded ? (
        <button
          type="button"
          onClick={() => setExpanded((open) => !open)}
          className="text-xs text-[color:var(--text-tertiary)] underline decoration-dotted underline-offset-2 hover:text-[color:var(--text-secondary)]"
        >
          {expanded ? "show fewer" : `+${hidden} more`}
        </button>
      ) : null}
      {receipts.length > 0 ? (
        <details className="w-full min-w-0 text-xs text-ink-secondary">
          <summary className="cursor-pointer py-2">Mapping sources</summary>
          {receipts.map(({ tag, receipt }) => (
            <div key={tag} className="space-y-1 py-2">
              <p>{receipt.cwe_ids.join(", ")} → {receipt.attack_reference} → {tag}</p>
              <p>ATLAS catalog {receipt.atlas_version}</p>
              <p>ATLAS SHA-256: <code className="break-all">{receipt.atlas_catalog_sha256}</code></p>
              <p>ATT&amp;CK bridge SHA-256: <code className="break-all">{receipt.attack_catalog_sha256}</code></p>
            </div>
          ))}
        </details>
      ) : null}
    </>
  );
}

export default FrameworkTagChips;
