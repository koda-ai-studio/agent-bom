"use client";

type EvidenceEdge = { data?: Record<string, unknown> | undefined };

/** Counts the supplied scope; a sampled map may draw only part of its loaded evidence. */
export function GraphScopeEvidence({ edges, scope = "visible", inline = false }: { edges: readonly EvidenceEdge[]; scope?: "visible" | "loaded"; inline?: boolean }) {
  const counts = new Map<string, number>();
  for (const edge of edges) {
    const value = edge.data?.evidenceLabel;
    const label = edge.data?.isClusterEdge || edge.data?.aggregate ? "Bundled (expand for evidence)" : typeof value === "string" && !["Not recorded", "Unclassified", "Scan inventory · no per-edge receipt"].includes(value)
      ? value : "Unknown";
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  const entries = [...counts].sort(([a], [b]) => a.localeCompare(b));
  const heading = entries.length > 1 ? "Mixed evidence" : entries[0]?.[0] ?? `No ${scope} relationships`;
  const hint = scope === "loaded" ? "Loaded links · the map may show a subset; open an asset to inspect direction and evidence" : "Visible links · select a link for direction and evidence";
  return <div aria-label={`${scope === "loaded" ? "Loaded" : "Visible"} relationship evidence`} title={inline ? hint : undefined}
    className={`flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-ink-secondary ${inline ? "" : "border-b border-outline px-4 py-2"}`}>
    <span className="font-medium text-foreground">{entries.length === 1 ? "Evidence" : heading}</span>
    <span>{entries.map(([label, count]) => `${label} ${count}`).join(" · ")}</span>
    {/* Inline in the status bar, the hint stays available to screen readers and as a tooltip. */}
    <span className={inline ? "sr-only" : "text-ink-tertiary"}>{hint}</span>
  </div>;
}
