"use client";

type EvidenceEdge = { data?: Record<string, unknown> | undefined };

/** Counts the supplied scope; a sampled map may draw only part of its loaded evidence. */
export function GraphScopeEvidence({ edges, scope = "visible" }: { edges: readonly EvidenceEdge[]; scope?: "visible" | "loaded" }) {
  const counts = new Map<string, number>();
  for (const edge of edges) {
    const value = edge.data?.evidenceLabel;
    const label = edge.data?.isClusterEdge || edge.data?.aggregate ? "Bundled (expand for evidence)" : typeof value === "string" && !["Not recorded", "Unclassified", "Scan inventory · no per-edge receipt"].includes(value)
      ? value : "Unknown";
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  const entries = [...counts].sort(([a], [b]) => a.localeCompare(b));
  const heading = entries.length > 1 ? "Mixed evidence" : entries[0]?.[0] ?? `No ${scope} relationships`;
  return <div aria-label={`${scope === "loaded" ? "Loaded" : "Visible"} relationship evidence`} className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-outline px-4 py-2 text-xs text-ink-secondary">
    <span className="font-medium text-foreground">{entries.length === 1 ? "Evidence" : heading}</span>
    <span>{entries.map(([label, count]) => `${label} ${count}`).join(" · ")}</span>
    <span className="text-ink-tertiary">{scope === "loaded" ? "Loaded links · the map may show a subset; open an asset to inspect direction and evidence" : "Visible links · select a link for direction and evidence"}</span>
  </div>;
}
