"use client";

type EvidenceEdge = { data?: Record<string, unknown> | undefined };

/** Counts the rendered projection only; missing receipts remain unknown. */
export function GraphScopeEvidence({ edges }: { edges: readonly EvidenceEdge[] }) {
  const counts = new Map<string, number>();
  for (const edge of edges) {
    const value = edge.data?.evidenceLabel;
    const label = edge.data?.isClusterEdge || edge.data?.aggregate ? "Bundled (expand for evidence)" : typeof value === "string" && !["Not recorded", "Unclassified", "Scan inventory · no per-edge receipt"].includes(value)
      ? value : "Unknown";
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  const entries = [...counts].sort(([a], [b]) => a.localeCompare(b));
  const heading = entries.length > 1 ? "Mixed evidence" : entries[0]?.[0] ?? "No visible relationships";
  return <div aria-label="Visible relationship evidence" className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-outline px-4 py-2 text-xs text-ink-secondary">
    <span className="font-medium text-foreground">{entries.length === 1 ? "Evidence" : heading}</span>
    <span>{entries.map(([label, count]) => `${label} ${count}`).join(" · ")}</span>
    <span className="text-ink-tertiary">Visible links · select an arrow for its receipt</span>
  </div>;
}
