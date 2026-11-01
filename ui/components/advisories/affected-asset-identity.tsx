import type { AdvisoryAffectedRow } from "@/lib/advisory-affected";

function isUnnamedOccurrence(row: AdvisoryAffectedRow): boolean {
  return !row.asset.agent && !row.asset.server && row.asset_label.startsWith("pkg:")
    && (row.asset_label === row.asset_node_id || row.asset_label === row.asset.node_id);
}

export function affectedAssetLabel(row: AdvisoryAffectedRow): string {
  if (row.asset_display?.name) return row.asset_display.name;
  return isUnnamedOccurrence(row) ? `${row.package.name}@${row.installed_version}` : row.asset_label;
}

const KIND_LABELS: Record<string, string> = { container_image: "Container image", mcp_server: "MCP server", package: "Package occurrence" };

/** One line of context from the graph: kind, owning agent, host, and the package for image rows. */
function displayContext(row: AdvisoryAffectedRow): string | null {
  const display = row.asset_display;
  if (!display) return null;
  const parts = [KIND_LABELS[display.kind] ?? display.kind.replaceAll("_", " ")];
  if (display.agent) parts.push(`agent ${display.agent}`);
  if (display.host) parts.push(`runs on ${display.host}`);
  if (display.kind === "container_image") parts.push(`${row.package.name}@${row.installed_version}`);
  return parts.join(" · ");
}

/** Keep the exact evidence target available without using a graph ID as the heading. */
export function AffectedAssetIdentity({ row }: { row: AdvisoryAffectedRow }) {
  const label = affectedAssetLabel(row);
  const context = displayContext(row) ?? (isUnnamedOccurrence(row)
    ? "Package occurrence · owner not recorded"
    : row.asset.agent || row.asset_type?.replaceAll("_", " ") || "Asset type not recorded");
  const node = row.asset_node_id || row.asset.node_id || row.graph.server_node_id || row.graph.package_node_id;
  return <div className="min-w-0 space-y-1">
    <p className="break-words text-sm font-medium text-foreground [overflow-wrap:anywhere]">{label}</p>
    <p className="break-words text-xs text-ink-tertiary [overflow-wrap:anywhere]">{context}</p>
    <details className="text-xs text-ink-secondary">
      <summary className="cursor-pointer">Evidence identity</summary>
      <dl className="mt-1 space-y-1 rounded border border-outline bg-surface-muted p-2">
        <div><dt className="text-ink-tertiary">Scan</dt><dd className="break-all font-mono">{row.scan_id || "Not recorded"}</dd></div>
        <div><dt className="text-ink-tertiary">Asset ID</dt><dd className="break-all font-mono">{node || "Not recorded"}</dd></div>
      </dl>
    </details>
  </div>;
}
