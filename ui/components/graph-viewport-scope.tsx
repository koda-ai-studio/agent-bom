"use client";

const LINK = "text-foreground underline underline-offset-4";
const count = (value: number, one: string, many: string) => `${value.toLocaleString()} ${value === 1 ? one : many}`;

/** Counts for what is on the canvas. Display-only objects are not nodes and are never counted as such. */
export function GraphViewportScope({ collapsedFindings, canonicalVisibleNodes, totalNodes, totalEdges, scopeLabel, aggregate, unconnected, scenarioToggle, minimap, onFitAll, findingsToggle, connections, onMoreConnections }: {
  collapsedFindings: number;
  canonicalVisibleNodes: number;
  totalNodes: number;
  totalEdges: number;
  scopeLabel: string;
  aggregate: boolean;
  unconnected: number;
  scenarioToggle?: { expanded: boolean; onToggle: () => void } | undefined;
  minimap?: { expanded: boolean; onToggle: () => void } | undefined;
  onFitAll: () => void;
  findingsToggle?: (() => void) | undefined;
  connections?: { loaded: number; total: number } | undefined;
  onMoreConnections?: (() => void) | undefined;
}) {
  return <div className="flex min-w-0 max-w-full flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground" data-testid="graph-viewport-scope">
    {collapsedFindings ? <span title={`${totalNodes} total nodes and ${totalEdges} total relationships loaded`}>
      Graph · {canonicalVisibleNodes} visible items · {collapsedFindings} grouped findings
    </span> : <span>
      {scopeLabel} · {totalNodes.toLocaleString()} {aggregate ? "entities" : "nodes"} · {aggregate ? count(totalEdges, "aggregate link", "aggregate links") : count(totalEdges, "relationship", "relationships")}
      {unconnected > 0 && ` · ${unconnected} unconnected items`}
    </span>}
    {scenarioToggle && <button type="button" onClick={scenarioToggle.onToggle} className={LINK}>{scenarioToggle.expanded ? "Focus changes" : "Show full graph"}</button>}
    {minimap && <button type="button" aria-pressed={minimap.expanded} onClick={minimap.onToggle} className={LINK}>{minimap.expanded ? "Hide minimap" : "Show minimap"}</button>}
    <button type="button" onClick={onFitAll} className={LINK}>Fit all</button>
    {findingsToggle && <button type="button" onClick={findingsToggle} className={LINK}>{collapsedFindings ? `Expand findings (${collapsedFindings} grouped)` : "Collapse findings"}</button>}
    {connections && <span data-testid="graph-connection-progress">Showing {connections.loaded} of {connections.total} connections</span>}
    {onMoreConnections && <button type="button" className="graph-page-action min-h-11 sm:min-h-7" onClick={onMoreConnections}>Show more connections</button>}
  </div>;
}
