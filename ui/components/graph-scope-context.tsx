"use client";

import type { UnifiedGraphResponse, GraphQueryResponse } from "@/lib/api";
import type { UnifiedGraphData } from "@/lib/graph-schema";
import { internetExposure } from "@/lib/graph-internet-context";

/** Additional recorded context, separate from the bounded overview's asset/edge totals. */
export function GraphScopeContext({ graph, selected, onInspect, compact = false, contextOpen, toolsOpen, onContextToggle, onToolsToggle }: {
  graph: UnifiedGraphResponse | GraphQueryResponse; selected: UnifiedGraphData;
  compact?: boolean;
  contextOpen?: boolean; toolsOpen?: boolean; onContextToggle?: () => void; onToolsToggle?: () => void;
  onInspect: (id: string, label: string) => void;
}) {
  const nodes = new Map(graph.nodes.map(node => [node.id, node]));
  const servers = selected.nodes.filter(node => ["server", "mcp_server"].includes(node.entity_type));
  const shared = servers.filter(server => new Set(selected.edges.filter(edge => edge.relationship === "uses" && edge.target === server.id).map(edge => edge.source)).size > 1);
  const tools = new Set(graph.edges.filter(edge => edge.relationship === "provides_tool" && servers.some(server => server.id === edge.source)).map(edge => edge.target));
  const controls = graph.edges.filter(edge => nodes.get(edge.source)?.entity_type === "policy" && tools.has(edge.target));
  const exposed = selected.nodes.filter(node => internetExposure(node.attributes) === true);
  const content = <>
    {shared.map(server => <p key={server.id}>Shared MCP server: {server.label}. Expand it to inspect tools and access evidence.</p>)}
    {exposed.map(node => <button key={node.id} className="mt-2 block underline underline-offset-4" onClick={() => onInspect(node.id, node.label)}>Internet-exposed: {node.label}</button>)}
    {controls.length > 0 && <details className="mt-2" open={toolsOpen}><summary className="cursor-pointer" onClick={event => { if (onToolsToggle) { event.preventDefault(); onToolsToggle(); } }}>Recorded tool control context ({controls.length})</summary>
      <p className="my-2">Additional relationships outside the overview. Recorded configuration does not confirm enforcement.</p>
      <ul>{controls.map(edge => <li key={edge.id} className="py-2">
        <button className="underline" onClick={() => onInspect(edge.source, nodes.get(edge.source)!.label)}>{nodes.get(edge.source)?.label}</button>
        {` → ${edge.relationship.replaceAll("_", " ")} → `}
        <button className="underline" onClick={() => onInspect(edge.target, nodes.get(edge.target)!.label)}>{nodes.get(edge.target)?.label}</button>
      </li>)}</ul>
    </details>}
  </>;
  return <div className="px-4 py-2 text-xs text-ink-secondary">{compact ? <details open={contextOpen}><summary className="cursor-pointer" onClick={event => { if (onContextToggle) { event.preventDefault(); onContextToggle(); } }}>Exposure and tool context</summary><div className="pt-2">{content}</div></details> : content}</div>;
}
