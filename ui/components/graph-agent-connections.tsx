"use client";

import { useEffect, useMemo, useState } from "react";
import { Background, ReactFlow, ReactFlowProvider, type Node, type Edge } from "@xyflow/react";
import { api, type GraphQueryResponse, type UnifiedGraphResponse } from "@/lib/api";
import type { GraphRollupAggregate } from "@/lib/api-types";
import { isStaticDemo } from "@/lib/static-demo";
import { useGraphNodeAggregates } from "@/lib/graph-node-aggregates";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";
import { scopeEvidenceGraph } from "@/lib/graph-scope-evidence";
import type { CSSProperties } from "react";
import { lineageNodeTypes, type LineageNodeData } from "@/components/lineage-nodes";
import { relationshipEdgeTypes } from "@/components/relationship-edge";
import { createExpandedGraphFilters } from "@/components/lineage-filter";
import { useNarrowViewport } from "@/hooks/use-narrow-viewport";
import { LegibleFitControls } from "@/components/graph-legible-controls";
import { CONTROLS_CLASS } from "@/lib/graph-utils";
import { graphEdgeEvidence } from "@/lib/graph-edge-evidence";

export function GraphAgentConnections({ scanId, rootId, generation, onInspect, onFindings, aggregate, onUnavailable }: {
  onUnavailable: () => void;
  scanId: string; rootId: string; generation?: string | undefined;
  onInspect: (id: string, label: string) => void; onFindings: (id: string, label: string, aggregate: GraphRollupAggregate) => void; aggregate: GraphRollupAggregate;
}) {
  const [response, setResponse] = useState<GraphQueryResponse | UnifiedGraphResponse>();
  const [error, setError] = useState(false);
  const [retry, setRetry] = useState(0);
  const narrow = useNarrowViewport();
  useEffect(() => {
    const controller = new AbortController();
    setResponse(undefined); setError(false);
    const read = isStaticDemo() ? api.getGraph({ scanId, limit: 200 }) : api.queryGraph({ roots: [rootId], scan_id: scanId, snapshot_generation: generation, direction: "both", max_depth: 2,
      max_nodes: 64, max_edges: 128, timeout_ms: 2500, traversable_only: false, include_roots: true, include_attack_paths: false },
    { signal: controller.signal });
    read.then(value => { if (!controller.signal.aborted) {
      if (value.scan_id !== scanId || !value.nodes.some(node => node.id === rootId)) throw new Error("Scope response mismatch");
      setResponse(value);
    } })
      .catch(() => { if (!controller.signal.aborted) { setError(true); onUnavailable(); } });
    return () => controller.abort();
  }, [scanId, rootId, generation, retry, onUnavailable]);
  const graph = useMemo(() => {
    if (!response) return null;
    const { snapshot_generation, ...data } = response;
    return scopeEvidenceGraph({ ...data, ...(snapshot_generation ? { snapshot_generation } : {}) }, rootId);
  }, [response, rootId]);
  const records = useGraphNodeAggregates(scanId, graph?.nodes.map(node => node.id) ?? [], generation);
  const flow = useMemo<{ nodes: Node<LineageNodeData>[]; edges: Edge[] } | null>(() => {
    if (!graph) return null;
    const filters = createExpandedGraphFilters();
    const base = buildUnifiedFlowGraph(graph, { layers: filters.layers, severity: null, agentName: null, vulnOnly: false, maxDepth: 32 });
    const incoming = base.nodes.filter(node => node.id !== rootId && graph.edges.some(edge => edge.source === node.id && edge.target === rootId));
    const outgoing = base.nodes.filter(node => node.id !== rootId && !incoming.includes(node) && graph.edges.some(edge => edge.source === rootId && edge.target === node.id));
    const peers = base.nodes.filter(node => node.id !== rootId && !incoming.includes(node) && !outgoing.includes(node));
    const nodes = base.nodes.map(node => ({ ...node,
      position: node.id === rootId ? { x: 360, y: 160 } : incoming.includes(node) ? { x: 0, y: incoming.indexOf(node) * 190 + 160 }
        : outgoing.includes(node) ? { x: 720, y: outgoing.indexOf(node) * 190 } : { x: 360, y: 380 + peers.indexOf(node) * 190 },
      style: { ...node.style, width: 220, "--graph-node-name-scale": 1 },
      data: { ...node.data, semanticLayout: true, readingFocus: node.id === rootId,
      ...((records.get(node.id)?.aggregate ?? (node.id === rootId ? aggregate : undefined)) ? { findingAggregate: records.get(node.id)?.aggregate ?? aggregate, onExploreFindings: () => onFindings(node.id, node.data.label, records.get(node.id)?.aggregate ?? aggregate) } : {}) } }));
    const positions = new Map(nodes.map(node => [node.id, node.position]));
    const edges = base.edges.map(edge => ({ ...edge, type: "smoothstep",
      ...(positions.get(edge.source)!.x > positions.get(edge.target)!.x ? { sourceHandle: "context", targetHandle: "context" } : {}),
      style: { ...edge.style, opacity: 1, strokeWidth: 2 },
      data: { ...edge.data, directionEmphasis: true, labelVisibility: "show", quietLabel: false, boundedOverview: true, stackedQualifier: true } }));
    return { nodes, edges };
  }, [graph, rootId, aggregate, onFindings, records]);
  if (error) return <div role="alert" className="p-4 text-sm">Recorded connections could not be loaded. <button className="underline" onClick={() => setRetry(n => n + 1)}>Retry connections</button></div>;
  if (!graph || !flow) return <p role="status" className="p-4">Loading recorded connections…</p>;
  const labels = new Map(graph.nodes.map(node => [node.id, node.label]));
  const rootAggregate = records.get(rootId)?.aggregate ?? aggregate;
  return <>
    <p className="px-4 pt-3 text-xs text-ink-secondary">Showing {graph.nodes.length} assets · {graph.edges.length} original relationships{(response && ("truncated" in response ? response.truncated : response.completeness?.truncated)) ? " · partial neighborhood" : ""}. Shared infrastructure does not establish successful lateral access.</p>
    {narrow ? <section data-testid="graph-agent-evidence" aria-label="Directed agent connections" className="px-4 py-3 text-sm">
      {!!rootAggregate.issue_count && <button className="graph-page-action mb-3" onClick={() => onFindings(rootId, labels.get(rootId) ?? rootId, rootAggregate)}>Open {rootAggregate.issue_count} {rootAggregate.issue_count === 1 ? "finding" : "findings"} for {labels.get(rootId)}</button>}
      <ul className="divide-y divide-outline">{graph.edges.map(edge => <li key={edge.id} className="py-3" data-recorded-edge={edge.id}>
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1"><button className="text-left font-medium underline underline-offset-4" onClick={() => onInspect(edge.source, labels.get(edge.source) ?? edge.source)}>{labels.get(edge.source)}</button>
          <span aria-label={edge.direction === "bidirectional" ? "bidirectional" : edge.direction === "directed" ? "directed" : "direction not recorded"}>{edge.direction === "bidirectional" ? "↔" : edge.direction === "directed" ? "→" : "—"}</span>
          <button className="text-left font-medium underline underline-offset-4" onClick={() => onInspect(edge.target, labels.get(edge.target) ?? edge.target)}>{labels.get(edge.target)}</button></div>
        <p className="mt-1 text-xs text-ink-secondary">{edge.relationship.replaceAll("_", " ")} · {graphEdgeEvidence(edge.evidence ?? {}).label}</p>
      </li>)}</ul>
      <div className="flex flex-wrap gap-2 border-t border-outline pt-3">{graph.nodes.filter(node => node.id !== rootId && (records.get(node.id)?.aggregate.issue_count ?? 0) > 0).map(node =>
        <button key={node.id} className="graph-page-action text-xs" onClick={() => onFindings(node.id, node.label, records.get(node.id)!.aggregate)}>{node.label} · {records.get(node.id)!.aggregate.issue_count} {records.get(node.id)!.aggregate.issue_count === 1 ? "finding" : "findings"}</button>)}</div>
    </section> : <ReactFlowProvider key={`${rootId}:${narrow}`}><div data-testid="graph-agent-evidence" style={{ height: Math.max(540, ...flow.nodes.map(node => node.position.y + 180)) }}>
      <ReactFlow style={{ "--graph-node-label-size": "18px", "--graph-node-meta-size": "14px", "--graph-node-glyph-size": "76px", "--graph-node-icon-size": "36px" } as CSSProperties} nodes={flow.nodes} edges={flow.edges} nodeTypes={lineageNodeTypes} edgeTypes={relationshipEdgeTypes}
        fitView fitViewOptions={{ padding: 0.15, minZoom: 0.65, maxZoom: 1 }} minZoom={0.35} nodesDraggable={false} nodesConnectable={false}
        proOptions={{ hideAttribution: true }} onNodeClick={(_, node) => onInspect(node.id, node.data.label)}>
        <Background gap={20} size={1} /><LegibleFitControls className={CONTROLS_CLASS} floor={0.65} showInteractive={false} />
      </ReactFlow>
    </div></ReactFlowProvider>}
    {!narrow && <details className="border-t border-outline px-4 py-2 text-xs"><summary className="cursor-pointer">Relationship evidence ({graph.edges.length})</summary>
      <ul className="mt-2 divide-y divide-outline">{graph.edges.map(edge => <li key={edge.id} className="py-2">
        {labels.get(edge.source)} {edge.direction === "bidirectional" ? "↔" : edge.direction === "directed" ? "→" : "—"} {labels.get(edge.target)} · {edge.relationship.replaceAll("_", " ")} · {graphEdgeEvidence(edge.evidence ?? {}).label}
      </li>)}</ul>
    </details>}
  </>;
}
