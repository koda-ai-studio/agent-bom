"use client";

import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Background, Controls, MarkerType, ReactFlow, ReactFlowProvider, useReactFlow, type Edge } from "@xyflow/react";

import { clusterNodeTypes, type ClusterCardNode } from "@/components/graph-cluster-node";
import { useAnimatedLayout } from "@/hooks/use-animated-layout";
import { useGraphClusterMap } from "@/hooks/use-graph-cluster-map";
import { api } from "@/lib/api";
import { NARROW_LABELLED_BUNDLES, bundleHandles, bundleLabel, bundleTitle, clusterMapLayout, relationshipLabel, type ClusterMapEdge, type ClusterMapResponse } from "@/lib/graph-cluster-map";
import { BACKGROUND_COLOR, BACKGROUND_GAP, CONTROLS_CLASS } from "@/lib/graph-utils";

export interface GraphClusterMapProps {
  scanId: string | undefined;
  narrow: boolean;
  /** Open one member's connections in the investigation canvas. */
  onInvestigate: (id: string, label: string) => void;
  /** Leave the grouped map for the ungrouped full map (every edge). */
  onShowEveryEdge: () => void;
  /** Called once when the grouped read fails, so the page can fall back to the ungrouped map. */
  onUnavailable?: () => void;
}

function toElements(view: ClusterMapResponse, narrow: boolean, onPage: (id: string, offset: number) => void) {
  const placed = clusterMapLayout(view, { narrow });
  const at = new Map(placed.map(item => [item.node.id, item]));
  const nodes: ClusterCardNode[] = placed.map(({ node, x, y, width, height }) => ({
    id: node.id, type: node.kind, position: { x, y }, width, height, style: { width, height },
    data: { node, narrow, onPage }, draggable: false, connectable: false,
  }));
  const labelled = new Set(narrow ? [...view.edges].sort((a, b) => b.count - a.count).slice(0, NARROW_LABELLED_BUNDLES).map(edge => edge.id) : view.edges.map(edge => edge.id));
  const edges: Edge[] = view.edges.map(edge => ({
    id: edge.id, source: edge.source, target: edge.target, type: "default",
    ...(labelled.has(edge.id) ? { label: bundleLabel(edge) } : {}),
    ...bundleHandles(at.get(edge.source), at.get(edge.target), narrow),
    style: { strokeWidth: Math.min(1 + Math.log2(edge.count + 1) * 0.4, 4) },
    markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
    labelBgPadding: [4, 2] as [number, number], labelBgBorderRadius: 4, ariaLabel: bundleTitle(edge), data: { bundle: edge },
  }));
  return { nodes, edges };
}

/** Bundles stay quiet until a group is pointed at or found; then its own bundles carry the colour. */
export function emphasiseBundles(edges: Edge[], activeId: string | null): Edge[] {
  if (!activeId) return edges;
  return edges.map(edge => ({ ...edge, className: edge.source === activeId || edge.target === activeId ? "cluster-edge-active" : "cluster-edge-quiet" }));
}

/** Below this zoom a card's text drops under ~10px; the camera pans instead of shrinking further. */
const MIN_READABLE_ZOOM = 0.8;

/** Frames the map after every layout change: whole when it stays readable, otherwise from the top (or the found node) at a readable size. */
function Camera({ layoutKey, narrow, settled, focusId }: { layoutKey: string; narrow: boolean; settled: boolean; focusId: string | null }) {
  const flow = useReactFlow();
  useEffect(() => {
    if (!settled) return;
    const frame = requestAnimationFrame(() => {
      const nodes = flow.getNodes();
      const width = nodes.reduce((right, node) => Math.max(right, node.position.x + (node.width ?? 0)), 0);
      const height = nodes.reduce((bottom, node) => Math.max(bottom, node.position.y + (node.height ?? 0)), 0);
      const pane = document.querySelector<HTMLElement>("[data-testid='cluster-map-canvas']");
      const paneW = (pane?.clientWidth ?? 360) - 16, paneH = (pane?.clientHeight ?? 480) - 24;
      const fitWidth = Math.min(1, paneW / Math.max(width, 1));
      const zoom = narrow ? fitWidth : Math.min(1, paneW / Math.max(width, 1), paneH / Math.max(height, 1));
      const readable = narrow ? zoom : Math.max(zoom, Math.min(1, Math.max(MIN_READABLE_ZOOM, fitWidth)));
      const focus = focusId ? nodes.find(node => node.id === focusId) : undefined;
      if (focus) { void flow.setCenter(focus.position.x + (focus.width ?? 0) / 2, focus.position.y + (focus.height ?? 0) / 2, { zoom: Math.max(readable, MIN_READABLE_ZOOM) }); return; }
      const x = width * readable < paneW ? (paneW - width * readable) / 2 + 8 : 8;
      const y = height * readable < paneH ? (paneH - height * readable) / 2 + 12 : 12;
      void flow.setViewport({ x, y, zoom: readable });
    });
    return () => cancelAnimationFrame(frame);
  }, [flow, layoutKey, narrow, settled, focusId]);
  return null;
}

function FindInMap({ scanId, onFocus }: { scanId: string | undefined; onFocus: (id: string) => void }) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<Array<{ id: string; label: string; entity_type?: string }> | null>(null);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!query.trim()) return;
    try {
      const found = await api.searchGraph(query.trim(), { ...(scanId ? { scanId } : {}), limit: 6 });
      const rows = found.results.map(node => ({ id: node.id, label: node.label, entity_type: String(node.entity_type ?? "") }));
      if (rows.length === 1) { onFocus(rows[0]!.id); setResults(null); } else setResults(rows);
    } catch { setResults([]); }
  };
  return <form role="search" onSubmit={event => void submit(event)} className="relative flex items-center gap-1">
    <input aria-label="Find in grouped map" value={query} onChange={event => setQuery(event.target.value)} placeholder="Find a node"
      className="min-h-9 w-40 rounded-md border border-outline bg-background px-2 text-sm text-foreground max-sm:w-32" />
    <button type="submit" className="graph-page-action graph-action-compact min-h-9">Find</button>
    {results && <ul role="listbox" aria-label="Matches" className="absolute right-0 top-full z-30 mt-1 w-72 max-w-[calc(100vw-2rem)] rounded-lg border border-outline bg-surface p-1 shadow-lg">
      {results.length === 0 && <li className="px-2 py-1 text-sm text-ink-secondary">No matching node in this snapshot.</li>}
      {results.map(row => <li key={row.id}><button type="button" role="option" aria-selected={false} className="w-full rounded px-2 py-1 text-left text-sm hover:bg-surface-elevated"
        onClick={() => { onFocus(row.id); setResults(null); }}>{row.label} <span className="text-ink-secondary">· {row.entity_type?.replace(/_/g, " ")}</span></button></li>)}
    </ul>}
  </form>;
}

function BundleReceipt({ bundle, labels, onClose }: { bundle: ClusterMapEdge; labels: Map<string, string>; onClose: () => void }) {
  return <div role="dialog" aria-label="Bundled relationship" className="absolute right-2 top-2 z-20 w-72 max-w-[calc(100%-1rem)] rounded-lg border border-outline bg-surface p-3 text-sm shadow-lg">
    <div className="flex items-start justify-between gap-2">
      <p className="font-medium text-foreground">{labels.get(bundle.source) ?? bundle.source} → {labels.get(bundle.target) ?? bundle.target}</p>
      <button type="button" aria-label="Close" className="text-ink-secondary" onClick={onClose}>×</button>
    </div>
    <p className="mt-1 text-ink-secondary">{bundle.count.toLocaleString()} underlying relationships</p>
    <ul className="mt-2 space-y-0.5">{bundle.relationships.map(item => <li key={item.relationship} className="flex justify-between gap-2"><span>{relationshipLabel(item.relationship)}</span><span className="tabular-nums">×{item.count.toLocaleString()}</span></li>)}</ul>
  </div>;
}

function Summary({ view }: { view: ClusterMapResponse }) {
  const s = view.summary;
  const parts = [`${s.visible_cluster_count} groups of ${s.total_nodes.toLocaleString()} nodes`, `${s.drawn_bundle_count} bundled links for ${s.total_edges.toLocaleString()} relationships`];
  if (s.hidden_bundle_count) parts.push(`${s.hidden_bundle_count} smaller links (${s.hidden_bundle_edge_count.toLocaleString()}) not drawn`);
  if (s.filtered_node_count) parts.push(`${s.filtered_node_count.toLocaleString()} nodes in lower-risk groups hidden`);
  return <p data-testid="cluster-map-summary" className="min-w-0 text-xs text-ink-secondary">{parts.join(" · ")}</p>;
}

function GraphClusterMapInner({ scanId, narrow, onInvestigate, onShowEveryEdge, onUnavailable }: GraphClusterMapProps) {
  const map = useGraphClusterMap(scanId, true);
  const [bundleId, setBundleId] = useState<string | null>(null);
  const { view, status } = map;
  useEffect(() => { if (status === "failed" && !view) onUnavailable?.(); }, [status, view, onUnavailable]);
  const elements = useMemo(() => (view ? toElements(view, narrow, map.page) : { nodes: [], edges: [] }), [view, narrow, map.page]);
  const motion = useAnimatedLayout(elements.nodes);
  const labels = useMemo(() => new Map((view?.nodes ?? []).map(node => [node.id, node.label])), [view]);
  const bundle = view?.edges.find(edge => edge.id === bundleId) ?? null;
  const layoutKey = useMemo(() => elements.nodes.map(node => `${node.id}@${node.position.x},${node.position.y}`).join("|"), [elements.nodes]);
  const [hoverId, setHoverId] = useState<string | null>(null);
  const focusId = view?.focus?.found ? view.focus.node_id : null;
  const shownEdges = useMemo(() => emphasiseBundles(elements.edges, hoverId ?? focusId), [elements.edges, hoverId, focusId]);
  return <section aria-label="Grouped map" data-testid="graph-cluster-map" className="cluster-map flex min-h-0 flex-1 flex-col">
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-outline px-3 py-1.5 max-sm:px-1">
      <span className="text-sm font-medium text-foreground">Grouped map</span>
      <button type="button" aria-pressed={map.state.riskyOnly} onClick={() => map.setRiskyOnly(!map.state.riskyOnly)}
        className="graph-page-action graph-action-compact min-h-9 aria-pressed:bg-surface-elevated aria-pressed:text-foreground">Risky groups only</button>
      <FindInMap scanId={scanId} onFocus={id => { setBundleId(null); map.focus(id); }} />
      {(map.state.expanded.length > 0 || map.state.focus) && <button type="button" className="graph-page-action graph-action-compact min-h-9" onClick={map.reset}>Collapse all</button>}
      <button type="button" className="graph-page-action graph-action-compact ml-auto min-h-9" onClick={onShowEveryEdge}>Show every edge</button>
      {view && <div className="basis-full"><Summary view={view} /></div>}
      {view?.focus && !view.focus.found && <p role="status" className="basis-full text-xs text-amber-700 dark:text-amber-200">That node is not in this snapshot.</p>}
    </div>
    <div data-testid="cluster-map-canvas" className={`relative ${narrow ? "h-[max(32rem,calc(100dvh-16rem))]" : "h-[max(30rem,calc(100dvh-17rem))]"} min-h-0 overflow-hidden rounded-lg border border-outline bg-surface`}>
      {status === "loading" && !view && <p role="status" className="p-6 text-sm text-ink-secondary">Grouping the snapshot…</p>}
      {status === "failed" && <p role="alert" className="p-3 text-sm text-ink-secondary">The grouped map did not load. <button type="button" className="underline" onClick={onShowEveryEdge}>Show every edge</button></p>}
      {view && view.nodes.length === 0 && <p role="status" className="p-6 text-sm text-ink-secondary">{map.state.riskyOnly ? "No group is on an attack path or holds a critical or high finding." : "This snapshot has no nodes."}</p>}
      {view && view.nodes.length > 0 && <ReactFlow
        nodes={motion.nodes} edges={shownEdges} nodeTypes={clusterNodeTypes}
        onNodeMouseEnter={(_event, node) => setHoverId(node.id)} onNodeMouseLeave={() => setHoverId(null)}
        nodesDraggable={false} nodesConnectable={false} nodesFocusable edgesFocusable elementsSelectable deleteKeyCode={null}
        minZoom={0.1} maxZoom={1.6} proOptions={{ hideAttribution: true }}
        onNodeClick={(_event, node) => {
          const item = node.data.node;
          setBundleId(null);
          if (item.kind === "cluster") map.toggle(item.id);
          else if (item.kind === "member") onInvestigate(item.id, item.label);
          else if (item.next_offset != null && item.cluster_id) map.page(item.cluster_id, item.next_offset);
        }}
        onEdgeClick={(_event, edge) => setBundleId(edge.id)}
        onPaneClick={() => setBundleId(null)}
      >
        <Camera layoutKey={layoutKey} narrow={narrow} settled={!motion.animating} focusId={focusId} />
        <Background color={BACKGROUND_COLOR} gap={BACKGROUND_GAP} />
        <Controls showInteractive={false} position="bottom-left" className={CONTROLS_CLASS} />
      </ReactFlow>}
      {bundle && <BundleReceipt bundle={bundle} labels={labels} onClose={() => setBundleId(null)} />}
    </div>
  </section>;
}

/** The grouped full map, with its own camera so it never moves the investigation canvas. */
export function GraphClusterMap(props: GraphClusterMapProps) {
  return <ReactFlowProvider><GraphClusterMapInner {...props} /></ReactFlowProvider>;
}
