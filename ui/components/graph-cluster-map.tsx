"use client";

import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Background, Controls, MarkerType, ReactFlow, ReactFlowProvider, useReactFlow, type Edge } from "@xyflow/react";

import { clusterNodeTypes, type ClusterCardNode } from "@/components/graph-cluster-node";
import { useAnimatedLayout } from "@/hooks/use-animated-layout";
import { useGraphClusterMap } from "@/hooks/use-graph-cluster-map";
import { api } from "@/lib/api";
import { clusterEdgeTypes, type BundleEdge } from "@/components/graph-cluster-edge";
import { clusterMapLayout, displayBundles, frameId, routeCards } from "@/lib/graph-cluster-layout";
import { bundleLabel, bundleTitle, relationshipLabel, type ClusterMapEdge, type ClusterMapResponse } from "@/lib/graph-cluster-map";
import { routeBundles, type Box } from "@/lib/graph-cluster-routes";
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

export interface ClusterElements { nodes: ClusterCardNode[]; edges: BundleEdge[]; bounds: Box }

/** Cards, frames and routed bundles for one response; `activeMember` shows one member's own bundles. */
export function toElements(view: ClusterMapResponse, narrow: boolean, onPage: (id: string, offset: number) => void, activeMember: string | null = null): ClusterElements {
  const layout = clusterMapLayout(view, { narrow });
  const frames: ClusterCardNode[] = layout.frames.map(frame => ({
    id: frame.id, type: "frame", position: { x: frame.x, y: frame.y }, width: frame.width, height: frame.height, style: { width: frame.width, height: frame.height },
    data: { node: { id: frame.id, kind: "cluster", label: "", tier: 0 }, narrow, onPage }, draggable: false, connectable: false, selectable: false, focusable: false, zIndex: -1,
  }));
  const nodes: ClusterCardNode[] = [...frames, ...layout.cards.map(({ node, x, y, width, height }) => ({
    id: node.id, type: node.kind, position: { x, y }, width, height, style: { width, height },
    data: { node, narrow, onPage }, draggable: false, connectable: false,
  }))];
  const bundles = displayBundles(view, activeMember);
  const routes = routeBundles(routeCards(layout, activeMember),
    bundles.map(bundle => ({ id: bundle.id, source: bundle.source, target: bundle.target, label: bundle.count > 1 ? bundleLabel(bundle) : null })),
    [...layout.cards, ...layout.frames]);
  const byId = new Map(bundles.map(bundle => [bundle.id, bundle]));
  const marker = { type: MarkerType.ArrowClosed, width: 14, height: 14 };
  const edges: BundleEdge[] = routes.map(route => {
    const bundle = byId.get(route.id)!;
    return {
      id: route.id, source: bundle.source, target: bundle.target, type: "bundle" as const,
      ...(route.reversed ? { markerStart: marker } : { markerEnd: marker }),
      style: { strokeWidth: Math.min(1 + Math.log2(bundle.count + 1) * 0.35, 3.5) },
      ariaLabel: bundleTitle(bundle), data: { route, text: bundleLabel(bundle), title: bundleTitle(bundle), bundle },
      ...(bundle.member ? { className: "cluster-edge-member" } : {}),
    };
  });
  const boxes = [...layout.cards, ...layout.frames];
  const xs = boxes.flatMap(box => [box.x, box.x + box.width]).concat(routes.flatMap(route => route.points.map(point => point.x)));
  const ys = boxes.flatMap(box => [box.y, box.y + box.height]).concat(routes.flatMap(route => route.points.map(point => point.y)));
  const minX = Math.min(...xs, 0), minY = Math.min(...ys, 0);
  return { nodes, edges, bounds: { x: minX, y: minY, width: Math.max(...xs, 0) - minX, height: Math.max(...ys, 0) - minY } };
}

/** Bundles stay quiet until a group is pointed at or found; then its own bundles carry the colour. */
export function emphasiseBundles<E extends Pick<Edge, "source" | "target">>(edges: E[], activeId: string | null): Array<E & { className?: string }> {
  if (!activeId) return edges;
  return edges.map(edge => ({ ...edge, className: edge.source === activeId || edge.target === activeId ? "cluster-edge-active" : "cluster-edge-quiet" }));
}

/** Below this zoom a card's text drops under ~10px; the camera pans instead of shrinking further. */
const MIN_READABLE_ZOOM = 0.9;

/** Frames the map after every layout change: whole when it stays readable, otherwise from the top (or the found node) at a readable size. */
function Camera({ layoutKey, narrow, settled, focusId, bounds }: { layoutKey: string; narrow: boolean; settled: boolean; focusId: string | null; bounds: Box }) {
  const flow = useReactFlow();
  const boundsRef = useRef(bounds);
  boundsRef.current = bounds;
  useEffect(() => {
    if (!settled) return;
    const frame = requestAnimationFrame(() => {
      const nodes = flow.getNodes();
      const box = boundsRef.current;
      const { width, height } = box;
      const pane = document.querySelector<HTMLElement>("[data-testid='cluster-map-canvas']");
      const paneW = (pane?.clientWidth ?? 360) - 16, paneH = (pane?.clientHeight ?? 480) - 24;
      const fitWidth = Math.min(1, paneW / Math.max(width, 1));
      const zoom = narrow ? fitWidth : Math.min(1, paneW / Math.max(width, 1), paneH / Math.max(height, 1));
      const readable = narrow ? zoom : Math.max(zoom, Math.min(1, Math.max(MIN_READABLE_ZOOM, fitWidth)));
      // A found node, or the group just opened, is brought into view; a tall frame shows from its top.
      const anchor = focusId ? nodes.find(node => node.id === focusId) : undefined;
      if (anchor) {
        const z = narrow ? readable : Math.max(readable, MIN_READABLE_ZOOM);
        const ax = anchor.position.x + (anchor.width ?? 0) / 2, ah = (anchor.height ?? 0) * z;
        void flow.setViewport({ x: paneW / 2 + 8 - ax * z, y: ah > paneH ? 24 - anchor.position.y * z : paneH / 2 + 12 - (anchor.position.y + (anchor.height ?? 0) / 2) * z, zoom: z });
        return;
      }
      const x = (width * readable < paneW ? (paneW - width * readable) / 2 + 8 : 8) - box.x * readable;
      const y = (height * readable < paneH ? (paneH - height * readable) / 2 + 12 : 12) - box.y * readable;
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

function BundleReceipt({ bundle, labels, onClose }: { bundle: Pick<ClusterMapEdge, "source" | "target" | "count" | "relationships">; labels: Map<string, string>; onClose: () => void }) {
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
  const [hoverId, setHoverId] = useState<string | null>(null);
  const focusId = view?.focus?.found ? view.focus.node_id : null;
  const members = useMemo(() => new Set((view?.nodes ?? []).filter(node => node.kind === "member").map(node => node.id)), [view]);
  // Per-member links appear only for the member pointed at (or found); otherwise a group's bundles meet its frame.
  const activeMember = hoverId && members.has(hoverId) ? hoverId : focusId && members.has(focusId) ? focusId : null;
  const elements = useMemo(() => (view ? toElements(view, narrow, map.page, activeMember) : { nodes: [], edges: [], bounds: { x: 0, y: 0, width: 0, height: 0 } }), [view, narrow, map.page, activeMember]);
  const motion = useAnimatedLayout(elements.nodes);
  const labels = useMemo(() => new Map((view?.nodes ?? []).flatMap(node => [[node.id, node.label], [frameId(node.id), node.label]] as const)), [view]);
  const bundle = elements.edges.find(edge => edge.id === bundleId)?.data?.bundle ?? null;
  const layoutKey = useMemo(() => elements.nodes.map(node => `${node.id}@${node.position.x},${node.position.y}`).join("|"), [elements.nodes]);
  const lastOpened = map.state.expanded.at(-1);
  const cameraAnchor = focusId ?? (lastOpened ? frameId(lastOpened) : null);
  const [hoverEdge, setHoverEdge] = useState<string | null>(null);
  const shownEdges = useMemo(
    () => emphasiseBundles(elements.edges, activeMember ?? hoverId ?? focusId).map(edge => (edge.id === hoverEdge && edge.data ? { ...edge, data: { ...edge.data, hovered: true } } : edge)),
    [elements.edges, activeMember, hoverId, focusId, hoverEdge],
  );
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
        nodes={motion.nodes} edges={shownEdges} nodeTypes={clusterNodeTypes} edgeTypes={clusterEdgeTypes}
        onNodeMouseEnter={(_event, node) => setHoverId(node.id)} onNodeMouseLeave={() => setHoverId(null)}
        onEdgeMouseEnter={(_event, edge) => setHoverEdge(edge.id)} onEdgeMouseLeave={() => setHoverEdge(null)}
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
        <Camera layoutKey={layoutKey} narrow={narrow} settled={!motion.animating} focusId={cameraAnchor} bounds={elements.bounds} />
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
