"use client";

import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Panel, useNodesInitialized, useReactFlow, useStore, type Node, type FitViewOptions } from "@xyflow/react";
import { GRAPH_FIT_MAX_ZOOM, graphAdaptiveFrame, legibleFitZoom } from "@/lib/graph-adaptive-frame";
import { graphInspectorTargets } from "@/lib/graph-inspector-framing";

/** Fit measured compact contexts after a docked inspector changes canvas width.
 * Only geometry changes trigger a fit; hover and evidence updates do not. */
export function GraphCanvasAutoFit({ enabled, layoutKey, anchorId, inspector, preserveViewport, onLayoutAspect, navigationIds, navigationMount, padding = 0.08 }: {
  padding?: number;
  navigationMount?: HTMLElement | null | undefined;
  navigationIds?: string[] | undefined;
  enabled: boolean;
  layoutKey: string;
  anchorId?: string | null | undefined;
  inspector: boolean;
  preserveViewport: boolean;
  onLayoutAspect: (aspect: number) => void;
}) {
  const initialized = useNodesInitialized();
  const width = useStore(state => state.width);
  const height = useStore(state => state.height);
  const canvas = useStore(state => state.domNode);
  const { fitView, getNodes, getNodesBounds, getEdges } = useReactFlow();
  const [windowHeight, setWindowHeight] = useState(0);
  const [spaceAbove, setSpaceAbove] = useState(0);
  const lastAutoFitKey = useRef<string | null>(null);
  useEffect(() => {
    const resize = () => setWindowHeight(window.innerHeight);
    resize();
    window.addEventListener("resize", resize);
    return () => window.removeEventListener("resize", resize);
  }, []);
  useEffect(() => {
    const frame = canvas?.closest<HTMLElement>("[data-graph-adaptive-frame]");
    if (!frame) return;
    // Clicking a control can scroll the document before its resize is measured.
    // Use a stable document offset so returning to the top does not clip the canvas.
    const measure = () => {
      const notice = frame.closest("main")?.querySelector<HTMLElement>('[aria-label="Saved snapshot updates"]');
      const noticeStyle = notice ? getComputedStyle(notice) : null;
      const noticeSpace = notice
        ? notice.getBoundingClientRect().height + (parseFloat(noticeStyle!.marginTop) || 0) + (parseFloat(noticeStyle!.marginBottom) || 0)
        : 0;
      // A late frame/control resize can arrive after a passive notice appears.
      // Exclude its space too, so it cannot change height, layout or camera.
      setSpaceAbove(Math.max(0, frame.getBoundingClientRect().top + window.scrollY - noticeSpace));
    };
    // Deliberate view controls change usable space. A new-snapshot notice
    // must not move the operator's pinned camera, so do not observe all chrome.
    const observer = new ResizeObserver(measure);
    observer.observe(frame);
    const controls = frame.closest("main")?.querySelector('[data-testid="graph-view-controls"]');
    if (controls) observer.observe(controls);
    measure();
    return () => observer.disconnect();
  }, [canvas, layoutKey]);
  useEffect(() => {
    if (!enabled || !initialized || !width || !height || !windowHeight) return;
    const frameElement = canvas?.closest<HTMLElement>("[data-graph-adaptive-frame]");
    if (!frameElement) return;
    const nodes = getNodes();
    const frameSize = graphAdaptiveFrame({
      bounds: getNodesBounds(nodes), width, inspector, nodeCount: nodes.length,
      availableHeight: windowHeight - spaceAbove - 24,
    });
    onLayoutAspect(frameSize.layoutAspect);
    frameElement.style.setProperty("--graph-adaptive-height", `${frameSize.height}px`);
    if (preserveViewport) return;
    // Virtualization toggles initialized while the operator pans or zooms.
    // Only a new layout/frame may replace that deliberate camera position.
    const autoFitKey = JSON.stringify([layoutKey, width, height, anchorId, inspector, windowHeight, spaceAbove, padding]);
    if (lastAutoFitKey.current === autoFitKey) return;
    // Frame every loaded node whenever captions stay legible at that fit; a
    // capped zoom keeps small graphs from opening as two giant cards. A graph
    // too dense to read whole opens on the anchor's neighbourhood, never a
    // lone card. The zoom controls sit bottom-left.
    const anchor = nodes.find(node => node.id === anchorId) ?? nodes[0];
    // A phone's overview is its Paths list; its Graph view keeps a dense graph's
    // anchor at full-card zoom, since summary pills below zoom 1 are unreadable there.
    const phone = width < 640;
    const focus = !frameSize.fitAll && anchor ? (phone ? [{ id: anchor.id }] : neighbourhood(anchor.id, nodes.map(node => node.id), getEdges())) : null;
    const options: FitViewOptions = { padding: { top: padding, right: padding, bottom: padding, left: phone ? padding : "72px" }, duration: 0, minZoom: 0.05, maxZoom: GRAPH_FIT_MAX_ZOOM,
      ...(focus ? phone ? { nodes: focus, minZoom: 0.85, maxZoom: 1.1 } : { nodes: focus, minZoom: legibleFitZoom(width) } : {}) };
    const fitIds = focus ? new Set(focus.map(node => node.id)) : null;
    // Convergence must measure exactly the nodes passed to fitView.
    const fittedBounds = () => getNodesBounds(fitIds ? getNodes().filter(node => fitIds.has(node.id)) : getNodes());
    let cancelled = false;
    const frames: number[] = [];
    const settle = (pass: number) => {
      const before = fittedBounds();
      void fitView(options).then(fitted => {
        // Zoom changes readable glyph/caption dimensions. Their observer and
        // React Flow measurements can finish after a second camera fit. Keep
        // fitting until measured bounds settle, with a bounded four-pass budget.
        if (cancelled) return;
        frames.push(requestAnimationFrame(() => frames.push(requestAnimationFrame(() => {
          if (cancelled) return;
          const after = fittedBounds();
          const stable = before.x === after.x && before.y === after.y && before.width === after.width && before.height === after.height;
          // Caption dimensions can oscillate around a zoom threshold. Once
          // the bounded budget is spent, keep this camera until geometry or
          // scope changes instead of restarting on virtualization updates.
          if (fitted && ((pass > 0 && stable) || pass === 3)) lastAutoFitKey.current = autoFitKey;
          else if (pass < 3) settle(pass + 1);
        }))));
      });
    };
    frames.push(requestAnimationFrame(() => settle(0)));
    return () => { cancelled = true; frames.forEach(cancelAnimationFrame); };
  }, [padding, enabled, initialized, width, height, layoutKey, anchorId, inspector, preserveViewport, windowHeight, spaceAbove, canvas, fitView, getNodes, getNodesBounds, getEdges, onLayoutAspect]);
  // The stepper walks an ordered path on a phone; a plain graph is shown whole.
  if (!initialized || width >= 640 || width <= 0 || !navigationIds?.length) return null;
  const navigator = <GraphNodeNavigator nodes={getNodes()} orderedIds={navigationIds} />;
  return navigationMount ? createPortal(navigator, navigationMount) : <Panel position="top-center">{navigator}</Panel>;
}

/** A camera target is not an access hop or a claim that the whole graph is visible. */
function GraphNodeNavigator({ nodes, orderedIds }: { nodes: Node[]; orderedIds?: string[] | undefined }) {
  const { fitView } = useReactFlow();
  const [targetId, setTargetId] = useState<string | null>(null);
  const byId = new Map(nodes.map(node => [node.id, node]));
  const ordered = orderedIds
    ? [...new Set(orderedIds)].flatMap(id => byId.has(id) ? [byId.get(id)!] : [])
    : nodes;
  const index = Math.max(0, ordered.findIndex(node => node.id === targetId));
  const target = ordered[index];
  if (ordered.length < 2 || !target) return null;
  const focus = async (node: Node) => {
    const fitted = await fitView({ nodes: [{ id: node.id }], minZoom: 0.85, maxZoom: 1, padding: 0.15, duration: 200 });
    if (fitted) setTargetId(node.id);
  };
  return <div className="mb-2 rounded-lg border border-outline bg-surface p-2">
    <div role="group" aria-label="Navigate loaded graph nodes" className="flex items-center gap-2">
      <button type="button" aria-label="Previous graph node" disabled={index === 0}
        className="graph-page-action min-h-11 px-3 disabled:opacity-40"
        onClick={() => void focus(ordered[index - 1]!)}>Previous</button>
      <div className="min-w-0 flex-1 text-center text-xs text-ink-secondary" aria-live="polite">
        <span>Canvas target · {index + 1} of {ordered.length}</span>
        <button type="button" className="block w-full truncate text-foreground underline underline-offset-4"
          aria-label={`Center graph node: ${String(target.data.label ?? target.id)}`} onClick={() => void focus(target)}>
          {String(target.data.label ?? target.id)}
        </button>
        <span className="block">Pan for connections · Fit all for overview</span>
      </div>
      <button type="button" aria-label="Next graph node" disabled={index >= ordered.length - 1}
        className="graph-page-action min-h-11 px-3 disabled:opacity-40"
        onClick={() => void focus(ordered[index + 1]!)}>Next</button>
    </div>
  </div>;
}

/** The anchor and up to six of its direct neighbours, so a dense graph still opens on context. */
function neighbourhood(anchorId: string, visibleIds: string[], edges: { source: string; target: string }[]) {
  const targets = graphInspectorTargets(anchorId, visibleIds, edges);
  if (targets.length > 1) return targets;
  const visible = new Set(visibleIds);
  const ids = new Set([anchorId]);
  for (const edge of edges) {
    if (ids.size >= 7) break;
    const other = edge.source === anchorId ? edge.target : edge.target === anchorId ? edge.source : null;
    if (other && visible.has(other)) ids.add(other);
  }
  return [...ids].map(id => ({ id }));
}
