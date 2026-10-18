"use client";

import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Panel, useNodesInitialized, useReactFlow, useStore, type Node, type FitViewOptions } from "@xyflow/react";
import { graphInspectorTargets } from "@/lib/graph-inspector-framing";
import { graphAdaptiveFrame } from "@/lib/graph-adaptive-frame";

/** Fit measured compact contexts after a docked inspector changes canvas width.
 * Only geometry changes trigger a fit; hover and evidence updates do not. */
export function GraphCanvasAutoFit({ enabled, layoutKey, anchorId, inspector, preserveViewport, onLayoutAspect, navigationIds, navigationMount }: {
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
    const measure = () => setSpaceAbove(Math.max(0, frame.getBoundingClientRect().top));
    // Deliberate view controls change usable space. A new-snapshot notice
    // must not move the operator's pinned camera, so do not observe all chrome.
    const observer = new ResizeObserver(measure);
    observer.observe(frame);
    const controls = frame.closest("main")?.querySelector('[data-testid="graph-view-controls"]');
    if (controls) observer.observe(controls);
    measure();
    return () => observer.disconnect();
  }, [canvas]);
  useEffect(() => {
    if (!enabled || !initialized || !width || !height || !windowHeight) return;
    const frameElement = canvas?.closest<HTMLElement>("[data-graph-adaptive-frame]");
    if (!frameElement) return;
    const nodes = getNodes();
    const frameSize = graphAdaptiveFrame({
      bounds: getNodesBounds(nodes), width, inspector,
      availableHeight: windowHeight - spaceAbove - 24,
    });
    onLayoutAspect(frameSize.layoutAspect);
    frameElement.style.setProperty("--graph-adaptive-height", `${frameSize.height}px`);
    if (preserveViewport) return;
    // Virtualization toggles initialized while the operator pans or zooms.
    // Only a new layout/frame may replace that deliberate camera position.
    const autoFitKey = JSON.stringify([layoutKey, width, height, anchorId, inspector, windowHeight, spaceAbove]);
    if (lastAutoFitKey.current === autoFitKey) return;
    const anchor = nodes.find(node => node.id === anchorId) ?? nodes[0];
    const options: FitViewOptions = { padding: 0.08, duration: 0, minZoom: 0.05, maxZoom: 2,
      ...(!frameSize.fitAll && anchor ? { nodes: inspector && width >= 640 ? graphInspectorTargets(anchor.id, nodes.map(node => node.id), getEdges()) : [{ id: anchor.id }], minZoom: inspector && width >= 640 ? 0.45 : 0.85, maxZoom: 1.1 } : {}),
    };
    let cancelled = false;
    const frames: number[] = [];
    const settle = (pass: number) => {
      const before = getNodesBounds(getNodes());
      void fitView(options).then(fitted => {
        // Zoom changes readable glyph/caption dimensions. Their observer and
        // React Flow measurements can finish after a second camera fit. Keep
        // fitting until measured bounds settle, with a bounded four-pass budget.
        if (cancelled) return;
        frames.push(requestAnimationFrame(() => frames.push(requestAnimationFrame(() => {
          if (cancelled) return;
          const after = getNodesBounds(getNodes());
          const stable = before.x === after.x && before.y === after.y && before.width === after.width && before.height === after.height;
          if (pass > 0 && fitted && stable) lastAutoFitKey.current = autoFitKey;
          else if (pass < 3) settle(pass + 1);
        }))));
      });
    };
    frames.push(requestAnimationFrame(() => settle(0)));
    return () => { cancelled = true; frames.forEach(cancelAnimationFrame); };
  }, [enabled, initialized, width, height, layoutKey, anchorId, inspector, preserveViewport, windowHeight, spaceAbove, canvas, fitView, getNodes, getNodesBounds, getEdges, onLayoutAspect]);
  if (!initialized || width >= 640 || width <= 0) return null;
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
