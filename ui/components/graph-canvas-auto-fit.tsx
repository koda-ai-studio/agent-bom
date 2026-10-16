"use client";

import { useEffect, useState } from "react";
import { getNodesBounds, useNodesInitialized, useReactFlow, useStore } from "@xyflow/react";
import { graphAdaptiveFrame } from "@/lib/graph-adaptive-frame";

/** Fit measured compact contexts after a docked inspector changes canvas width.
 * Only geometry changes trigger a fit; hover and evidence updates do not. */
export function GraphCanvasAutoFit({ enabled, layoutKey, anchorId, inspector, preserveViewport, onLayoutAspect }: {
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
  const { fitView, getNodes } = useReactFlow();
  const [windowHeight, setWindowHeight] = useState(0);
  const [spaceAbove, setSpaceAbove] = useState(0);
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
    // Opening filters can move the canvas without changing its width. Observe
    // the preceding chrome, not graph mutations or every pan/hover frame.
    const observer = new ResizeObserver(measure);
    observer.observe(frame);
    for (let element: Element | null = frame; element && element.tagName !== "MAIN"; element = element.parentElement) {
      for (let sibling = element.previousElementSibling; sibling; sibling = sibling.previousElementSibling) observer.observe(sibling);
    }
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
    const frame = requestAnimationFrame(() => {
      const anchor = nodes.find(node => node.id === anchorId) ?? nodes[0];
      void fitView({ padding: 0.08, duration: 0, minZoom: 0.05, maxZoom: 2,
        ...(!frameSize.fitAll && anchor ? { nodes: [{ id: anchor.id }], minZoom: 0.85, maxZoom: 1.1 } : {}),
      });
    });
    return () => cancelAnimationFrame(frame);
  }, [enabled, initialized, width, height, layoutKey, anchorId, inspector, preserveViewport, windowHeight, spaceAbove, canvas, fitView, getNodes, onLayoutAspect]);
  return null;
}
