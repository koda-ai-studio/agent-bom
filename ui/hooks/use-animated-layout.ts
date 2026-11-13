"use client";

import { useLayoutEffect, useRef, useState } from "react";
import type { Node } from "@xyflow/react";

import { prefersReducedMotion } from "@/lib/reduced-motion";

/** One layout change, start to finish. */
export const LAYOUT_MOTION_MS = 260;
/** Past this many cards a moving frame costs more than it helps; the layout changes at once. */
const MAX_ANIMATED_NODES = 150;

type Point = { x: number; y: number };

/**
 * One frame of a layout change at progress `t` (0..1, eased out): a node that
 * was already drawn moves from where it was toward its new place, and a new
 * node fades in at its new place. Edges follow because they are drawn from
 * these positions.
 */
export function layoutFrame<N extends Node>(from: ReadonlyMap<string, Point>, to: N[], t: number): N[] {
  const k = 1 - (1 - Math.min(1, Math.max(0, t))) ** 3;
  return to.map(node => {
    const start = from.get(node.id);
    return start
      ? { ...node, position: { x: start.x + (node.position.x - start.x) * k, y: start.y + (node.position.y - start.y) * k } }
      : { ...node, style: { ...node.style, opacity: k } };
  });
}

const positions = (nodes: readonly Node[]) => new Map(nodes.map(node => [node.id, node.position]));

/**
 * Expanding, drilling down, filtering or switching a view moves the cards to
 * their new places instead of jumping, so the reader keeps their place. It runs
 * once per change, never continuously, and not at all under reduced motion,
 * while the reader drags, or on a very large map. `animating` lets the camera
 * wait for the final positions before it frames them.
 */
export function useAnimatedLayout<N extends Node>(nodes: N[], disabled = false): { nodes: N[]; animating: boolean } {
  const [frame, setFrame] = useState<N[] | null>(null);
  const shown = useRef<Map<string, Point>>(new Map());

  useLayoutEffect(() => {
    const from = shown.current;
    const moved = nodes.some(node => {
      const before = from.get(node.id);
      return !before || Math.abs(before.x - node.position.x) > 1 || Math.abs(before.y - node.position.y) > 1;
    });
    shown.current = positions(nodes);
    if (prefersReducedMotion() || disabled || !from.size || !moved || nodes.length > MAX_ANIMATED_NODES) { setFrame(null); return; }
    const start = performance.now();
    let id = 0;
    // Each frame records what is on screen, so a change mid-move continues from there.
    const step = () => {
      const t = (performance.now() - start) / LAYOUT_MOTION_MS;
      const next = t < 1 ? layoutFrame(from, nodes, t) : null;
      shown.current = positions(next ?? nodes);
      if (next) id = requestAnimationFrame(step);
      setFrame(next);
    };
    step();
    return () => cancelAnimationFrame(id);
  }, [nodes, disabled]);

  return frame ? { nodes: frame, animating: true } : { nodes, animating: false };
}
