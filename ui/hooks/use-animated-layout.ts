"use client";

import { useLayoutEffect, useRef, useState } from "react";
import type { Node } from "@xyflow/react";

import { useReducedMotion } from "@/hooks/use-reduced-motion";

/** One layout change, start to finish. */
export const LAYOUT_MOTION_MS = 260;
/** Past this many cards a moving frame costs more than it helps; the layout changes at once. */
const MAX_ANIMATED_NODES = 150;

type Point = { x: number; y: number };
const easeOut = (t: number) => 1 - (1 - t) ** 3;

/**
 * One frame of a layout change at progress `t` (0..1): a node that was already
 * drawn moves from where it was toward its new place, and a new node fades in
 * at its new place. Edges follow because they are drawn from these positions.
 */
export function layoutFrame<N extends Node>(from: ReadonlyMap<string, Point>, to: N[], t: number): N[] {
  const k = easeOut(Math.min(1, Math.max(0, t)));
  return to.map(node => {
    const start = from.get(node.id);
    if (!start) return { ...node, style: { ...node.style, opacity: k } };
    return { ...node, position: { x: start.x + (node.position.x - start.x) * k, y: start.y + (node.position.y - start.y) * k } };
  });
}

function positions(nodes: readonly Node[]): Map<string, Point> {
  return new Map(nodes.map(node => [node.id, node.position]));
}

/**
 * Expanding, drilling down, filtering or switching a view moves the cards to
 * their new places instead of jumping, so the reader keeps their place. It runs
 * once per change, never continuously, and not at all under reduced motion,
 * while the reader drags, or on a very large map. `animating` lets the camera
 * wait for the final positions before it frames them.
 */
export function useAnimatedLayout<N extends Node>(nodes: N[], disabled = false): { nodes: N[]; animating: boolean } {
  const reduced = useReducedMotion();
  const [frame, setFrame] = useState<N[] | null>(null);
  const shown = useRef<Map<string, Point>>(new Map());
  const raf = useRef<number | null>(null);

  useLayoutEffect(() => {
    if (raf.current !== null) cancelAnimationFrame(raf.current);
    raf.current = null;
    const from = shown.current;
    const moved = nodes.some(node => {
      const before = from.get(node.id);
      return before ? Math.abs(before.x - node.position.x) > 1 || Math.abs(before.y - node.position.y) > 1 : true;
    });
    if (reduced || disabled || from.size === 0 || !moved || nodes.length > MAX_ANIMATED_NODES) {
      shown.current = positions(nodes);
      setFrame(null);
      return;
    }
    const start = performance.now();
    setFrame(layoutFrame(from, nodes, 0));
    const step = () => {
      const t = (performance.now() - start) / LAYOUT_MOTION_MS;
      if (t >= 1) {
        raf.current = null;
        shown.current = positions(nodes);
        setFrame(null);
        return;
      }
      const next = layoutFrame(from, nodes, t);
      shown.current = positions(next);
      setFrame(next);
      raf.current = requestAnimationFrame(step);
    };
    raf.current = requestAnimationFrame(step);
    return () => { if (raf.current !== null) cancelAnimationFrame(raf.current); };
  }, [nodes, reduced, disabled]);

  return frame ? { nodes: frame, animating: true } : { nodes, animating: false };
}
