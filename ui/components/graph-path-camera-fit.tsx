"use client";

import { useEffect, useRef } from "react";
import { useReactFlow, type FitViewOptions } from "@xyflow/react";

/**
 * Frames a focused attack path once its layout has settled. React Flow's
 * `fitView` prop fits only the first measured frame, which can still hold the
 * pre-layout positions; this refits on the final ones, once per path and layout,
 * and never after the reader moved the camera.
 */
export function GraphPathCameraFit({ enabled, fitKey, options }: { enabled: boolean; fitKey: string; options: FitViewOptions }) {
  const { fitView } = useReactFlow();
  const done = useRef<string | null>(null);
  useEffect(() => {
    if (!enabled || done.current === fitKey) return;
    const frame = requestAnimationFrame(() => {
      done.current = fitKey;
      void fitView(options);
    });
    return () => cancelAnimationFrame(frame);
  }, [enabled, fitKey, fitView, options]);
  return null;
}
