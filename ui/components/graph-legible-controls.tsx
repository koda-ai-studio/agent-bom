"use client";

import { ControlButton, Controls, useReactFlow, type FitViewOptions } from "@xyflow/react";
import { Maximize } from "lucide-react";
import type { ComponentProps } from "react";

import { legibleFit } from "@/lib/graph-adaptive-frame";

type Props = Omit<ComponentProps<typeof Controls>, "showFitView" | "fitViewOptions" | "onFitView"> & {
  /** Lowest zoom at which this canvas's card text is still at least 11px on screen. */
  floor: number;
  fitOptions?: FitViewOptions;
  /** The canvas's own whole-graph fit; it must apply the same floor. */
  onFit?: () => void;
};

/**
 * React Flow's controls with a fit button that never zooms below the canvas's legible floor.
 * The stock button fits at the canvas's `minZoom`, which can draw card text at a few pixels.
 */
export function LegibleFitControls({ floor, fitOptions, onFit, children, ...props }: Props) {
  const { fitView } = useReactFlow();
  return <Controls {...props} showFitView={false}>
    <ControlButton className="react-flow__controls-fitview" title="Fit View" aria-label="Fit View"
      onClick={() => { if (onFit) onFit(); else void fitView(legibleFit(fitOptions ?? {}, floor)); }}>
      <Maximize aria-hidden="true" />
    </ControlButton>
    {children}
  </Controls>;
}
