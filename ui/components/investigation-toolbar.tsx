"use client";

import { ChevronLeft, ChevronRight, SlidersHorizontal } from "lucide-react";

import { PathToolbarLead } from "@/components/path-view-toolbar";

export type InvestigationStepper = {
  overview: boolean;
  nodeCount: number;
  index: number;
  count: number;
  onPrevious: () => void;
  onNext: () => void;
  onReadable: () => void;
};

/**
 * The single control row above the investigation canvas. On a phone the graph
 * actions fold into one options menu; the node stepper appears only when the
 * path is too long to show whole.
 */
export function InvestigationToolbar({ embedded, compact, stepper, controls, layoutControls }: {
  embedded: boolean;
  compact: boolean;
  stepper: InvestigationStepper | null;
  controls: React.ReactNode;
  layoutControls: React.ReactNode;
}) {
  return (
    <div
      role="toolbar"
      aria-label="Graph controls"
      className={`flex shrink-0 flex-wrap items-center justify-end border-b border-outline bg-surface py-2 ${compact ? "gap-1.5 px-2" : "gap-2 px-3"}`}
      data-testid="security-graph-interaction-band"
    >
      {embedded && <PathToolbarLead compact={Boolean(stepper)} />}
      {compact ? <>
        {stepper && <StepperControls stepper={stepper} />}
        <details className="relative">
          <summary aria-label="Graph options" title="Graph options" className="graph-page-action flex min-h-11 min-w-11 justify-center cursor-pointer list-none items-center [&::-webkit-details-marker]:hidden"><SlidersHorizontal className="h-4 w-4" /><span className="sr-only">Graph options</span></summary>
          <div className="absolute right-0 top-full z-20 mt-2 flex w-64 max-w-[75vw] flex-wrap gap-2 rounded-xl border border-outline bg-surface p-2 shadow-lg">
            {controls}
            {layoutControls}
            {stepper && <button type="button" className="graph-page-action" onClick={stepper.onReadable}>Readable view</button>}
          </div>
        </details>
      </> : <>
        {controls}
        {layoutControls && (embedded ? <details className="relative">
          <summary className="graph-page-action cursor-pointer">Layout</summary>
          <div className="absolute right-0 top-full z-20 mt-2 rounded-xl border border-outline bg-surface p-2 shadow-lg">{layoutControls}</div>
        </details> : layoutControls)}
      </>}
    </div>
  );
}

function StepperControls({ stepper }: { stepper: InvestigationStepper }) {
  return <>
    <span className="mr-auto text-xs text-ink-secondary" aria-live="polite"
      title="The focused viewport shows part of the loaded graph. Navigate between nodes or pan to inspect connections.">
      <span className="sr-only">{stepper.overview ? "Overview · " : "Focused view · "}</span>
      {stepper.overview ? `${stepper.nodeCount} nodes` : `${stepper.index + 1} of ${stepper.count}`}
    </span>
    <div className="flex gap-1">
      <button type="button" aria-label="Previous graph node" disabled={stepper.index === 0}
        className="graph-page-action min-h-11 min-w-11 justify-center px-1 disabled:opacity-40"
        onClick={stepper.onPrevious}><ChevronLeft className="h-4 w-4" /></button>
      <button type="button" aria-label="Next graph node" disabled={stepper.index >= stepper.count - 1}
        className="graph-page-action min-h-11 min-w-11 justify-center px-1 disabled:opacity-40"
        onClick={stepper.onNext}><ChevronRight className="h-4 w-4" /></button>
    </div>
  </>;
}
