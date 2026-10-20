"use client";

import { ReactFlowProvider } from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import { GraphPageView } from "@/components/graph-page-view";
import { useGraphCanvasModel } from "@/hooks/use-graph-canvas-model";
import { useGraphPageActions } from "@/hooks/use-graph-page-actions";
import { useGraphPageData } from "@/hooks/use-graph-page-data";

export { DiffPreview } from "@/components/graph-snapshot-diff";
export { graphFetchLimitForSnapshot, knownGraphTotal, queryResponseToGraphResponse } from "@/lib/graph-page-data";

/** One xyflow store for the page, so the camera, LOD band and canvas share a viewport. */
export default function GraphPageClient() {
  return (
    <ReactFlowProvider>
      <GraphPageInner />
    </ReactFlowProvider>
  );
}

/** Data, canvas model and interactions compose into the view; each owns one concern. */
function GraphPageInner() {
  const data = useGraphPageData();
  const model = useGraphCanvasModel(data);
  const actions = useGraphPageActions({ ...data, ...model });
  return <GraphPageView page={{ ...data, ...model, ...actions }} />;
}
