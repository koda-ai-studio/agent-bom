"use client";

import { Background, ReactFlow, ReactFlowProvider } from "@xyflow/react";
import { useMemo, useState, type ComponentProps, type CSSProperties } from "react";
import { GraphRollupDecisionSurface } from "@/components/graph-rollup-decision-surface";
import { lineageNodeTypes } from "@/components/lineage-nodes";
import { relationshipEdgeTypes } from "@/components/relationship-edge";
import { buildScopePreview } from "@/lib/graph-scope-preview";
import { useNarrowViewport } from "@/hooks/use-narrow-viewport";
import { CONTROLS_CLASS } from "@/lib/graph-utils";
import { legibleZoomForText } from "@/lib/graph-adaptive-frame";
import { LegibleFitControls } from "@/components/graph-legible-controls";

type Props = ComponentProps<typeof GraphRollupDecisionSurface>;

/** Start with readable recorded connections; keep the complete returned directory one click away. */
/** Cards here draw 14px metadata at layout size, so a fit stops where it is still 11px on screen. */
const SCOPE_FIT = { padding: 0.12, minZoom: legibleZoomForText(14), maxZoom: 1 };

export function GraphScopeOverview(props: Props) {
  const [showList, setShowList] = useState(false);
  const [rootId, setRootId] = useState<string>();
  const [edgeDetail, setEdgeDetail] = useState<string>();
  const narrow = useNarrowViewport();
  const preview = useMemo(() => buildScopePreview(props.items, props.edges, rootId) ?? buildScopePreview(props.items, props.edges), [props.items, props.edges, rootId]);
  if (!preview || props.edges.length < 3) return <GraphRollupDecisionSurface {...props} />;
  return <section data-testid="graph-scope-overview" className="overflow-hidden rounded-2xl bg-surface">
    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-outline px-4 py-3">
      <div className="flex min-w-0 flex-wrap items-center gap-3">
        <span className="text-sm font-semibold text-foreground">Recorded connections</span>
        {!showList && <label className="min-w-0 text-sm"><span className="sr-only">Connection scope</span>
          <select value={preview.root.id} onChange={event => { setRootId(event.target.value); setEdgeDetail(undefined); }} className="max-w-[min(440px,70vw)] rounded-lg border border-outline bg-surface px-3 py-2 text-foreground">
            {preview.roots.map(root => <option key={root.id} value={root.id}>{root.label}</option>)}
          </select>
        </label>}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {!showList && <button type="button" className="graph-page-action" onClick={() => props.onInvestigate(preview.root)}>Inspect this scope</button>}
        <button type="button" className="graph-page-action" onClick={() => setShowList(value => !value)}>{showList ? "Show connections" : `Browse all ${props.items.length} nodes and scopes`}</button>
      </div>
    </div>
    {showList ? <GraphRollupDecisionSurface {...props} /> : <>
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-3 text-xs text-ink-secondary">
        <span>{preview.shownRelationships} of {preview.availableRelationships} loaded relationships for this scope{props.completeness?.truncated ? " · partial inventory" : ""}</span>
      </div>
      {edgeDetail && <p role="status" className="px-4 pt-3 text-sm text-ink-secondary">{edgeDetail}</p>}
      <ReactFlowProvider key={`${preview.root.id}:${narrow}`}>
        <div style={{ height: narrow ? preview.nodes.length * 230 : 560 }} data-testid="graph-scope-connections">
          <ReactFlow nodes={narrow ? preview.nodes.map((node, index) => ({ ...node, position: { x: 0, y: index * 230 } })) : preview.nodes}
            style={{ "--graph-node-meta-size": "14px" } as CSSProperties}
            edges={narrow ? preview.edges.map(edge => ({ ...edge, sourceHandle: null, targetHandle: "context" })) : preview.edges} nodeTypes={lineageNodeTypes} edgeTypes={relationshipEdgeTypes}
            fitView fitViewOptions={SCOPE_FIT} minZoom={0.35} maxZoom={1.5}
            nodesDraggable={false} nodesConnectable={false} proOptions={{ hideAttribution: true }}
            onEdgeClick={(_, edge) => { const recorded = props.edges.find(row => row.source === edge.source && row.target === edge.target); if (recorded) setEdgeDetail(`${recorded.count} recorded relationship${recorded.count === 1 ? "" : "s"}: ${recorded.relationships.join(", ").replaceAll("_", " ")} · ${recorded.directions?.join(", ") || "direction not recorded"}.`); }}
            onNodeClick={(_, node) => { const item = props.items.find(item => item.id === node.id); if (item) props.onInvestigate(item); }}>
            <Background color="var(--border-subtle)" gap={20} size={1} />
            <LegibleFitControls floor={SCOPE_FIT.minZoom} fitOptions={SCOPE_FIT} showInteractive={false} className={CONTROLS_CLASS} />
          </ReactFlow>
        </div>
      </ReactFlowProvider>
    </>}
  </section>;
}
