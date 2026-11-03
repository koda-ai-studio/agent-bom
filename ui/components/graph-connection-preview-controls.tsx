import type { graphConnectionPreview } from "@/lib/graph-connection-preview";

export function GraphConnectionPreviewControls({ preview, expanded, onRoot, onExpanded, onExplore }: {
  preview: NonNullable<ReturnType<typeof graphConnectionPreview>>;
  expanded: boolean;
  onRoot: (id: string) => void;
  onExpanded: (expanded: boolean) => void;
  onExplore: () => void;
}) {
  return <div role="group" aria-label="Connection preview" className="flex w-full min-w-0 flex-wrap items-center gap-2 text-xs text-ink-secondary">
    {expanded ? <button className="graph-page-action" onClick={() => onExpanded(false)}>Return to connection preview</button> : <>
      <span>Connection preview · {preview.nodes.length} of {preview.totalNodes} nodes in this map · {preview.edges.length} of {preview.totalEdges} relationships</span>
      <label className="flex min-w-0 items-center gap-2">Start at
        <select aria-label="Preview starting point" className="graph-page-action max-w-64 min-w-0" value={preview.root.id} onChange={event => onRoot(event.target.value)}>
          {preview.roots.map(node => <option key={node.id} value={node.id}>{node.data.label}</option>)}
        </select>
      </label>
      <button className="graph-page-action" onClick={onExplore}>Explore these connections</button>
      <button className="graph-page-action" onClick={() => onExpanded(true)}>Show full map ({preview.totalNodes})</button>
    </>}
  </div>;
}
