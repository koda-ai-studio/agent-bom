"use client";

import { useStore, ViewportPortal } from "@xyflow/react";

/** Reading guides, never synthetic graph entities or ownership boundaries. */
export function GraphCloudGroups() {
  const nodes = useStore(state => state.nodes);
  const visible = nodes.filter(node => !node.hidden);
  if (!visible.length || visible.some(node => typeof node.data.readingGroup !== "string")) return null;
  const groups = new Map<string, typeof visible>();
  for (const node of visible) {
    const group = String(node.data.readingGroup);
    groups.set(group, [...(groups.get(group) ?? []), node]);
  }
  const top = Math.min(...visible.map(node => node.position.y));
  return <ViewportPortal>
    <div className="pointer-events-none absolute inset-0" style={{ zIndex: -1 }} aria-label="Asset categories">
      {[...groups].map(([group, members]) => {
        const left = Math.min(...members.map(node => node.position.x)) - 28;
        const width = Math.max(...members.map(node => node.position.x + (node.measured?.width ?? 340))) - left + 28;
        return <div key={group} data-graph-category={group} className="absolute"
          style={{ left, top, width, height: 80 }}>
          <div className="px-4 py-4 text-center font-semibold text-ink-secondary" style={{ fontSize: "var(--graph-node-label-size, 18px)" }}>{group}</div>
        </div>;
      })}
    </div>
  </ViewportPortal>;
}
