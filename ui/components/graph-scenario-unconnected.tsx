import type { Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { entityIcon } from "@/lib/entity-icons";

/** Disconnected modeled items remain inspectable without implying new edges. */
export function GraphScenarioUnconnected({ nodes, notes, selectedId, onSelect }: {
  nodes: Node<LineageNodeData>[];
  notes: ReadonlyMap<string, string>;
  selectedId: string | null;
  onSelect: (node: Node<LineageNodeData>) => void;
}) {
  if (nodes.length === 0) return null;
  return (
    <section aria-label="Unconnected proposal items" className="order-last max-h-48 shrink-0 overflow-y-auto border-t border-outline bg-surface-secondary p-3">
      <h3 className="text-sm font-semibold text-foreground">Unconnected proposal items</h3>
      <p className="mt-1 text-xs leading-5 text-ink-secondary">{nodes.length} {nodes.length === 1 ? "item has" : "items have"} no connection in the supplied proposal.</p>
      <ul className="mt-2 grid gap-2 sm:grid-cols-2">
        {nodes.map(node => {
          const Icon = entityIcon(node.data.nodeType);
          return <li key={node.id}>
            <button type="button" aria-pressed={selectedId === node.id} onClick={() => onSelect(node)} className="w-full rounded-lg border border-outline bg-surface p-3 text-left hover:bg-surface-tertiary focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary aria-pressed:border-primary">
              <span className="flex items-start gap-2 text-sm font-medium text-foreground"><Icon aria-hidden className="mt-0.5 size-4 shrink-0" /><span className="min-w-0 break-words">{node.data.label}</span></span>
              <span className="mt-2 block text-xs leading-5 text-ink-secondary">{notes.get(node.id)}</span>

            </button>
          </li>;
        })}
      </ul>
    </section>
  );
}
