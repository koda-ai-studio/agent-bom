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
    <section aria-label="Unconnected proposal items" className="order-last max-h-48 shrink-0 overflow-y-auto border-t border-outline bg-surface-secondary p-2">
      <h3 className="text-sm font-semibold text-foreground">Unconnected proposal items <span className="font-normal text-ink-secondary">· {nodes.length}</span></h3>
      <ul className="mt-2 grid gap-2 sm:grid-cols-2">
        {nodes.map(node => {
          const Icon = entityIcon(node.data.nodeType);
          return <li key={node.id}>
            <button type="button" aria-pressed={selectedId === node.id} onClick={() => onSelect(node)} className="w-full rounded-lg border border-outline bg-surface p-2 text-left hover:bg-surface-tertiary focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary aria-pressed:border-primary">
              <span className="flex items-start gap-2 text-sm font-medium text-foreground"><Icon aria-hidden className="mt-0.5 size-4 shrink-0" /><span className="min-w-0 break-words">{node.data.label}</span></span>
              <span className="mt-1 block text-xs leading-5 text-ink-secondary">{notes.get(node.id)}</span>

            </button>
          </li>;
        })}
      </ul>
    </section>
  );
}
