import type { InvestigationContextGroup } from "@/lib/graph-investigation-context";

export function GraphInvestigationContextControls({ groups, selected, visibleNodes, loadedNodes, crossContextEdges, onSelect, inline = false }: {
  groups: InvestigationContextGroup[];
  selected: string;
  visibleNodes: number;
  loadedNodes: number;
  crossContextEdges: number;
  onSelect: (id: string) => void;
  inline?: boolean;
}) {
  const choices = [...groups, { id: "all", label: "All relationships", nodeIds: [] }];
  const note = `${visibleNodes} of ${loadedNodes} nodes in this view.${crossContextEdges > 0 ? ` ${crossContextEdges} relationship${crossContextEdges === 1 ? " crosses" : "s cross"} groups; choose All relationships to inspect them.` : ""}${selected === "all" ? " Access relationships are context, not a containment hierarchy." : ""}`;
  return <section aria-label="Investigation context" title={inline ? note : undefined}
    className={inline ? "shrink-0 sm:flex sm:items-center sm:gap-2" : "shrink-0 rounded-lg border border-outline bg-surface px-3 py-2 sm:flex sm:items-center sm:gap-3"}>
    <label className="flex items-center gap-2 text-sm sm:hidden">
      <span>Context</span>
      <select aria-label="Graph context" value={selected} onChange={event => onSelect(event.target.value)}
        className="min-h-11 min-w-0 flex-1 rounded-md border border-outline bg-surface px-2 text-foreground">
        {choices.map(group => <option key={group.id} value={group.id}>{group.label}</option>)}
      </select>
    </label>
    <div className="hidden shrink-0 flex-wrap items-center gap-2 sm:flex">
      {choices.map(group =>
        <button key={group.id} type="button" aria-pressed={selected === group.id} onClick={() => onSelect(group.id)}
          className={`${inline ? "min-h-8 px-2.5 text-xs" : "min-h-11 px-3 text-sm"} rounded-md border ${selected === group.id ? "border-emerald-500/50 bg-emerald-500/10 text-foreground" : "border-outline text-ink-secondary hover:text-foreground"}`}>
          {group.label}
        </button>)}
    </div>
    {/* Inline, the note stays readable to screen readers and as a tooltip; cross-group links stay visible. */}
    <p className={inline ? "sr-only" : "mt-2 min-w-0 flex-1 text-xs text-ink-secondary sm:mt-0"}>{note}</p>
    {inline && crossContextEdges > 0 && <span aria-hidden="true" className="text-xs text-ink-secondary">{crossContextEdges} cross-group</span>}
  </section>;
}
