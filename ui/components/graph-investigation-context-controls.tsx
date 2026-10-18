import type { InvestigationContextGroup } from "@/lib/graph-investigation-context";

export function GraphInvestigationContextControls({ groups, selected, visibleNodes, loadedNodes, crossContextEdges, onSelect }: {
  groups: InvestigationContextGroup[];
  selected: string;
  visibleNodes: number;
  loadedNodes: number;
  crossContextEdges: number;
  onSelect: (id: string) => void;
}) {
  const choices = [...groups, { id: "all", label: "All relationships", nodeIds: [] }];
  return <section aria-label="Investigation context" className="shrink-0 rounded-lg border border-outline bg-surface px-3 py-2">
    <label className="flex items-center gap-2 text-sm sm:hidden">
      <span>Context</span>
      <select aria-label="Graph context" value={selected} onChange={event => onSelect(event.target.value)}
        className="min-h-11 min-w-0 flex-1 rounded-md border border-outline bg-surface px-2 text-foreground">
        {choices.map(group => <option key={group.id} value={group.id}>{group.label}</option>)}
      </select>
    </label>
    <div className="hidden flex-wrap items-center gap-2 sm:flex">
      {choices.map(group =>
        <button key={group.id} type="button" aria-pressed={selected === group.id} onClick={() => onSelect(group.id)}
          className={`min-h-11 rounded-md border px-3 text-sm ${selected === group.id ? "border-emerald-500/50 bg-emerald-500/10 text-foreground" : "border-outline text-ink-secondary hover:text-foreground"}`}>
          {group.label}
        </button>)}
    </div>
    <p className="mt-2 text-xs text-ink-secondary">
      {visibleNodes} of {loadedNodes} loaded nodes shown.
      {crossContextEdges > 0 && ` ${crossContextEdges} relationship${crossContextEdges === 1 ? " crosses" : "s cross"} groups; choose All relationships to inspect them.`}
      {selected === "all" && " Access relationships are context, not a containment hierarchy."}
    </p>
  </section>;
}
