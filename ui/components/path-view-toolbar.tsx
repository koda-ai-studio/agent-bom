"use client";

import { createContext, useCallback, useContext, useLayoutEffect, useMemo, useState } from "react";
import type { LucideIcon } from "lucide-react";
import { List, Network } from "lucide-react";

/**
 * Which single representation of the selected path is shown. The command center
 * used to stack the path DAG, the neighbor list, and a full interactive graph
 * all at once; the toggle collapses that to one view at a time.
 */
export type ExposurePathView = "path" | "graph" | "list";

const PATH_VIEW_ITEMS: { key: ExposurePathView; label: string; icon: LucideIcon }[] = [
  { key: "graph", label: "Graph", icon: Network },
  { key: "list", label: "Connections", icon: List },
];

export function PathViewToggle({ view, onChange }: {
  view: ExposurePathView;
  onChange: (next: ExposurePathView) => void;
}) {
  return (
    <div role="group" aria-label="Exposure path view" className="ep-view-toggle shrink-0">
      {PATH_VIEW_ITEMS.map(({ key, label, icon: Icon }) => {
        const active = view === key;
        return (
          <button key={key} type="button" onClick={() => onChange(key)} aria-pressed={active} aria-label={label} title={label}
            className={`flex min-h-8 items-center justify-center gap-1.5 px-2.5 py-1 text-xs font-medium transition max-sm:min-h-11 max-sm:min-w-11 ${
              active ? "bg-emerald-600 text-white" : "text-ink-secondary hover:text-foreground"
            }`}>
            <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            <span className="max-sm:sr-only">{label}</span>
          </button>
        );
      })}
    </div>
  );
}

type ToolbarLead = { lead: React.ReactNode; claim: () => () => void };

const PathToolbarLeadContext = createContext<ToolbarLead | null>(null);

/**
 * Lets an embedded graph host the path view toggle in its own toolbar so the
 * card shows one control row. Until a toolbar claims it, `claimed` stays false
 * and the card renders the toggle itself.
 */
export function usePathToolbarLead(lead: React.ReactNode) {
  const [claims, setClaims] = useState(0);
  const claim = useCallback(() => {
    setClaims(count => count + 1);
    return () => setClaims(count => count - 1);
  }, []);
  const value = useMemo(() => ({ lead, claim }), [lead, claim]);
  return { claimed: claims > 0, value };
}

export function PathToolbarLeadProvider({ value, children }: { value: ToolbarLead; children: React.ReactNode }) {
  return <PathToolbarLeadContext.Provider value={value}>{children}</PathToolbarLeadContext.Provider>;
}

/** Renders the card's view toggle at the start of a graph toolbar, when hosted in one. */
export function PathToolbarLead({ compact = false }: { compact?: boolean }) {
  const context = useContext(PathToolbarLeadContext);
  const claim = context?.claim;
  useLayoutEffect(() => claim?.(), [claim]);
  return context ? <div className={`flex items-center ${compact ? "" : "mr-auto"}`}>{context.lead}</div> : null;
}
