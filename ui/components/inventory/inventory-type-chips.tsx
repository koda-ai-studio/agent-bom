"use client";

import { useMemo } from "react";

import { useInventory } from "@/lib/inventory-context";
import type { AssetKindConfig } from "@/lib/inventory";
import { capitalize, entityTypeLabel, kindTypeCounts } from "@/lib/inventory-units";

const CHIP =
  "inline-flex h-7 items-center gap-1.5 rounded-full border px-2.5 text-xs transition-colors focus-visible:outline-2 focus-visible:outline-offset-2";
const CHIP_ON = "border-outline-strong bg-surface-muted font-medium text-foreground";
const CHIP_OFF = "border-outline bg-surface text-ink-secondary hover:bg-surface-muted";

/**
 * One chip per entity type in a multi-type kind. Counts come from the same
 * summary that feeds the inventory cards, so the primary-type chip equals the
 * card headline and the other chips equal its breakdown.
 */
export function InventoryTypeChips({ kind }: { kind: AssetKindConfig }) {
  const { summary, filters, setFilter } = useInventory();
  const counts = useMemo(() => (summary ? kindTypeCounts(kind, summary) : []), [kind, summary]);
  const selected = useMemo(
    () => new Set(filters.type.split(",").map((type) => type.trim()).filter(Boolean)),
    [filters.type],
  );
  if (!summary || kind.entityTypes.length < 2) return null;

  const all = counts.reduce((total, part) => total + part.count, 0);
  const visible = counts.filter((part) => part.count > 0 || selected.has(part.type) || (kind.primaryTypes.length === 1 && kind.primaryTypes[0] === part.type));
  const chip = (key: string, label: string, count: number, pressed: boolean, onClick: () => void) => (
    <button key={key} type="button" aria-pressed={pressed} aria-label={`${label} ${count.toLocaleString()}`}
      onClick={onClick} className={`${CHIP} ${pressed ? CHIP_ON : CHIP_OFF}`}>
      <span>{label}</span>
      <span className="tabular-nums text-ink-tertiary">{count.toLocaleString()}</span>
    </button>
  );

  return (
    <div role="group" aria-label="Filter by asset type" className="flex flex-wrap items-center gap-1.5">
      {chip("all", "All types", all, selected.size === 0, () => setFilter("type", ""))}
      {visible.map((part) =>
        chip(part.type, capitalize(entityTypeLabel(part.type, 2)), part.count, selected.has(part.type),
          () => setFilter("type", selected.size === 1 && selected.has(part.type) ? "" : part.type)),
      )}
    </div>
  );
}
