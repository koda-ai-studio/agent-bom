"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { withFindingContext } from "@/lib/finding-investigation-href";
import type { LegendItem } from "@/lib/graph-utils";

const SHARED_INVESTIGATION_PARAMS = [
  "scan",
  "agent",
  "cve",
  "finding",
  "node",
  "package",
  "root",
  "root_label",
  "investigate",
  "q",
  "rollup",
  "rollup_node",
  "trace",
  "scenario",
  "state",
] as const;

export function buildInvestigationLensHref(
  targetHref: string,
  current: { get(name: string): string | null },
): string {
  const [pathname, targetQuery = ""] = targetHref.split("?", 2);
  const params = new URLSearchParams();
  for (const key of SHARED_INVESTIGATION_PARAMS) {
    const value = current.get(key);
    if (value) params.set(key, value);
  }
  const targetParams = new URLSearchParams(targetQuery);
  const targetLens = targetParams.get("lens");
  if (targetLens && targetLens !== "estate") {
    // Roll-up is the Estate lens' composition state, not investigation
    // identity. Carrying it into Cloud/Repository/Identity would make those
    // buttons render the unfiltered estate roll-up and mislabel the canvas.
    params.delete("rollup");
    params.delete("rollup_node");
  }
  // Target-owned parameters (for example the Asset Drift scope) are
  // authoritative and replace any context inherited from the current lens.
  for (const [key, value] of targetParams) {
    params.set(key, value);
  }
  const query = params.toString();
  return withFindingContext(query ? `${pathname}?${query}` : (pathname ?? targetHref), current);
}

interface GraphLensSwitcherProps {
  scanId?: string | undefined;
  variant?: "inline" | "floating" | "compact";
  legendItems?: LegendItem[];
  legendDefaultOpen?: boolean;
}

/** Task navigation only. Entity scopes and layers belong to the graph toolbar. */
export function GraphLensSwitcher({ scanId, variant = "inline" }: GraphLensSwitcherProps) {
  const pathname = usePathname();
  const router = useRouter();
  const params = useSearchParams();
  const lens = params.get("lens");
  const exploring = pathname === "/graph" || Boolean(lens && lens !== "attack-path");
  const options = [
    { label: "Find a path", active: !exploring, href: "/security-graph?lens=attack-path" },
    { label: "Explore connections", active: exploring, href: "/security-graph?lens=estate&rollup=1" },
  ];
  return <nav aria-label="Investigation workspace" className={variant === "floating" ? "absolute left-3 top-3 z-30 flex gap-4 bg-surface px-3 py-2" : "flex flex-wrap gap-5 border-b border-outline"}>
    {options.map(option => <button key={option.label} type="button" aria-current={option.active ? "page" : undefined}
      className={`min-h-11 border-b-2 px-1 text-sm font-medium ${option.active ? "border-[var(--accent)] text-foreground" : "border-transparent text-ink-secondary hover:text-foreground"}`}
      onClick={() => { if (!option.active) router.push(buildInvestigationLensHref(option.href, {
        get: key => key === "scan" && scanId ? scanId : params.get(key),
      })); }}>
      {option.label}
    </button>)}
  </nav>;
}
