"use client";

import { useSyncExternalStore } from "react";

export type ProductView = "personal" | "team" | "organization";
export const PRODUCT_VIEW_KEY = "agent-bom.product-view";
const CHANGE_EVENT = "agent-bom:product-view";
export const PRODUCT_VIEWS: Record<ProductView, { label: string; description: string }> = {
  personal: { label: "Personal", description: "Scan a project, investigate findings and verify fixes." },
  team: { label: "Team", description: "Review shared inventory, retained scans and runtime evidence." },
  organization: { label: "Organization", description: "Add governance, compliance and audit review to shared evidence." },
};

export function parseProductView(value: unknown): ProductView {
  return value === "team" || value === "organization" ? value : "personal";
}

// Presentation only: never sent to an API or used to decide access or scope.
// In-memory fallback keeps the selector usable when browser storage is denied.
let volatileView: ProductView | null = null;
function readProductView(): ProductView {
  if (volatileView !== null) return volatileView;
  try { return parseProductView(window.localStorage.getItem(PRODUCT_VIEW_KEY)); }
  catch { return "personal"; }
}
function subscribe(onChange: () => void) {
  const onStorage = (event: StorageEvent) => {
    if (event.key === PRODUCT_VIEW_KEY || event.key === null) { volatileView = null; onChange(); }
  };
  window.addEventListener("storage", onStorage);
  window.addEventListener(CHANGE_EVENT, onChange);
  return () => {
    window.removeEventListener("storage", onStorage);
    window.removeEventListener(CHANGE_EVENT, onChange);
  };
}
export function setProductView(value: ProductView): void {
  volatileView = parseProductView(value);
  try { window.localStorage.setItem(PRODUCT_VIEW_KEY, volatileView); volatileView = null; } catch { /* display preference only */ }
  window.dispatchEvent(new Event(CHANGE_EVENT));
}
export function useProductView(): ProductView {
  return useSyncExternalStore(subscribe, readProductView, () => "personal");
}

const GROUPS: Record<ProductView, readonly string[]> = {
  personal: ["Connect", "Posture", "Inventory", "Runtime"],
  team: ["Posture", "Inventory", "Connect", "Runtime", "Operations"],
  organization: ["Posture", "Inventory", "Governance", "Connect", "Runtime", "Operations"],
};
export function primaryProductGroups(view: ProductView): readonly string[] { return GROUPS[view]; }
