"use client";

import { useId } from "react";
import { parseProductView, PRODUCT_VIEWS, setProductView, useProductView } from "@/lib/product-view";

export function ProductViewPicker() {
  const id = useId();
  const view = useProductView();
  return <div className="space-y-2">
    <label htmlFor={id} className="block text-xs font-medium text-ink-secondary">Product view</label>
    <select id={id} value={view} onChange={(event) => setProductView(parseProductView(event.target.value))}
      aria-describedby={`${id}-help`} className="min-h-10 w-full rounded-lg border border-outline bg-surface px-2 text-sm text-foreground">
      {Object.entries(PRODUCT_VIEWS).map(([value, { label }]) => <option key={value} value={value}>{label}</option>)}
    </select>
    <p id={`${id}-help`} className="text-xs leading-5 text-ink-secondary">Organizes pages in this browser. Access and evidence scope stay the same.</p>
  </div>;
}
