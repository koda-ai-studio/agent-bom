"use client";

import { useEffect, useState } from "react";

/** Read `kev=1` from the URL: the Overview KEV chip links here, so the list must show the issues it counted. */
export function useKevOnlyParam(searchParams: { get(name: string): string | null }) {
  const paramKev = ["1", "true"].includes(searchParams.get("kev") ?? "");
  const [kevOnly, setKevOnly] = useState(paramKev);
  useEffect(() => { setKevOnly(paramKev); }, [paramKev]);
  return [kevOnly, setKevOnly] as const;
}

export function FindingsKevFilterNote({ onClear }: { onClear: () => void }) {
  return (
    <p data-testid="findings-kev-filter" className="flex flex-wrap items-center gap-2 text-xs text-ink-secondary">
      Known-exploited (CISA KEV) findings only
      <button type="button" className="underline hover:text-foreground" onClick={onClear}>Show all findings</button>
    </p>
  );
}
