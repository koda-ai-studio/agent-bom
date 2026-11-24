"use client";

import { useEffect, useMemo, useState } from "react";

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

export type FixFilter = "" | "available" | "none";
const FIX_VALUES: FixFilter[] = ["available", "none"];

/** The queue's signal filters (known exploitation and fix availability), read from and written to the URL together. */
export function useFindingSignals(searchParams: { get(name: string): string | null }) {
  const [kevOnly, setKevOnly] = useKevOnlyParam(searchParams);
  const paramFix = searchParams.get("fix") as FixFilter;
  const initialFix: FixFilter = FIX_VALUES.includes(paramFix) ? paramFix : "";
  const [fix, setFix] = useState<FixFilter>(initialFix);
  useEffect(() => { setFix(initialFix); }, [initialFix]);
  // One object per filter state, so effects can depend on it directly.
  return useMemo(() => ({
    kevOnly, setKevOnly, fix, setFix,
    query: { ...(kevOnly ? { kev: true } : {}), ...(fix ? { fix } : {}) },
    active: kevOnly || Boolean(fix),
    write: (params: URLSearchParams) => { if (kevOnly) params.set("kev", "1"); if (fix) params.set("fix", fix); },
    clear: () => { setKevOnly(false); setFix(""); },
  }), [kevOnly, setKevOnly, fix]);
}
export type FindingSignals = ReturnType<typeof useFindingSignals>;

export function FindingsSignalFilterNotes({ signals }: { signals: FindingSignals }) {
  return (
    <>
      {signals.kevOnly && <FindingsKevFilterNote onClear={() => signals.setKevOnly(false)} />}
      {signals.fix && (
        <p data-testid="findings-fix-filter" className="flex flex-wrap items-center gap-2 text-xs text-ink-secondary">
          {signals.fix === "available" ? "Findings with a recorded fix only: upgrade to close them" : "Findings without a recorded fix only: these need a compensating control"}
          <button type="button" className="underline hover:text-foreground" onClick={() => signals.setFix("")}>Show all findings</button>
        </p>
      )}
    </>
  );
}
