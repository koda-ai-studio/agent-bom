"use client";

import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import { secretFindingsTotalQuery } from "@/lib/findings-default-query";
import { formatFindingsTotal } from "@/lib/findings-view";

/** The Secrets chip's number: the linked Findings view's own total, or null until (or unless) it answers. */
export function useSecretFindingsTotal(enabled: boolean): string | null {
  const [total, setTotal] = useState<string | null>(null);
  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    api.listFindings(secretFindingsTotalQuery()).then(
      (response) => {
        if (!cancelled) setTotal(typeof response.total === "number" ? formatFindingsTotal(response.total, Boolean(response.total_approximate)) : null);
      },
      () => { if (!cancelled) setTotal(null); },
    );
    return () => { cancelled = true; };
  }, [enabled]);
  return enabled ? total : null;
}
