import { useCallback, useEffect, useRef, useState } from "react";

import { vulnRowKey, type EnrichedVuln } from "@/lib/findings-view";

/**
 * The finding id that should narrow the findings query. Only a deep link to a
 * finding outside the loaded page narrows it: selecting a loaded row also
 * writes `finding=` to the URL, and must not refetch that issue group down to
 * the one selected occurrence.
 */
export function useDeepLinkFinding(paramFinding: string | null): { deepLinkFinding: string | null; rememberLoaded: (rows: EnrichedVuln[]) => EnrichedVuln[] } {
  const [deepLinkFinding, setDeepLinkFinding] = useState<string | null>(paramFinding);
  const loaded = useRef<EnrichedVuln[]>([]);
  useEffect(() => {
    if (!paramFinding) setDeepLinkFinding(null);
    else if (!loaded.current.some((vuln) => vulnRowKey(vuln) === paramFinding || vuln.id === paramFinding)) setDeepLinkFinding(paramFinding);
  }, [paramFinding]);
  const rememberLoaded = useCallback((rows: EnrichedVuln[]) => { loaded.current = rows; return rows; }, []);
  return { deepLinkFinding, rememberLoaded };
}
