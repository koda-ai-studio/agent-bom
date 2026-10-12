"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { useAuthState } from "@/components/auth-provider";

/** Resolve old scan graph URLs through their recorded snapshot, never a job-ID guess. */
export function ScanInvestigationEntry({ id, path = false }: { id: string; path?: boolean }) {
  const router = useRouter();
  const { session } = useAuthState();
  const authenticated = Boolean(session);
  const owner = JSON.stringify([session?.tenant_id, session?.subject, session?.auth_method]);
  const [error, setError] = useState("");
  useEffect(() => {
    if (!authenticated) return;
    const controller = new AbortController();
    setError("");
    void api.getScanStatus(id, controller.signal).then(status => {
      if (controller.signal.aborted) return;
      if (!status.graph_scan_id) {
        setError("This scan has no recorded graph snapshot. Open its report to inspect the available evidence.");
        return;
      }
      const params = new URLSearchParams({ scan: status.graph_scan_id, lens: path ? "attack-path" : "estate" });
      router.replace(`/security-graph?${params}`);
    }).catch(() => {
      if (!controller.signal.aborted) setError("Could not resolve this scan's graph. Open its report or try again.");
    });
    return () => controller.abort();
  }, [id, path, owner, router, authenticated]); // Owner changes revoke late navigation; token refresh retains the owner.
  return <section className="space-y-3 p-6">
    <h1 className="text-lg font-semibold">Investigation</h1>
    <p role={error ? "alert" : "status"}>{session ? error || "Opening the recorded graph…" : "Resolving access to investigation evidence…"}</p>
    <Link className="text-sm underline" href={`/scan?id=${encodeURIComponent(id)}`}>Open scan report</Link>
  </section>;
}
