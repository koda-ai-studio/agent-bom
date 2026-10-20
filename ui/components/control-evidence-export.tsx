"use client";

import { Download, Loader2 } from "lucide-react";
import { useState } from "react";

import { api } from "@/lib/api";
import { userFacingApiErrorMessage } from "@/lib/api-errors";
import { controlEvidenceExcerpt, controlReportSlug } from "@/lib/control-evidence";

function saveJson(name: string, body: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(body, null, 2)], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}

/** Downloads this control's slice of the signed framework evidence bundle. */
export function ControlEvidenceExport({ frameworkId, controlCode }: { frameworkId: string; controlCode: string }) {
  const [state, setState] = useState<{ busy: boolean; error: string | null }>({ busy: false, error: null });
  const exportEvidence = async () => {
    setState({ busy: true, error: null });
    try {
      const slug = controlReportSlug(frameworkId);
      const bundle = await api.getComplianceFrameworkReport(slug);
      saveJson(`agent-bom-${slug}-${controlCode}-evidence.json`, controlEvidenceExcerpt(bundle, controlCode));
      setState({ busy: false, error: null });
    } catch (error) {
      setState({ busy: false, error: userFacingApiErrorMessage(error, "Control evidence export failed") });
    }
  };
  return (
    <span className="inline-flex flex-col gap-1">
      <button type="button" onClick={() => void exportEvidence()} disabled={state.busy}
        className="inline-flex items-center gap-1.5 rounded-lg border border-outline bg-surface px-3 py-1.5 text-xs font-medium text-foreground transition hover:bg-surface-muted disabled:opacity-60">
        {state.busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <Download className="h-3.5 w-3.5" aria-hidden="true" />}
        Export control evidence
      </button>
      {state.error ? <span role="alert" className="text-xs text-red-700 dark:text-red-300">{state.error}</span> : null}
    </span>
  );
}
